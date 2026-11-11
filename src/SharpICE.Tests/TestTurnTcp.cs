using SharpSTUN;
using SharpTURN;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// TCP allocations (RFC 6062): the TURN client and server of each other over the loopback, of TCP and of TLS; a connection to
    /// a peer of Connect, and one of a peer of a ConnectionAttempt, relayed both ways as they are; a peer of no permission
    /// closed; each connection closed with the other, and with the allocation; and the server's error responses.
    /// </summary>
    [TestClass]
    public class TestTurnTcp
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static TurnServerOptions ServerOptions() => new TurnServerOptions
        {
            Stun = new StunServerOptions
            {
                Realm = "example.org",
                Users = new Dictionary<string, string> { ["user"] = "secret", ["other"] = "secret" },
                AuthenticateBinding = false,
            },
            RelayAddress = IPAddress.Loopback,
            // the peers of the tests are of the loopback
            AllowPeer = peer => true,
        };

        private static StunClientOptions ClientOptions(string user = "user") => new StunClientOptions
        {
            Username = user,
            Password = "secret",
            CertificateValidation = (s, c, ch, e) => true,
        };

        private static X509Certificate2 CreateCertificate(string host)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
#pragma warning disable SYSLIB0057
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        private static async Task<TurnClient> AllocateTcp(string uri)
        {
            var client = new TurnClient(ClientOptions());
            await client.ConnectAsync(uri);
            await client.AllocateAsync(new TurnAllocateOptions { Tcp = true });
            return client;
        }

        private static async Task Write(Stream stream, string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            await stream.WriteAsync(bytes, 0, bytes.Length);
            await stream.FlushAsync();
        }

        // what the stream sends, until it has the bytes of the text expected
        private static async Task<string> Read(Stream stream, string expected)
        {
            int length = Encoding.UTF8.GetByteCount(expected);
            byte[] buffer = new byte[length];
            int read = 0;
            var deadline = DateTime.UtcNow + Timeout;
            while (read < length)
            {
                var reading = stream.ReadAsync(buffer, read, length - read);
                Assert.AreSame(reading, await Task.WhenAny(reading, Task.Delay(deadline - DateTime.UtcNow > TimeSpan.Zero ? deadline - DateTime.UtcNow : TimeSpan.Zero)), "nothing relayed");
                int count = await reading;
                Assert.AreNotEqual(0, count, "the connection ended");
                read += count;
            }
            return Encoding.UTF8.GetString(buffer);
        }

        // whether the stream ends - its end read, or of one reset - in time
        private static async Task<bool> Ends(Stream stream)
        {
            var deadline = DateTime.UtcNow + Timeout;
            byte[] buffer = new byte[64];
            while (DateTime.UtcNow < deadline)
            {
                Task<int> reading;
                try
                {
                    reading = stream.ReadAsync(buffer, 0, buffer.Length);
                    if (await Task.WhenAny(reading, Task.Delay(deadline - DateTime.UtcNow)) != reading)
                        return false;
                    if (await reading == 0)
                        return true;
                }
                catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException)
                {
                    return true;
                }
            }
            return false;
        }

        private static async Task<T> Within<T>(Task<T> task, string what)
        {
            Assert.AreSame(task, await Task.WhenAny(task, Task.Delay(Timeout)), what);
            return await task;
        }

        [TestMethod]
        public async Task ConnectsToAPeerOverTcpAndTls()
        {
            using var certificate = CreateCertificate("localhost");
            var options = ServerOptions();
            options.Stun.Certificate = certificate;
            using var server = new TurnServer(options);
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));

            foreach (string uri in new[] { $"turn:127.0.0.1:{tcp.Port}?transport=tcp", $"turns:localhost:{tls.Port}" })
            {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                try
                {
                    using var client = await AllocateTcp(uri);
                    Assert.IsTrue(client.IsTcp);
                    var peerEndPoint = (IPEndPoint)listener.LocalEndpoint;

                    var accepting = listener.AcceptTcpClientAsync();
                    using var connection = await client.ConnectPeerAsync(peerEndPoint);
                    using var peer = await Within(accepting, "the server connected to the peer");
                    Assert.AreEqual(peerEndPoint, connection.Peer);
                    Assert.AreNotEqual(0u, connection.ConnectionId);
                    Assert.AreEqual(client.RelayedEndPoint, peer.Client.RemoteEndPoint, "of the relayed address: " + uri);

                    // as they are, both ways: of no framing
                    var peerStream = peer.GetStream();
                    await Write(connection.Stream, "hello peer");
                    Assert.AreEqual("hello peer", await Read(peerStream, "hello peer"));
                    await Write(peerStream, "hello client");
                    Assert.AreEqual("hello client", await Read(connection.Stream, "hello client"));
                    string large = new string('x', 200000);
                    var writing = Write(connection.Stream, large);
                    Assert.AreEqual(large, await Read(peerStream, large));
                    await writing;
                }
                finally
                {
                    listener.Stop();
                }
            }
        }

        // coturn closes a data connection whose ConnectionBind it refuses, its 401 too: so the first ConnectionBind of a data
        // connection is to carry the control connection's credentials. A proxy in front of the server closes any data connection
        // whose first message is a ConnectionBind of no MESSAGE-INTEGRITY, as coturn would.
        [TestMethod]
        public async Task AuthenticatesTheFirstConnectionBindOfADataConnection()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var proxy = new TcpListener(IPAddress.Loopback, 0);
            proxy.Start();
            var unauthenticated = new ConcurrentQueue<bool>();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient accepted;
                    try { accepted = await proxy.AcceptTcpClientAsync(); }
                    catch (Exception) { return; }
                    _ = ProxyAsync(accepted, tcp, unauthenticated);
                }
            });
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                using var client = await AllocateTcp($"turn:127.0.0.1:{((IPEndPoint)proxy.LocalEndpoint).Port}?transport=tcp");
                var accepting = listener.AcceptTcpClientAsync();
                using var connection = await client.ConnectPeerAsync((IPEndPoint)listener.LocalEndpoint);
                using var peer = await Within(accepting, "the server connected to the peer");
                await Write(connection.Stream, "hello peer");
                Assert.AreEqual("hello peer", await Read(peer.GetStream(), "hello peer"));
                Assert.IsTrue(unauthenticated.IsEmpty, "a ConnectionBind of no credentials was sent");
            }
            finally
            {
                listener.Stop();
                proxy.Stop();
            }
        }

        private static async Task ProxyAsync(TcpClient accepted, IPEndPoint server, ConcurrentQueue<bool> unauthenticated)
        {
            using (accepted)
            using (var upstream = new TcpClient())
            {
                try
                {
                    await upstream.ConnectAsync(server.Address, server.Port);
                    var from = accepted.GetStream();
                    var to = upstream.GetStream();

                    // the first message: a STUN header, then its attributes
                    byte[] header = await ReadExactly(from, 20);
                    byte[] first = new byte[20 + ((header[2] << 8) | header[3])];
                    Buffer.BlockCopy(header, 0, first, 0, 20);
                    byte[] body = await ReadExactly(from, first.Length - 20);
                    Buffer.BlockCopy(body, 0, first, 20, body.Length);
                    var message = StunMessage.Parse(first, 0, first.Length);
                    if (message.Method == TurnMethod.ConnectionBind && !message.HasIntegrity && !message.HasIntegritySha256)
                    {
                        unauthenticated.Enqueue(true);
                        return;
                    }
                    await to.WriteAsync(first, 0, first.Length);
                    await Task.WhenAny(from.CopyToAsync(to), to.CopyToAsync(from));
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException)
                {
                }
            }
        }

        private static async Task<byte[]> ReadExactly(Stream stream, int count)
        {
            byte[] buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await stream.ReadAsync(buffer, read, count - read);
                if (n == 0)
                    throw new IOException("The connection ended.");
                read += n;
            }
            return buffer;
        }

        [TestMethod]
        public async Task AcceptsAPeerOfAPermission()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = await AllocateTcp($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            var attempts = new BlockingCollection<TurnConnectionAttemptEventArgs>();
            client.ConnectionAttempt += (s, e) => attempts.Add(e);
            await client.CreatePermissionAsync(IPAddress.Loopback);

            using var peer = new TcpClient(AddressFamily.InterNetwork);
            await peer.ConnectAsync(client.RelayedEndPoint.Address, client.RelayedEndPoint.Port);
            var peerStream = peer.GetStream();
            // sent before the client takes the connection: kept until it does (RFC 6062 5.4)
            await Write(peerStream, "early");

            Assert.IsTrue(attempts.TryTake(out var attempt, Timeout), "no ConnectionAttempt");
            Assert.AreEqual(peer.Client.LocalEndPoint, attempt.Peer);
            using var connection = await client.AcceptPeerAsync(attempt);
            Assert.AreEqual("early", await Read(connection.Stream, "early"));
            await Write(connection.Stream, "welcome");
            Assert.AreEqual("welcome", await Read(peerStream, "welcome"));

            // the connection is the client's once: bound again, 400
            var again = await Assert.ThrowsExactlyAsync<TurnException>(() => client.AcceptPeerAsync(attempt));
            Assert.AreEqual(StunErrorCode.BadRequest, again.Code);
        }

        [TestMethod]
        public async Task ClosesAPeerOfNoPermission()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = await AllocateTcp($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            var attempts = new BlockingCollection<TurnConnectionAttemptEventArgs>();
            client.ConnectionAttempt += (s, e) => attempts.Add(e);

            using var peer = new TcpClient(AddressFamily.InterNetwork);
            await peer.ConnectAsync(client.RelayedEndPoint.Address, client.RelayedEndPoint.Port);
            Assert.IsTrue(await Ends(peer.GetStream()), "closed as it was accepted");
            Assert.AreEqual(0, attempts.Count, "of no ConnectionAttempt");
        }

        [TestMethod]
        public async Task ClosesEachConnectionWithTheOther()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = await AllocateTcp($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            // a listener of each step: a connection of the relayed address to one peer's address and port again, at once,
            // would be of the 4-tuple TCP's TIME_WAIT holds of the one before
            var listeners = Enumerable.Range(0, 3).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToList();
            listeners.ForEach(l => l.Start());
            try
            {
                // the client's closed: the peer's with it
                var accepting = listeners[0].AcceptTcpClientAsync();
                var first = await client.ConnectPeerAsync((IPEndPoint)listeners[0].LocalEndpoint);
                using (var peer = await Within(accepting, "connected"))
                {
                    first.Dispose();
                    Assert.IsTrue(await Ends(peer.GetStream()), "the peer's closed with the client's");
                }

                // the peer's closed: the client's with it
                accepting = listeners[1].AcceptTcpClientAsync();
                using var second = await client.ConnectPeerAsync((IPEndPoint)listeners[1].LocalEndpoint);
                var other = await Within(accepting, "connected again");
                other.Dispose();
                Assert.IsTrue(await Ends(second.Stream), "the client's closed with the peer's");

                // the allocation deleted: its connections with it
                accepting = listeners[2].AcceptTcpClientAsync();
                using var third = await client.ConnectPeerAsync((IPEndPoint)listeners[2].LocalEndpoint);
                using var last = await Within(accepting, "connected a third time");
                await client.DeallocateAsync();
                Assert.IsTrue(await Ends(third.Stream), "the client's closed with the allocation");
                Assert.IsTrue(await Ends(last.GetStream()), "the peer's closed with the allocation");
            }
            finally
            {
                listeners.ForEach(l => l.Stop());
            }
        }

        [TestMethod]
        public async Task RefusesWhatIsNotOfATcpAllocation()
        {
            using var server = new TurnServer(ServerOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));

            // of UDP to the server, 400 (RFC 6062 5.1); the client does not ask
            using (var overUdp = new TurnClient(ClientOptions()))
            {
                await overUdp.ConnectAsync("turn:127.0.0.1:" + udp.Port);
                var request = new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddRequestedTransport(TurnConstants.Tcp);
                Assert.AreEqual(StunErrorCode.BadRequest, (await overUdp.Client.RequestAsync(request)).Error.Value.Code);
                await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => overUdp.AllocateAsync(new TurnAllocateOptions { Tcp = true }));
            }

            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            // of EVEN-PORT, 400
            var even = new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddRequestedTransport(TurnConstants.Tcp).AddEvenPort(false);
            Assert.AreEqual(StunErrorCode.BadRequest, (await client.Client.RequestAsync(even)).Error.Value.Code);
            await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.AllocateAsync(new TurnAllocateOptions { Tcp = true, EvenPort = true }));

            // of no allocation, 437
            var connect = new StunMessage(TurnMethod.Connect, StunMessageClass.Request).AddXorAddress(new IPEndPoint(IPAddress.Loopback, 9), TurnAttributeType.XorPeerAddress);
            Assert.AreEqual(TurnErrorCode.AllocationMismatch, (await client.Client.RequestAsync(connect)).Error.Value.Code);

            await client.AllocateAsync(new TurnAllocateOptions { Tcp = true });
            // of no XOR-PEER-ADDRESS, 400; of a channel, 400
            Assert.AreEqual(StunErrorCode.BadRequest, (await client.Client.RequestAsync(new StunMessage(TurnMethod.Connect, StunMessageClass.Request))).Error.Value.Code);
            var channel = new StunMessage(TurnMethod.ChannelBind, StunMessageClass.Request).AddChannelNumber(0x4000).AddXorAddress(new IPEndPoint(IPAddress.Loopback, 9), TurnAttributeType.XorPeerAddress);
            Assert.AreEqual(StunErrorCode.BadRequest, (await client.Client.RequestAsync(channel)).Error.Value.Code);
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => client.SendAsync(new IPEndPoint(IPAddress.Loopback, 9), new byte[1]));

            // of a peer no one listens of, 447
            var nothing = new TcpListener(IPAddress.Loopback, 0);
            nothing.Start();
            var closed = (IPEndPoint)nothing.LocalEndpoint;
            nothing.Stop();
            var failed = await Assert.ThrowsExactlyAsync<TurnException>(() => client.ConnectPeerAsync(closed));
            Assert.AreEqual(TurnErrorCode.ConnectionTimeoutOrFailure, failed.Code);

            // of a peer a connection is of already, 446
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var peerEndPoint = (IPEndPoint)listener.LocalEndpoint;
                var accepting = listener.AcceptTcpClientAsync();
                using var connection = await client.ConnectPeerAsync(peerEndPoint);
                using var peer = await Within(accepting, "connected");
                var twice = await Assert.ThrowsExactlyAsync<TurnException>(() => client.ConnectPeerAsync(peerEndPoint));
                Assert.AreEqual(TurnErrorCode.ConnectionAlreadyExists, twice.Code);
            }
            finally
            {
                listener.Stop();
            }

            // a ConnectionBind of no connection of the server's, or on the control connection: 400
            var unknown = new StunMessage(TurnMethod.ConnectionBind, StunMessageClass.Request).AddConnectionId(12345);
            Assert.AreEqual(StunErrorCode.BadRequest, (await client.Client.RequestAsync(unknown)).Error.Value.Code);
        }

        [TestMethod]
        public async Task BindsAPeersConnectionOfItsUsersCredentialsAlone()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = await AllocateTcp($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            var attempts = new BlockingCollection<TurnConnectionAttemptEventArgs>();
            client.ConnectionAttempt += (s, e) => attempts.Add(e);
            await client.CreatePermissionAsync(IPAddress.Loopback);
            using var peer = new TcpClient(AddressFamily.InterNetwork);
            await peer.ConnectAsync(client.RelayedEndPoint.Address, client.RelayedEndPoint.Port);
            Assert.IsTrue(attempts.TryTake(out var attempt, Timeout), "no ConnectionAttempt");

            // another user's ConnectionBind of it, over a connection of its own: 441
            using var transport = await StunStreamTransport.ConnectAsync(tcp);
            using var other = new StunClient(transport, ClientOptions("other"));
            other.Options.IsKnownAttribute = TurnAttributeType.IsKnownOfTurn;
            var bind = new StunMessage(TurnMethod.ConnectionBind, StunMessageClass.Request).AddConnectionId(attempt.ConnectionId);
            Assert.AreEqual(TurnErrorCode.WrongCredentials, (await other.RequestAsync(bind)).Error.Value.Code);

            // its user's, still
            using var connection = await client.AcceptPeerAsync(attempt);
            await Write(peer.GetStream(), "still mine");
            Assert.AreEqual("still mine", await Read(connection.Stream, "still mine"));
        }
    }
}
