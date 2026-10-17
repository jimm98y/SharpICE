using SharpStunClient;
using SharpStunCommon;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// A STUN client's transactions with servers on this machine's loopback, over UDP, TCP and TLS: long-term credentials of
    /// MD5 and of SHA-256, USERHASH, stale nonces, wrong passwords, responses of no integrity, redirection, unknown attributes,
    /// retransmissions, and the agent's 420.
    /// </summary>
    [TestClass]
    public class TestStunTransactions
    {
        private const string User = "user";
        private const string Password = "secret";
        private const string ServerRealm = "example.org";

        // a test of no answer takes 3 transmissions: at 0, 200 and 600 ms, then waits 400 ms more; one answered at once is not
        // retransmitted, which the counts of the requests the servers receive rely on
        private static StunClientOptions FastOptions(string password = Password) => new StunClientOptions
        {
            Username = User,
            Password = password,
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxTransmissions = 3,
            LastWaitMultiplier = 2,
            ReliableTimeout = TimeSpan.FromSeconds(2),
            CertificateValidation = (s, c, ch, e) => true,
        };

        /// <summary>A server on the loopback - UDP, TCP or TLS over it - of a handler that gives the bytes to answer each message with, or null.</summary>
        private sealed class FakeServer : IDisposable
        {
            private readonly Socket _udp;
            private readonly TcpListener _tcp;
            private readonly X509Certificate2 _certificate;
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();
            private int _received;

            public FakeServer(Func<StunMessage, IPEndPoint, byte[]> handler, bool tcp = false, X509Certificate2 certificate = null)
            {
                Handler = handler;
                if (tcp || certificate != null)
                {
                    _certificate = certificate;
                    _tcp = new TcpListener(IPAddress.Loopback, 0);
                    _tcp.Start();
                    EndPoint = (IPEndPoint)_tcp.LocalEndpoint;
                    Task.Run(AcceptAsync);
                }
                else
                {
                    _udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    _udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                    EndPoint = (IPEndPoint)_udp.LocalEndPoint;
                    Task.Run(ServeUdpAsync);
                }
            }

            public Func<StunMessage, IPEndPoint, byte[]> Handler { get; set; }

            public IPEndPoint EndPoint { get; }

            public int Received => _received;

            /// <summary>The transactions of the requests received: their retransmissions once.</summary>
            public int Transactions => Requests.Select(r => Convert.ToBase64String(r.TransactionId)).Distinct().Count();

            public ConcurrentQueue<StunMessage> Requests { get; } = new ConcurrentQueue<StunMessage>();

            private byte[] Handle(StunMessage message, IPEndPoint from)
            {
                Interlocked.Increment(ref _received);
                Requests.Enqueue(message);
                return Handler(message, from);
            }

            private async Task ServeUdpAsync()
            {
                byte[] buffer = new byte[1500];
                while (!_cts.IsCancellationRequested)
                {
                    SocketReceiveFromResult result;
                    try
                    {
                        result = await _udp.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0));
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                    var message = StunMessage.Parse(buffer, 0, result.ReceivedBytes);
                    if (message == null)
                        continue;
                    byte[] answer = Handle(message, (IPEndPoint)result.RemoteEndPoint);
                    if (answer != null)
                        _udp.SendTo(answer, result.RemoteEndPoint);
                }
            }

            private async Task AcceptAsync()
            {
                while (!_cts.IsCancellationRequested)
                {
                    TcpClient client;
                    try
                    {
                        client = await _tcp.AcceptTcpClientAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    _ = Task.Run(() => ServeTcpAsync(client));
                }
            }

            private async Task ServeTcpAsync(TcpClient client)
            {
                using (client)
                {
                    try
                    {
                        Stream stream = client.GetStream();
                        if (_certificate != null)
                        {
                            var ssl = new SslStream(stream, false);
                            await ssl.AuthenticateAsServerAsync(_certificate);
                            stream = ssl;
                        }
                        var from = (IPEndPoint)client.Client.RemoteEndPoint;
                        byte[] header = new byte[StunMessage.HeaderLength];
                        while (!_cts.IsCancellationRequested)
                        {
                            if (!await ReadAsync(stream, header, 0, header.Length))
                                return;
                            int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                            byte[] bytes = new byte[header.Length + length];
                            Buffer.BlockCopy(header, 0, bytes, 0, header.Length);
                            if (!await ReadAsync(stream, bytes, header.Length, length))
                                return;
                            byte[] answer = Handle(StunMessage.Parse(bytes, 0, bytes.Length), from);
                            if (answer != null)
                                await stream.WriteAsync(answer, 0, answer.Length);
                        }
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            private static async Task<bool> ReadAsync(Stream stream, byte[] buffer, int offset, int count)
            {
                while (count > 0)
                {
                    int read = await stream.ReadAsync(buffer, offset, count);
                    if (read == 0)
                        return false;
                    offset += read;
                    count -= read;
                }
                return true;
            }

            public void Dispose()
            {
                _cts.Cancel();
                _udp?.Dispose();
                _tcp?.Stop();
            }
        }

        /// <summary>
        /// A server of long-term credentials (RFC 8489 9.2.4): a request of no integrity challenged, one of the nonce it gave
        /// and of integrity of the key of its algorithm answered, signed as the request was.
        /// </summary>
        private sealed class LongTermServer
        {
            private int _nonces;
            private readonly System.Collections.Generic.HashSet<string> _challenged = new System.Collections.Generic.HashSet<string>();

            public LongTermServer(StunSecurityFeatures? features)
            {
                Features = features;
                Nonce = NewNonce();
            }

            // of no nonce cookie, a server of RFC 5389
            public StunSecurityFeatures? Features { get; }

            public string Nonce { get; private set; }

            /// <summary>The transactions challenged: a retransmission of one once.</summary>
            public int Challenges { get { lock (_challenged) return _challenged.Count; } }

            /// <summary>The next request of credentials: answered 438, of a new nonce.</summary>
            public bool StaleNext { get; set; }

            public StunMessage LastAuthenticated { get; private set; }

            private bool ListsAlgorithms => Features.HasValue && (Features.Value & StunSecurityFeatures.PasswordAlgorithms) != 0;

            private bool Anonymous => Features.HasValue && (Features.Value & StunSecurityFeatures.UsernameAnonymity) != 0;

            private string NewNonce()
            {
                string rest = "n" + (++_nonces);
                return Features.HasValue ? StunCredentials.CreateNonce(Features.Value, rest) : rest;
            }

            public byte[] Handle(StunMessage request, IPEndPoint from)
            {
                if (!request.HasIntegrity && !request.HasIntegritySha256)
                    return Challenge(request, StunErrorCode.Unauthorized, "Unauthenticated");

                var algorithm = request.PasswordAlgorithm.HasValue ? (StunPasswordAlgorithm)request.PasswordAlgorithm.Value : StunPasswordAlgorithm.Md5;
                bool known = Anonymous
                    ? request.GetAttribute(StunAttributeType.Userhash)?.Value.SequenceEqual(StunCredentials.UserHash(User, ServerRealm)) == true
                    : request.Username == User;
                if (!known || request.Realm != ServerRealm)
                    return Challenge(request, StunErrorCode.Unauthorized, "Unauthenticated");
                if (request.Nonce != Nonce || StaleNext)
                {
                    StaleNext = false;
                    Nonce = NewNonce();
                    return Challenge(request, StunErrorCode.StaleNonce, "Stale Nonce");
                }

                byte[] key = StunCredentials.LongTermKey(User, ServerRealm, Password, algorithm);
                if (!request.VerifyAnyIntegrity(key))
                    return Challenge(request, StunErrorCode.Unauthorized, "Unauthenticated");

                LastAuthenticated = request;
                return new StunMessage(request.Method, StunMessageClass.SuccessResponse, request.TransactionId)
                    .AddXorAddress(from)
                    .ToBytes(key, request.HasIntegritySha256 ? StunIntegrity.Sha256 : StunIntegrity.Sha1);
            }

            private byte[] Challenge(StunMessage request, int code, string reason)
            {
                lock (_challenged)
                    _challenged.Add(Convert.ToBase64String(request.TransactionId));
                var error = new StunMessage(request.Method, StunMessageClass.ErrorResponse, request.TransactionId)
                    .AddError(code, reason)
                    .AddString(StunAttributeType.Realm, ServerRealm)
                    .AddString(StunAttributeType.Nonce, Nonce);
                if (ListsAlgorithms)
                    error.AddPasswordAlgorithms(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5);
                return error.ToBytes();
            }
        }

        private static byte[] Success(StunMessage request, IPEndPoint from)
            => new StunMessage(request.Method, StunMessageClass.SuccessResponse, request.TransactionId).AddXorAddress(from).ToBytes();

        [TestMethod]
        public async Task AuthenticatesOfTheMd5KeyOfAServerOfRFC5389()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());

            var mapped = await client.GetMappedAddressAsync();

            Assert.AreEqual(client.Transport.LocalEndPoint.Port, mapped.Port);
            Assert.IsTrue(client.IsAuthenticated);
            Assert.AreEqual(1, logic.Challenges);
            Assert.AreEqual(User, logic.LastAuthenticated.Username);
            Assert.IsTrue(logic.LastAuthenticated.HasIntegrity && !logic.LastAuthenticated.HasIntegritySha256, "MESSAGE-INTEGRITY alone");
            Assert.IsNull(logic.LastAuthenticated.PasswordAlgorithm);

            // the next request goes of the credentials at once
            Assert.IsNotNull(await client.GetMappedAddressAsync());
            Assert.AreEqual(1, logic.Challenges);
            Assert.AreEqual(3, server.Transactions);
        }

        [TestMethod]
        public async Task AuthenticatesOfTheSha256KeyAndAUserhash()
        {
            var logic = new LongTermServer(StunSecurityFeatures.PasswordAlgorithms | StunSecurityFeatures.UsernameAnonymity);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());

            Assert.IsNotNull(await client.GetMappedAddressAsync());

            var request = logic.LastAuthenticated;
            Assert.IsNull(request.Username, "a USERHASH in its place");
            Assert.IsTrue(request.HasIntegritySha256 && !request.HasIntegrity, "MESSAGE-INTEGRITY-SHA256 alone");
            Assert.AreEqual((ushort)StunPasswordAlgorithm.Sha256, request.PasswordAlgorithm, "the first of the server's that the client has");
            CollectionAssert.AreEqual(new[] { (ushort)2, (ushort)1 }, request.PasswordAlgorithms.ToArray(), "its list sent back");
            Assert.AreEqual(ServerRealm, client.Realm);
        }

        [TestMethod]
        public async Task SendsTheRequestAgainOfANewNonce()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());
            Assert.IsNotNull(await client.GetMappedAddressAsync());
            string first = logic.Nonce;

            logic.StaleNext = true;
            Assert.IsNotNull(await client.GetMappedAddressAsync());

            Assert.AreNotEqual(first, logic.Nonce);
            Assert.AreEqual(logic.Nonce, logic.LastAuthenticated.Nonce);
        }

        [TestMethod]
        public async Task EndsWithTheChallengeOfAWrongPassword()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions("wrong"));

            var response = await client.RequestAsync(StunClient.CreateBindingRequest());

            Assert.AreEqual(StunErrorCode.Unauthorized, response.Error.Value.Code);
            Assert.AreEqual(2, server.Transactions, "sent again once, of the credentials, and no more");
            Assert.IsFalse(client.IsAuthenticated);
        }

        [TestMethod]
        public async Task EndsWithTheChallengeOfNoCredentials()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), new StunClientOptions { InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200) });

            var response = await client.RequestAsync(StunClient.CreateBindingRequest());

            Assert.AreEqual(StunErrorCode.Unauthorized, response.Error.Value.Code);
            Assert.AreEqual(1, server.Transactions);
        }

        [TestMethod]
        public async Task DiscardsAResponseOfNoIntegrityOverUdp()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());
            Assert.IsNotNull(await client.GetMappedAddressAsync());

            // the server's answers unsigned from now on: each discarded, retransmissions go on, then the violation is told of
            server.Handler = Success;
            int before = server.Received;
            var error = await Assert.ThrowsExactlyAsync<StunException>(() => client.GetMappedAddressAsync());

            StringAssert.Contains(error.Message, "integrity");
            Assert.AreEqual(3, server.Received - before);
        }

        [TestMethod]
        public async Task EndsAtOnceOfAResponseOfNoIntegrityOverTcp()
        {
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle, tcp: true);
            using var client = new StunClient(await StunStreamTransport.ConnectAsync(server.EndPoint), FastOptions());
            Assert.IsNotNull(await client.GetMappedAddressAsync());

            server.Handler = Success;
            await Assert.ThrowsExactlyAsync<StunException>(() => client.GetMappedAddressAsync());
        }

        [TestMethod]
        public async Task FollowsAnAlternateServer()
        {
            using var alternate = new FakeServer(Success);
            using var redirecting = new FakeServer((request, from) => new StunMessage(request.Method, StunMessageClass.ErrorResponse, request.TransactionId)
                .AddError(StunErrorCode.TryAlternate, "Try Alternate")
                .AddAddress(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 3478), StunAttributeType.AlternateServer)
                .AddAddress(alternate.EndPoint, StunAttributeType.AlternateServer)
                .ToBytes());
            using var client = new StunClient(new StunUdpTransport(redirecting.EndPoint), FastOptions());

            var mapped = await client.GetMappedAddressAsync();

            Assert.AreEqual(client.Transport.LocalEndPoint.Port, mapped.Port);
            Assert.AreEqual(alternate.EndPoint, client.Transport.RemoteEndPoint, "the one of the request's address family");
            Assert.AreEqual(1, alternate.Transactions);
        }

        [TestMethod]
        public async Task EndsARedirectionLoop()
        {
            FakeServer a = null, b = null;
            byte[] Redirect(StunMessage request, IPEndPoint to) => new StunMessage(request.Method, StunMessageClass.ErrorResponse, request.TransactionId)
                .AddError(StunErrorCode.TryAlternate, "Try Alternate")
                .AddAddress(to, StunAttributeType.AlternateServer)
                .ToBytes();
            using (a = new FakeServer((request, from) => Redirect(request, b.EndPoint)))
            using (b = new FakeServer((request, from) => Redirect(request, a.EndPoint)))
            using (var client = new StunClient(new StunUdpTransport(a.EndPoint), FastOptions()))
            {
                var response = await client.RequestAsync(StunClient.CreateBindingRequest());

                Assert.AreEqual(StunErrorCode.TryAlternate, response.Error.Value.Code);
                Assert.AreEqual(1, a.Transactions);
                Assert.AreEqual(1, b.Transactions);
            }
        }

        [TestMethod]
        public async Task FailsOfAnUnknownComprehensionRequiredAttribute()
        {
            using var server = new FakeServer((request, from) => new StunMessage(request.Method, StunMessageClass.SuccessResponse, request.TransactionId)
                .AddXorAddress(from)
                .AddAttribute(0x7FFE, new byte[4])
                .ToBytes());
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());

            var error = await Assert.ThrowsExactlyAsync<StunException>(() => client.GetMappedAddressAsync());
            StringAssert.Contains(error.Message, "0x7FFE");
        }

        [TestMethod]
        public async Task TakesTheResponseOfAServerOfClassicStun()
        {
            // SOURCE-ADDRESS and CHANGED-ADDRESS of RFC 3489, as such a server sends them still: retired, not unknown
            using var server = new FakeServer((request, from) => new StunMessage(request.Method, StunMessageClass.SuccessResponse, request.TransactionId)
                .AddAddress(from, StunAttributeType.MappedAddress)
                .AddAddress(new IPEndPoint(IPAddress.Loopback, 3478), 0x0004)
                .AddAddress(new IPEndPoint(IPAddress.Loopback, 3479), 0x0005)
                .ToBytes(null, false));
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());

            var mapped = await client.GetMappedAddressAsync();

            Assert.AreEqual(client.Transport.LocalEndPoint.Port, mapped.Port, "of its MAPPED-ADDRESS");
        }

        [TestMethod]
        public async Task RetransmitsAsManyTimesAsItIsToThenGivesUp()
        {
            using var server = new FakeServer((request, from) => null);
            using var client = new StunClient(new StunUdpTransport(server.EndPoint), FastOptions());

            Assert.IsNull(await client.RequestAsync(StunClient.CreateBindingRequest()));
            Assert.AreEqual(3, server.Received);
            Assert.AreEqual(1, server.Transactions, "one transaction");
        }

        [TestMethod]
        public async Task TriesEachAddressOfAUriUntilOneAnswers()
        {
            // "localhost" is of ::1 and 127.0.0.1, the server of the latter alone: whichever comes first, the client ends at it
            using var server = new FakeServer(Success);
            var all = await StunClient.ResolveAllAsync(StunUri.Parse("stun:localhost:" + server.EndPoint.Port), TimeSpan.FromSeconds(1));
            CollectionAssert.Contains(all, server.EndPoint);

            using var client = await StunClient.ConnectAsync("stun:localhost:" + server.EndPoint.Port, FastOptions());
            Assert.IsInstanceOfType<StunUdpTransport>(client.Transport, "a stun URI is of UDP");

            Assert.IsNotNull(await client.GetMappedAddressAsync());
            Assert.AreEqual(server.EndPoint, client.Transport.RemoteEndPoint);
        }

        [TestMethod]
        public async Task AuthenticatesOverTcp()
        {
            var logic = new LongTermServer(StunSecurityFeatures.PasswordAlgorithms);
            using var server = new FakeServer(logic.Handle, tcp: true);
            using var client = new StunClient(await StunStreamTransport.ConnectAsync(server.EndPoint), FastOptions());

            Assert.IsNotNull(await client.GetMappedAddressAsync());
            Assert.IsNotNull(await client.GetMappedAddressAsync());

            Assert.IsTrue(client.IsAuthenticated);
            Assert.AreEqual(1, logic.Challenges);
            Assert.AreEqual(3, server.Received, "no retransmissions over TCP");
        }

        private static X509Certificate2 CreateCertificate(string host)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            // of a key SChannel can use: of a PFX, not of the ephemeral key it was made of
#pragma warning disable SYSLIB0057
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
#pragma warning restore SYSLIB0057
        }

        [TestMethod]
        public async Task AuthenticatesOverTlsOfAStunsUri()
        {
            using var certificate = CreateCertificate("localhost");
            var logic = new LongTermServer(null);
            using var server = new FakeServer(logic.Handle, certificate: certificate);

            using var client = await StunClient.ConnectAsync("stuns:localhost:" + server.EndPoint.Port, FastOptions());

            Assert.IsInstanceOfType<StunStreamTransport>(client.Transport);
            Assert.IsTrue(((StunStreamTransport)client.Transport).IsSecure);
            Assert.IsNotNull(await client.GetMappedAddressAsync());
            Assert.IsTrue(client.IsAuthenticated);
        }

        [TestMethod]
        public async Task RefusesACertificateTheSystemDoesNotTrust()
        {
            using var certificate = CreateCertificate("localhost");
            using var server = new FakeServer(Success, certificate: certificate);
            var options = FastOptions();
            options.CertificateValidation = null;

            await Assert.ThrowsExactlyAsync<StunException>(() => StunClient.ConnectAsync("stuns:localhost:" + server.EndPoint.Port, options));
            await Assert.ThrowsExactlyAsync<StunException>(() => StunClient.ConnectAsync("stuns:127.0.0.1:" + server.EndPoint.Port, options), "of an IP address");
        }

        [TestMethod]
        public async Task TheAgentAnswersAnUnknownAttributeWith420()
        {
            using var agent = new IceAgent(new IceAgentOptions
            {
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
            });
            var candidates = await agent.GatherCandidatesAsync();
            var target = new IPEndPoint(IPAddress.Parse(candidates[0].Address), candidates[0].Port);

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            using var transport = new StunUdpTransport(socket, target, true);
            var key = StunMessage.ShortTermKey(agent.LocalPassword);
            var received = new TaskCompletionSource<StunMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            transport.MessageReceived += (s, e) => received.TrySetResult(e.Message);

            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request)
                .AddString(StunAttributeType.Username, agent.LocalUfrag + ":peer")
                .AddUInt64(StunAttributeType.IceControlling, 1)
                .AddAttribute(0x7FFD, new byte[4]);
            await transport.SendAsync(request.ToBytes(key));

            Assert.AreSame(received.Task, await Task.WhenAny(received.Task, Task.Delay(5000)));
            var response = await received.Task;
            Assert.AreEqual(StunErrorCode.UnknownAttribute, response.Error.Value.Code);
            CollectionAssert.AreEqual(new[] { (ushort)0x7FFD }, response.UnknownAttributeTypes.ToArray());
            Assert.IsTrue(response.VerifyIntegrity(key), "signed, as the request was of the agent's password");
        }
    }
}
