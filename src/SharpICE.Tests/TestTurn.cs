using SharpStunClient;
using SharpStunCommon;
using SharpStunServer;
using SharpTurnClient;
using SharpTurnCommon;
using SharpTurnServer;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    /// The TURN client and server of each other over the loopback (RFC 8656): allocations over UDP, TCP, TLS and DTLS, data
    /// relayed both ways of Send and Data indications and of channels, permissions enforced, a dual allocation, EVEN-PORT and its
    /// reservation, lifetimes refreshed and expired, and the server's error responses.
    /// </summary>
    [TestClass]
    public class TestTurn
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
        };

        private static StunClientOptions ClientOptions(string user = "user") => new StunClientOptions
        {
            Username = user,
            Password = "secret",
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxTransmissions = 4,
            LastWaitMultiplier = 2,
            CertificateValidation = (s, c, ch, e) => true,
        };

        /// <summary>A peer of the relay: a UDP socket of a loopback address.</summary>
        private sealed class Peer : IDisposable
        {
            public Peer(string address = "127.0.0.1")
            {
                Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                Socket.Bind(new IPEndPoint(IPAddress.Parse(address), 0));
                Socket.ReceiveTimeout = 3000;
            }

            public Socket Socket { get; }

            public IPEndPoint EndPoint => (IPEndPoint)Socket.LocalEndPoint;

            public (string Text, IPEndPoint From) Receive()
            {
                byte[] buffer = new byte[2048];
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int count = Socket.ReceiveFrom(buffer, ref from);
                return (Encoding.UTF8.GetString(buffer, 0, count), (IPEndPoint)from);
            }

            public void Send(string text, IPEndPoint to) => Socket.SendTo(Encoding.UTF8.GetBytes(text), to);

            public void Dispose() => Socket.Dispose();
        }

        private static async Task<string> Received(BlockingCollection<(string Text, IPEndPoint From)> received, IPEndPoint from)
        {
            Assert.IsTrue(received.TryTake(out var item, Timeout), "nothing relayed to the client");
            Assert.AreEqual(from, item.From);
            return await Task.FromResult(item.Text);
        }

        private static BlockingCollection<(string, IPEndPoint)> Listen(TurnClient client)
        {
            var received = new BlockingCollection<(string, IPEndPoint)>();
            client.DataReceived += (s, e) => received.Add((Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count), e.Peer));
            return received;
        }

        // to the peer and back, of indications, then of a channel
        private static async Task RelaysBothWays(TurnClient client)
        {
            using var peer = new Peer();
            var received = Listen(client);

            await client.SendAsync(peer.EndPoint, Encoding.UTF8.GetBytes("odd"));
            var (text, from) = peer.Receive();
            Assert.AreEqual("odd", text);
            Assert.AreEqual(client.RelayedEndPoint, from, "from the relayed address");
            peer.Send("back", from);
            Assert.AreEqual("back", await Received(received, peer.EndPoint));

            ushort channel = await client.BindChannelAsync(peer.EndPoint);
            Assert.AreEqual((ushort)0x4000, channel);
            await client.SendAsync(peer.EndPoint, Encoding.UTF8.GetBytes("of a channel"));
            Assert.AreEqual("of a channel", peer.Receive().Text);
            peer.Send("back again", from);
            Assert.AreEqual("back again", await Received(received, peer.EndPoint));
        }

        [TestMethod]
        public async Task AllocatesAndRelaysOverUdp()
        {
            using var server = new TurnServer(ServerOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);

            await client.AllocateAsync();

            Assert.AreEqual(IPAddress.Loopback, client.RelayedEndPoint.Address);
            Assert.IsTrue(client.RelayedEndPoint.Port >= 49152);
            Assert.AreEqual(client.Client.Transport.LocalEndPoint.Port, client.MappedEndPoint.Port);
            Assert.AreEqual(TimeSpan.FromSeconds(600), client.Lifetime);
            Assert.AreEqual(1, server.AllocationCount);
            await RelaysBothWays(client);

            await client.DeallocateAsync();
            Assert.AreEqual(0, server.AllocationCount);
        }

        [TestMethod]
        public async Task AllocatesAndRelaysOverTcpTlsAndDtls()
        {
            using var certificate = CreateCertificate("localhost");
            var options = ServerOptions();
            options.Stun.Certificate = certificate;
            using var server = new TurnServer(options);
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));

            foreach (string uri in new[] { $"turn:127.0.0.1:{tcp.Port}?transport=tcp", $"turns:localhost:{tls.Port}", $"turns:localhost:{dtls.Port}?transport=udp" })
            {
                using var client = new TurnClient(ClientOptions());
                await client.ConnectAsync(uri);
                await client.AllocateAsync();
                await RelaysBothWays(client);
            }
            Assert.AreEqual(0, server.AllocationCount, "each deleted as its client was disposed");
        }

        [TestMethod]
        public async Task EndsAnAllocationOfTcpWithItsConnection()
        {
            using var server = new TurnServer(ServerOptions());
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var client = new TurnClient(ClientOptions());
            await client.ConnectAsync($"turn:127.0.0.1:{tcp.Port}?transport=tcp");
            await client.AllocateAsync();
            Assert.AreEqual(1, server.AllocationCount);

            client.Client.Transport.Dispose();

            DateTime deadline = DateTime.UtcNow + Timeout;
            while (server.AllocationCount > 0 && DateTime.UtcNow < deadline)
                await Task.Delay(20);
            Assert.AreEqual(0, server.AllocationCount);
        }

        [TestMethod]
        public async Task RelaysOnlyOfAPermission()
        {
            using var server = new TurnServer(ServerOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await client.AllocateAsync();
            var received = Listen(client);
            using var stranger = new Peer("127.0.0.2");

            // of no permission of 127.0.0.2, dropped (RFC 8656 9)
            stranger.Send("dropped", client.RelayedEndPoint);
            Assert.IsFalse(received.TryTake(out _, TimeSpan.FromMilliseconds(500)));

            await client.CreatePermissionAsync(IPAddress.Parse("127.0.0.2"));
            stranger.Send("let through", client.RelayedEndPoint);
            Assert.AreEqual("let through", await Received(received, stranger.EndPoint));
        }

        [TestMethod]
        public async Task RefusesWhatIsNotOfAnAllocation()
        {
            using var server = new TurnServer(ServerOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);

            // of none: 437
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.RefreshAsync());
            Assert.AreEqual(TurnErrorCode.AllocationMismatch, error.Code);
            error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.CreatePermissionAsync(IPAddress.Loopback));
            Assert.AreEqual(TurnErrorCode.AllocationMismatch, error.Code);

            // another Allocate of the 5-tuple: 437 (RFC 8656 7.2)
            await client.AllocateAsync();
            error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.AllocateAsync());
            Assert.AreEqual(TurnErrorCode.AllocationMismatch, error.Code);
        }

        [TestMethod]
        public async Task RefusesWhatItCannotAllocate()
        {
            var options = ServerOptions();
            options.MaxAllocationsPerUser = 1;
            using var server = new TurnServer(options);
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);

            // of TCP to the peers, 442; of no REQUESTED-TRANSPORT, 400
            var tcp = new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddAttribute(TurnAttributeType.RequestedTransport, new byte[] { 6, 0, 0, 0 });
            Assert.AreEqual(TurnErrorCode.UnsupportedTransportProtocol, (await client.Client.RequestAsync(tcp)).Error.Value.Code);
            var none = new StunMessage(TurnMethod.Allocate, StunMessageClass.Request);
            Assert.AreEqual(StunErrorCode.BadRequest, (await client.Client.RequestAsync(none)).Error.Value.Code);

            // of IPv6, of a server of no IPv6 relays: 440
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.AllocateAsync(new TurnAllocateOptions { AddressFamily = AddressFamily.InterNetworkV6 }));
            Assert.AreEqual(TurnErrorCode.AddressFamilyNotSupported, error.Code);

            // a second allocation of the user: 486
            await client.AllocateAsync();
            using var second = new TurnClient(ClientOptions());
            await second.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            error = await Assert.ThrowsExactlyAsync<TurnException>(() => second.AllocateAsync());
            Assert.AreEqual(TurnErrorCode.AllocationQuotaReached, error.Code);
        }

        [TestMethod]
        public async Task RefusesTheRequestsOfAnotherUser()
        {
            // two users of one 5-tuple, of the requests of each made by hand through Process
            using var server = new TurnServer(ServerOptions());
            var from = new IPEndPoint(IPAddress.Loopback, 40000);
            StunMessage Ask(StunMessage request, byte[] key = null)
            {
                byte[] bytes = request.ToBytes(key, key == null ? StunIntegrity.None : StunIntegrity.Sha256);
                byte[] answer = server.Stun.Process(bytes, 0, bytes.Length, from, false);
                return StunMessage.Parse(answer, 0, answer.Length);
            }
            StunMessage Signed(StunMessage request, StunMessage challenge, string user)
            {
                request.AddString(StunAttributeType.Username, user).AddString(StunAttributeType.Realm, challenge.Realm).AddString(StunAttributeType.Nonce, challenge.Nonce)
                    .AddAttribute(StunAttributeType.PasswordAlgorithms, challenge.GetAttribute(StunAttributeType.PasswordAlgorithms).Value)
                    .AddPasswordAlgorithm(StunPasswordAlgorithm.Sha256);
                return request;
            }
            byte[] KeyOf(string user) => StunCredentials.LongTermKey(user, "example.org", "secret", StunPasswordAlgorithm.Sha256);
            StunMessage Allocate() => new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddAttribute(TurnAttributeType.RequestedTransport, new byte[] { 17, 0, 0, 0 });

            var challenge = Ask(Allocate());
            Assert.AreEqual(StunErrorCode.Unauthorized, challenge.Error.Value.Code);
            var allocate = Signed(Allocate(), challenge, "user");
            var allocated = Ask(allocate, KeyOf("user"));
            Assert.AreEqual(StunMessageClass.SuccessResponse, allocated.Class);

            // its retransmission: answered again, of the same relayed address (RFC 8656 7.2)
            var again = Ask(allocate, KeyOf("user"));
            Assert.AreEqual(allocated.GetXorAddress(TurnAttributeType.XorRelayedAddress), again.GetXorAddress(TurnAttributeType.XorRelayedAddress));
            Assert.AreEqual(1, server.AllocationCount);

            // a Refresh of the other user: 441
            var refused = Ask(Signed(new StunMessage(TurnMethod.Refresh, StunMessageClass.Request), challenge, "other"), KeyOf("other"));
            Assert.AreEqual(TurnErrorCode.WrongCredentials, refused.Error.Value.Code);
            Assert.IsTrue(refused.VerifyIntegritySha256(KeyOf("other")), "signed of the credentials it was authenticated of");
        }

        [TestMethod]
        public async Task AllocatesBothFamiliesOrSaysWhyNot()
        {
            var options = ServerOptions();
            options.RelayAddressV6 = IPAddress.IPv6Loopback;
            using (var server = new TurnServer(options))
            {
                var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
                using var client = new TurnClient(ClientOptions());
                await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);
                await client.AllocateAsync(new TurnAllocateOptions { Dual = true });

                CollectionAssert.AreEquivalent(new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 }, client.RelayedEndPoints.Select(e => e.AddressFamily).ToArray());
                Assert.IsNull(client.AddressError);

                // a peer of IPv6, through the relay of IPv6
                using var peer = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                peer.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
                peer.ReceiveTimeout = 3000;
                await client.SendAsync((IPEndPoint)peer.LocalEndPoint, Encoding.UTF8.GetBytes("six"));
                byte[] buffer = new byte[64];
                EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
                int count = peer.ReceiveFrom(buffer, ref from);
                Assert.AreEqual("six", Encoding.UTF8.GetString(buffer, 0, count));
                Assert.AreEqual(client.RelayedEndPoints.Single(e => e.AddressFamily == AddressFamily.InterNetworkV6), from);
            }

            using (var server = new TurnServer(ServerOptions()))
            {
                var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
                using var client = new TurnClient(ClientOptions());
                await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);
                await client.AllocateAsync(new TurnAllocateOptions { Dual = true });

                Assert.AreEqual(1, client.RelayedEndPoints.Count, "of IPv4 alone");
                Assert.AreEqual(TurnErrorCode.AddressFamilyNotSupported, client.AddressError.Value.Code);
            }
        }

        [TestMethod]
        public async Task ReservesTheNextPortOfAnEvenOne()
        {
            using var server = new TurnServer(ServerOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var first = new TurnClient(ClientOptions());
            await first.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await first.AllocateAsync(new TurnAllocateOptions { EvenPort = true, ReserveNextPort = true });

            Assert.AreEqual(0, first.RelayedEndPoint.Port % 2);
            Assert.AreEqual(8, first.ReservationToken.Length);

            using var second = new TurnClient(ClientOptions("other"));
            await second.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await second.AllocateAsync(new TurnAllocateOptions { ReservationToken = first.ReservationToken });
            Assert.AreEqual(first.RelayedEndPoint.Port + 1, second.RelayedEndPoint.Port);

            // a token used once is gone: 508
            using var third = new TurnClient(ClientOptions("other"));
            await third.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => third.AllocateAsync(new TurnAllocateOptions { ReservationToken = first.ReservationToken }));
            Assert.AreEqual(TurnErrorCode.InsufficientCapacity, error.Code);
        }

        [TestMethod]
        public async Task KeepsAnAllocationAliveAndLetsAnotherExpire()
        {
            var options = ServerOptions();
            options.DefaultLifetime = TimeSpan.FromSeconds(8);
            options.MaxLifetime = TimeSpan.FromSeconds(8);
            using var server = new TurnServer(options);
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var kept = new TurnClient(ClientOptions());
            await kept.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await kept.AllocateAsync(new TurnAllocateOptions { Lifetime = TimeSpan.FromSeconds(3600) });
            Assert.AreEqual(TimeSpan.FromSeconds(8), kept.Lifetime, "the server's maximum");

            // an allocation of no client to refresh it: its socket gone, of no Refresh to delete it
            using var left = new TurnClient(ClientOptions("other"));
            await left.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await left.AllocateAsync();
            left.Client.Transport.Dispose();
            Assert.AreEqual(2, server.AllocationCount);

            await Task.Delay(TimeSpan.FromSeconds(11));

            Assert.AreEqual(1, server.AllocationCount, "the other one expired");
            Assert.IsTrue(kept.IsAllocated);
            await RelaysBothWays(kept);
        }

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
    }
}
