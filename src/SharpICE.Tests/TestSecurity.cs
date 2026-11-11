using SharpSTUN;
using SharpTURN;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// What a hostile client, peer or network sends, and what it is not to get: a nonce that once threw before any credential
    /// was checked, a TURN server that relayed to its own network, unbounded connections, permissions and candidates, and
    /// indications forged to a TURN client.
    /// </summary>
    [TestClass]
    public class TestSecurity
    {
        private static TurnServerOptions TurnOptions() => new TurnServerOptions
        {
            Stun = new StunServerOptions { Realm = "example.org", Users = new Dictionary<string, string> { ["user"] = "secret" }, AuthenticateBinding = false },
            RelayAddress = IPAddress.Loopback,
        };

        private static StunClientOptions ClientOptions() => new StunClientOptions
        {
            Username = "user",
            Password = "secret",
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxTransmissions = 4,
        };

        private static async Task<TurnClient> Allocate(int port, TurnAllocateOptions options = null)
        {
            var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + port);
            await client.AllocateAsync(options);
            return client;
        }

        [TestMethod]
        [DataRow("obMatJos2AA==")]
        [DataRow("obMatJos2AAA=")]
        [DataRow("obMatJos2!!!!")]
        public void ANonceOfTooFewFeatureBytesIsOfNoFeatures(string nonce)
        {
            Assert.IsNull(StunCredentials.GetSecurityFeatures(nonce));
        }

        [TestMethod]
        public void ARequestOfSuchANonceIsChallengedNotThrown()
        {
            using var server = new StunServer(new StunServerOptions { Realm = "example.org", Users = new Dictionary<string, string> { ["user"] = "secret" } });
            byte[] key = new byte[16];
            byte[] request = new StunMessage(StunMethod.Binding, StunMessageClass.Request)
                .AddString(StunAttributeType.Username, "anyone")
                .AddString(StunAttributeType.Realm, "anything")
                .AddString(StunAttributeType.Nonce, "obMatJos2AA==")
                .ToBytes(key);

            byte[] answer = server.Process(request, 0, request.Length, new IPEndPoint(IPAddress.Loopback, 5000), false);

            Assert.AreEqual(StunErrorCode.Unauthorized, StunMessage.Parse(answer, 0, answer.Length).Error.Value.Code);
        }

        [TestMethod]
        [DataRow("8.8.8.8", true)]
        [DataRow("2001:4860:4860::8888", true)]
        [DataRow("127.0.0.1", false)]
        [DataRow("10.1.2.3", false)]
        [DataRow("172.16.0.1", false)]
        [DataRow("172.32.0.1", true)]
        [DataRow("192.168.1.1", false)]
        [DataRow("169.254.1.1", false)]
        [DataRow("100.64.0.1", false)]
        [DataRow("100.128.0.1", true)]
        [DataRow("0.0.0.0", false)]
        [DataRow("224.0.0.251", false)]
        [DataRow("239.255.255.250", false)]
        [DataRow("255.255.255.255", false)]
        [DataRow("::1", false)]
        [DataRow("::", false)]
        [DataRow("fe80::1", false)]
        [DataRow("fd00::1", false)]
        [DataRow("ff02::fb", false)]
        [DataRow("::ffff:127.0.0.1", false)]
        [DataRow("::ffff:8.8.8.8", true)]
        [DataRow("64:ff9b::a00:1", false)]
        [DataRow("64:ff9b::808:808", true)]
        [DataRow("2002:c0a8:101::1", false)]
        public void OnlyPublicUnicastPeersAreRelayedToOfTheDefault(string address, bool expected)
        {
            Assert.AreEqual(expected, TurnPeers.IsPublic(new IPEndPoint(IPAddress.Parse(address), 5000)));
        }

        [TestMethod]
        public void ATurnServerOfNoCredentialsIsRefused()
        {
            Assert.ThrowsExactly<ArgumentException>(() => new TurnServer(new TurnServerOptions()));
            using var open = new TurnServer(new TurnServerOptions { AllowUnauthenticated = true });
        }

        [TestMethod]
        public async Task TheLoopbackIsNoPeerOfTheDefault()
        {
            using var server = new TurnServer(TurnOptions());
            int port = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)).Port;
            using var client = await Allocate(port);

            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.CreatePermissionAsync(IPAddress.Loopback));
            Assert.AreEqual(TurnErrorCode.Forbidden, error.Code);
            error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.CreatePermissionAsync(IPAddress.Parse("192.168.1.1")));
            Assert.AreEqual(TurnErrorCode.Forbidden, error.Code);
        }

        [TestMethod]
        public async Task TheServersOwnListenerIsNoPeerOfAny()
        {
            var options = TurnOptions();
            options.AllowPeer = peer => true;
            using var server = new TurnServer(options);
            int port = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)).Port;
            using var client = await Allocate(port);

            // a channel to the listener: an Allocate of the relay's, a loop of the server's own
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.BindChannelAsync(new IPEndPoint(IPAddress.Loopback, port)));
            Assert.AreEqual(TurnErrorCode.Forbidden, error.Code);
            // another port of the loopback, allowed of the options, is a peer
            await client.BindChannelAsync(new IPEndPoint(IPAddress.Loopback, port == 9 ? 10 : 9));
        }

        [TestMethod]
        public async Task PermissionsAreOfAQuota()
        {
            var options = TurnOptions();
            options.AllowPeer = peer => true;
            options.MaxPermissionsPerAllocation = 2;
            using var server = new TurnServer(options);
            int port = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)).Port;
            using var client = await Allocate(port);

            await client.CreatePermissionAsync(IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4"));
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => client.CreatePermissionAsync(IPAddress.Parse("1.1.1.1")));
            Assert.AreEqual(TurnErrorCode.InsufficientCapacity, error.Code);
            await client.CreatePermissionAsync(IPAddress.Parse("8.8.8.8"));
        }

        [TestMethod]
        public async Task AReservedPortIsOfTheUsersQuota()
        {
            var options = TurnOptions();
            options.MaxAllocationsPerUser = 2;
            using var server = new TurnServer(options);
            int port = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)).Port;

            // an allocation and the port it reserved: two of the user's quota of two
            var first = await Allocate(port, new TurnAllocateOptions { EvenPort = true, ReserveNextPort = true });
            var error = await Assert.ThrowsExactlyAsync<TurnException>(() => Allocate(port));
            Assert.AreEqual(TurnErrorCode.AllocationQuotaReached, error.Code);

            // deleted, the allocation's reservation with it
            await first.DeallocateAsync();
            first.Dispose();
            using var second = await Allocate(port);
            using var third = await Allocate(port);
        }

        [TestMethod]
        public void AnIndicationOfAnotherThanTheServerIsNotTheServers()
        {
            var server = new IPEndPoint(IPAddress.Loopback, 3478);
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            using var transport = new StunUdpTransport(socket, server, false);
            int told = 0;
            transport.MessageReceived += (s, e) => told++;
            var peer = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 1234);
            var indication = new StunMessage(TurnMethod.Data, StunMessageClass.Indication).AddXorAddress(peer, TurnAttributeType.XorPeerAddress).AddAttribute(TurnAttributeType.Data, new byte[] { 1, 2, 3 });
            byte[] bytes = indication.ToBytes(null, false);

            Assert.IsFalse(transport.Receive(bytes, 0, bytes.Length, new IPEndPoint(IPAddress.Loopback, 40000)), "forged of another source");
            Assert.AreEqual(0, told);
            Assert.IsTrue(transport.Receive(bytes, 0, bytes.Length, server));
            Assert.AreEqual(1, told);
        }

        [TestMethod]
        public void TheCandidatesOfAPeerAreOfAQuota()
        {
            using var agent = new IceAgent(new IceAgentOptions { MaxRemoteCandidates = 3 });
            for (int i = 0; i < 3; i++)
                Assert.IsTrue(agent.AddRemoteCandidate($"candidate:{i} 1 udp 2130706431 192.0.2.{i + 1} 5000 typ host"));
            Assert.IsFalse(agent.AddRemoteCandidate("candidate:9 1 udp 2130706431 192.0.2.9 5000 typ host"));
            Assert.IsFalse(new IceAgent().AddRemoteCandidate("candidate:1 1 udp 2130706431 192.0.2.1 70000 typ host"), "of a port that is none");
            Assert.IsFalse(new IceAgent().AddRemoteCandidate("candidate:1 1 udp 2130706431 attacker.example 5000 typ host"), "no name looked up of DNS");
        }

        [TestMethod]
        public void AQueryOfAnotherNetworkIsNotAnswered()
        {
            Assert.IsTrue(MdnsResponder.IsOnLink(IPAddress.Parse("fe80::1")));
            Assert.IsTrue(MdnsResponder.IsOnLink(IPAddress.Loopback));
            Assert.IsFalse(MdnsResponder.IsOnLink(IPAddress.Parse("8.8.8.8")));
            Assert.IsFalse(MdnsResponder.IsOnLink(IPAddress.Parse("2001:4860:4860::8888")));
        }

        [TestMethod]
        public async Task ConnectionsAreOfAQuotaAndADeadline()
        {
            using var server = new StunServer(new StunServerOptions { MaxConnections = 1, FirstMessageTimeout = TimeSpan.FromMilliseconds(300) });
            var endPoint = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));

            using var first = new TcpClient();
            await first.ConnectAsync(endPoint.Address, endPoint.Port);
            await Task.Delay(100);
            using var second = new TcpClient();
            await second.ConnectAsync(endPoint.Address, endPoint.Port);
            var stream = second.GetStream();
            stream.ReadTimeout = 3000;
            Assert.AreEqual(0, stream.Read(new byte[1], 0, 1), "past the quota, closed as it is accepted");

            // the first, of no message, closed past its deadline
            var firstStream = first.GetStream();
            firstStream.ReadTimeout = 3000;
            Assert.AreEqual(0, firstStream.Read(new byte[1], 0, 1));
        }
    }
}
