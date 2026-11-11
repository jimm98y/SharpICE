using SharpStun;
using SharpTurn;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// What the security review of the DTLS and TLS stacks found, each of a test of its own: the TURN server's relays to its
    /// own host refused and its permissions of its default policy granted, connections of one source capped and a failed
    /// ConnectionBind's closed, an association of BouncyCastle's DTLS ended of the peer's close_notify, a TLS handshake of a
    /// server that answers nothing timed out, a DNS name of a pointer forward refused, and an ICE agent's remote candidates
    /// of unusable addresses, and its peer reflexive ones past its limit, left out.
    /// </summary>
    [TestClass]
    public class TestSecurityReview
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static TurnServerOptions TurnOptions(Func<IPEndPoint, bool> allowPeer = null) => new TurnServerOptions
        {
            Stun = new StunServerOptions
            {
                Realm = "example.org",
                Users = new Dictionary<string, string> { ["user"] = "secret" },
                AuthenticateBinding = false,
            },
            RelayAddress = IPAddress.Loopback,
            AllowPeer = allowPeer ?? TurnPeers.IsPublic,
        };

        private static StunClientOptions ClientOptions() => new StunClientOptions { Username = "user", Password = "secret", CertificateValidation = (s, c, ch, e) => true };

        private static IPAddress HostAddress() => NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(u => u.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));

        [TestMethod]
        public async Task GrantsPermissionsOfItsDefaultPolicy()
        {
            // a permission is of an address alone, of port 0 in its XOR-PEER-ADDRESS: of the default policy, of a public one
            using var server = new TurnServer(TurnOptions());
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await client.AllocateAsync();
            await client.CreatePermissionAsync(IPAddress.Parse("8.8.8.8"));
            Assert.IsTrue(client.HasPermission(IPAddress.Parse("8.8.8.8")));

            // of a private one, as ever, 403
            var refused = await Assert.ThrowsExactlyAsync<TurnException>(() => client.CreatePermissionAsync(IPAddress.Parse("192.168.1.1")));
            Assert.AreEqual(TurnErrorCode.Forbidden, refused.Code);
        }

        [TestMethod]
        public async Task RefusesRelaysToItsOwnHost()
        {
            // of a policy that lets anything through, as the tests' do: its own host's addresses, and the unspecified ones,
            // refused all the same, of every port but its relays'
            using var server = new TurnServer(TurnOptions(peer => true));
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Any, 0));
            using var client = new TurnClient(ClientOptions());
            await client.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await client.AllocateAsync();

            var unspecified = await Assert.ThrowsExactlyAsync<TurnException>(() => client.BindChannelAsync(new IPEndPoint(IPAddress.Any, 22)));
            Assert.AreEqual(TurnErrorCode.Forbidden, unspecified.Code, "of 0.0.0.0, of Linux the host's own");

            var host = HostAddress();
            if (host == null)
                Assert.Inconclusive("No address of an interface of this host's but the loopback.");
            var own = await Assert.ThrowsExactlyAsync<TurnException>(() => client.BindChannelAsync(new IPEndPoint(host, 22)));
            Assert.AreEqual(TurnErrorCode.Forbidden, own.Code, "of a service of the host's");
            var listener = await Assert.ThrowsExactlyAsync<TurnException>(() => client.BindChannelAsync(new IPEndPoint(host, udp.Port)));
            Assert.AreEqual(TurnErrorCode.Forbidden, listener.Code, "of its own listener");
        }

        [TestMethod]
        public async Task CapsTheConnectionsOfOneSource()
        {
            using var server = new StunServer(new StunServerOptions { MaxConnectionsPerAddress = 2 });
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var clients = new List<TcpClient>();
            try
            {
                for (int i = 0; i < 3; i++)
                {
                    var client = new TcpClient(AddressFamily.InterNetwork);
                    await client.ConnectAsync(IPAddress.Loopback, tcp.Port);
                    clients.Add(client);
                }
                // the third closed as it was accepted: its read ends
                var read = clients[2].GetStream().ReadAsync(new byte[1], 0, 1);
                Assert.AreSame(read, await Task.WhenAny(read, Task.Delay(Timeout)), "closed");
                Assert.AreEqual(0, await ReadOrReset(read));
                // one let go: another of the source taken again, and answered
                clients[0].Dispose();
                await Task.Delay(200);
                using var stun = new StunClient(await StunStreamTransport.ConnectAsync(tcp));
                Assert.IsNotNull(await stun.GetMappedAddressAsync());
            }
            finally
            {
                clients.ForEach(c => c.Dispose());
            }
        }

        private static async Task<int> ReadOrReset(Task<int> read)
        {
            try
            {
                return await read;
            }
            catch (IOException)
            {
                return 0;
            }
        }

        [TestMethod]
        public async Task ClosesAConnectionOfAFailedConnectionBind()
        {
            using var server = new TurnServer(TurnOptions(peer => true));
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            using var transport = await StunStreamTransport.ConnectAsync(tcp);
            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            transport.Closed += (s, e) => closed.TrySetResult(true);
            using var client = new StunClient(transport, ClientOptions());
            client.Options.IsKnownAttribute = TurnAttributeType.IsKnownOfTurn;

            // a guess of a CONNECTION-ID: answered, then the connection closed, that it guesses no other over it
            var response = await client.RequestAsync(new StunMessage(TurnMethod.ConnectionBind, StunMessageClass.Request).AddConnectionId(0x12345678));
            Assert.AreEqual(StunErrorCode.BadRequest, response.Error.Value.Code);
            Assert.AreSame(closed.Task, await Task.WhenAny(closed.Task, Task.Delay(Timeout)), "closed of the server");
        }

        [TestMethod]
        public async Task EndsAnAssociationOfBouncyCastleOfThePeersCloseNotify()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
            using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(created.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, DtlsStack = DtlsStacks.BouncyCastle });
            var ended = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ConnectionClosed += (s, connection) => ended.TrySetResult(true);
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));

            var transport = await StunDtlsTransport.ConnectAsync(dtls, "localhost", (s, c, ch, e) => true, DtlsStacks.BouncyCastle);
            using (var client = new StunClient(transport))
                Assert.IsNotNull(await client.GetMappedAddressAsync());
            // its close_notify: of BouncyCastle's record layer, the peer's datagrams ended - its thread to end, not to spin
            transport.Dispose();
            Assert.AreSame(ended.Task, await Task.WhenAny(ended.Task, Task.Delay(Timeout)), "the association ended of the server");
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        [DataRow("system")]
        public async Task TimesOutATlsHandshakeOfAServerThatAnswersNothing(string stack)
        {
            var tlsStack = stack == "bc" ? TlsStacks.BouncyCastle : stack == "system" ? TlsStacks.System : TlsStacks.SharpDtls;
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var accepting = listener.AcceptTcpClientAsync();
                var connecting = StunStreamTransport.ConnectAsync((IPEndPoint)listener.LocalEndpoint, "localhost", (s, c, ch, e) => true, tlsStack);
                using var silent = await accepting;
                var done = await Task.WhenAny(connecting, Task.Delay(TimeSpan.FromSeconds(30)));
                Assert.AreSame(connecting, done, "the handshake ended in time");
                await Assert.ThrowsExactlyAsync<IOException>(() => connecting);
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public void RefusesADnsNameOfAPointerForward()
        {
            // a response of one record whose name is a pointer to a name after it: of names built of pointers ever longer
            var message = new List<byte> { 0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0 };
            message.AddRange(new byte[] { 0xC0, 28, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 });
            message.AddRange(new byte[] { 3, (byte)'a', (byte)'b', (byte)'c', 0 });
            Assert.IsNull(DnsMessage.ParseResponse(message.ToArray(), message.Count, null, out _));

            // and a name longer than 255 bytes
            var longName = new List<byte> { 0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0 };
            for (int i = 0; i < 5; i++)
            {
                longName.Add(63);
                longName.AddRange(Enumerable.Repeat((byte)'x', 63));
            }
            longName.Add(0);
            longName.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 });
            Assert.IsNull(DnsMessage.ParseResponse(longName.ToArray(), longName.Count, null, out _));
        }

        [TestMethod]
        public void LeavesOutRemoteCandidatesOfUnusableAddresses()
        {
            using var agent = new IceAgent(new IceAgentOptions { IncludeLoopback = false });
            foreach (string address in new[] { "0.0.0.0", "224.0.0.251", "255.255.255.255", "239.1.2.3", "127.1", "2130706433", "::", "ff02::fb", "::ffff:192.0.2.1", "fe80::1%3", "127.0.0.1" })
                Assert.IsFalse(agent.AddRemoteCandidate($"candidate:1 1 udp 2130706431 {address} 50000 typ host"), address);
            Assert.IsTrue(agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.0.2.10 50000 typ host"), "a unicast address");
            Assert.AreEqual(1, agent.RemoteCandidates.Count);
        }

        [TestMethod]
        public async Task LearnsNoMorePeerReflexiveCandidatesThanItTakes()
        {
            var options = new IceAgentOptions
            {
                Role = IceRole.Controlled,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                MaxRemoteCandidates = 3,
            };
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            agent.SetRemoteCredentials("peer", "peerpasswordpeerpassword");
            agent.Start();
            var target = new IPEndPoint(IPAddress.Loopback, agent.LocalCandidates.Single().Port);
            var key = StunMessage.ShortTermKey(agent.LocalPassword);

            // checks of the agent's credentials, each of a source of its own
            var sockets = Enumerable.Range(0, 10).Select(_ =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                return socket;
            }).ToList();
            try
            {
                foreach (var socket in sockets)
                {
                    var check = new StunMessage(StunMethod.Binding, StunMessageClass.Request).AddString(StunAttributeType.Username, agent.LocalUfrag + ":peer")
                        .AddUInt32(StunAttributeType.Priority, 1).AddUInt64(StunAttributeType.IceControlling, 1);
                    socket.SendTo(check.ToBytes(key, true), target);
                }
                await Task.Delay(500);
                Assert.AreEqual(3, agent.RemoteCandidates.Count, "of the limit, and no more");
            }
            finally
            {
                sockets.ForEach(s => s.Dispose());
            }
        }
    }
}
