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

        [TestMethod]
        public async Task ExemptsOnlyARelayOfTheSameProtocolOnItsOwnAddress()
        {
            // relays on a host address: a TCP relay's port is no way to a UDP service of the host on that port, nor a UDP
            // relay's port to a TCP one
            var host = HostAddress();
            if (host == null)
                Assert.Inconclusive("No address of an interface of this host's but the loopback.");
            var options = TurnOptions(peer => true);
            options.RelayAddress = host;
            using var server = new TurnServer(options);
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));

            using var tcpClient = new TurnClient(ClientOptions());
            await tcpClient.ConnectAsync("turn:127.0.0.1:" + tcp.Port + "?transport=tcp");
            await tcpClient.AllocateAsync(new TurnAllocateOptions { Tcp = true });
            using var udpClient = new TurnClient(ClientOptions());
            await udpClient.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await udpClient.AllocateAsync();
            using var otherUdpClient = new TurnClient(ClientOptions());
            await otherUdpClient.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await otherUdpClient.AllocateAsync();

            var tcpRelay = new IPEndPoint(host, tcpClient.RelayedEndPoint.Port);
            var udpRelay = new IPEndPoint(host, otherUdpClient.RelayedEndPoint.Port);

            // UDP to a TCP relay's port: refused
            var refused = await Assert.ThrowsExactlyAsync<TurnException>(() => udpClient.BindChannelAsync(tcpRelay));
            Assert.AreEqual(TurnErrorCode.Forbidden, refused.Code, "UDP to the port of a TCP relay");
            // UDP to another allocation's UDP relay: allowed, as two clients of one server relay to each other
            await udpClient.BindChannelAsync(udpRelay);

            // TCP (Connect) to a UDP relay's port: refused
            await tcpClient.CreatePermissionAsync(host);
            var connect = await Assert.ThrowsExactlyAsync<TurnException>(() => tcpClient.ConnectPeerAsync(udpRelay));
            Assert.AreEqual(TurnErrorCode.Forbidden, connect.Code, "TCP to the port of a UDP relay");
        }

        [TestMethod]
        public async Task ClosesARelayedIceTcpConnectionWhosePeerReadsNothing()
        {
            // a connection of a stream - as of a TURN relay's data connection - to a peer that never reads: a write ends,
            // of the write timeout, and the connection with it, rather than blocking for ever
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var accepting = listener.AcceptTcpClientAsync();
                var client = new TcpClient(AddressFamily.InterNetwork);
                await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
                using var silent = await accepting;
                using var connection = new IceTcpConnection(client.GetStream(), (IPEndPoint)client.Client.LocalEndPoint, (IPEndPoint)client.Client.RemoteEndPoint, client);
                byte[] packet = new byte[60000];
                var sending = Task.Run(() =>
                {
                    while (connection.Send(packet, 0, packet.Length))
                    {
                    }
                });
                var done = await Task.WhenAny(sending, Task.Delay(TimeSpan.FromSeconds(60)));
                Assert.AreSame(sending, done, "the write ended, of its timeout");
                Assert.IsFalse(connection.Send(packet, 0, 10), "the connection closed");
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public async Task KeepsRoomForSignalledCandidatesWhenChecksAreReplayed()
        {
            // checks replayed from many sources fill the peer reflexive candidates' own cap, not that of the signalled ones
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
            var check = new StunMessage(StunMethod.Binding, StunMessageClass.Request).AddString(StunAttributeType.Username, agent.LocalUfrag + ":peer")
                .AddUInt32(StunAttributeType.Priority, 1).AddUInt64(StunAttributeType.IceControlling, 1).ToBytes(key, true);
            var sockets = Enumerable.Range(0, 10).Select(_ =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                return socket;
            }).ToList();
            try
            {
                // one captured check, replayed from each source
                foreach (var socket in sockets)
                    socket.SendTo(check, target);
                await Task.Delay(500);
                Assert.IsTrue(agent.RemoteCandidates.Count(c => c.Type == IceCandidateType.PeerReflexive) <= 3);
                for (int i = 0; i < 3; i++)
                    Assert.IsTrue(agent.AddRemoteCandidate($"candidate:{i} 1 udp 2130706431 192.0.2.{10 + i} 50000 typ host"), "signalled " + i);
                Assert.IsFalse(agent.AddRemoteCandidate("candidate:9 1 udp 2130706431 192.0.2.99 50000 typ host"), "past the signalled cap");
            }
            finally
            {
                sockets.ForEach(s => s.Dispose());
            }
        }

        [TestMethod]
        public async Task ClosesAPassiveConnectionOfAReplayedCheck()
        {
            // a check over a connection to a passive candidate, of the agent's credentials, from someone who never answers the
            // agent's own check: the connection is closed once that check has had its time
            var options = new IceAgentOptions
            {
                Role = IceRole.Controlled,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                IncludeTcp = true,
                TcpCheckTimeout = TimeSpan.FromSeconds(1),
            };
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            agent.SetRemoteCredentials("peer", "peerpasswordpeerpassword");
            agent.Start();
            var passive = agent.LocalCandidates.First(c => c.IsTcp && c.TcpType == IceCandidate.TcpPassive);
            var key = StunMessage.ShortTermKey(agent.LocalPassword);
            byte[] check = new StunMessage(StunMethod.Binding, StunMessageClass.Request).AddString(StunAttributeType.Username, agent.LocalUfrag + ":peer")
                .AddUInt32(StunAttributeType.Priority, 1).AddUInt64(StunAttributeType.IceControlling, 1).ToBytes(key, true);

            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, passive.Port);
            var stream = client.GetStream();
            byte[] frame = new byte[2 + check.Length];
            frame[0] = (byte)(check.Length >> 8);
            frame[1] = (byte)check.Length;
            Buffer.BlockCopy(check, 0, frame, 2, check.Length);
            await stream.WriteAsync(frame, 0, frame.Length);

            // what the agent sends - its response, its own check - is read and left unanswered, until it closes
            byte[] buffer = new byte[4096];
            var reading = Task.Run(async () =>
            {
                try
                {
                    while (await stream.ReadAsync(buffer, 0, buffer.Length) > 0)
                    {
                    }
                }
                catch (IOException)
                {
                }
            });
            Assert.AreSame(reading, await Task.WhenAny(reading, Task.Delay(TimeSpan.FromSeconds(20))), "the agent closed the connection");
        }

        [TestMethod]
        public async Task SwitchesRoleOnceOfSeveral487sToChecksOfOneRole()
        {
            // two checks in flight as controlling, both answered 487: the agent switches to controlled once, rather than
            // back and forth with each response
            var options = new IceAgentOptions
            {
                Role = IceRole.Controlling,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
            };
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            const string peerPassword = "peerpasswordpeerpassword";
            agent.SetRemoteCredentials("peer", peerPassword);
            var peerKey = StunMessage.ShortTermKey(peerPassword);
            var sockets = Enumerable.Range(0, 2).Select(_ =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                socket.ReceiveTimeout = 5000;
                return socket;
            }).ToList();
            try
            {
                // of foundations of their own, so that neither pair is frozen behind the other
                for (int i = 0; i < sockets.Count; i++)
                    Assert.IsTrue(agent.AddRemoteCandidate($"candidate:{i + 1} 1 udp 2130706431 127.0.0.1 {((IPEndPoint)sockets[i].LocalEndPoint).Port} typ host"));
                agent.Start();

                // each check, held until both have come
                var checks = new List<(Socket Socket, StunMessage Request, EndPoint From)>();
                foreach (var socket in sockets)
                {
                    byte[] buffer = new byte[1500];
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int count = socket.ReceiveFrom(buffer, ref from);
                    var request = StunMessage.Parse(buffer, 0, count);
                    Assert.IsNotNull(request);
                    Assert.IsTrue(request.HasAttribute(StunAttributeType.IceControlling));
                    checks.Add((socket, request, from));
                }
                foreach (var (socket, request, from) in checks)
                {
                    var error = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse) { TransactionId = request.TransactionId }
                        .AddError(StunErrorCode.RoleConflict, "Role Conflict");
                    socket.SendTo(error.ToBytes(peerKey, true), from);
                }
                await Task.Delay(500);
                Assert.AreEqual(IceRole.Controlled, agent.Role);
            }
            finally
            {
                sockets.ForEach(s => s.Dispose());
            }
        }
    }
}
