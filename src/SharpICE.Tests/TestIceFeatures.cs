using SharpStunClient;
using SharpStunCommon;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// Agents on this machine's loopback, of what RFC 8445 has beyond the checks themselves: ICE over TCP (RFC 6544), frozen
    /// foundations, end-of-candidates (RFC 8838), candidates of mDNS names, a lite peer, and a restart.
    /// </summary>
    [TestClass]
    public class TestIceFeatures
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static IceAgentOptions Loopback(IceRole role = IceRole.Controlled) => new IceAgentOptions
        {
            Role = role,
            IncludeLoopback = true,
            AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
        };

        private static void Exchange(IceAgent a, IceAgent b)
        {
            a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
            b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
            foreach (var candidate in b.LocalCandidates)
                a.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in a.LocalCandidates)
                b.AddRemoteCandidate(candidate.ToString());
        }

        private static async Task WaitUntil(Func<bool> condition, string what)
        {
            DateTime deadline = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < deadline)
            {
                if (condition())
                    return;
                await Task.Delay(20);
            }
            Assert.Fail(what);
        }

        private static async Task Connect(IceAgent a, IceAgent b)
        {
            await a.GatherCandidatesAsync();
            await b.GatherCandidatesAsync();
            Exchange(a, b);
            a.Start();
            b.Start();
            await WaitUntil(() => a.SelectedPair?.Nominated == true && b.SelectedPair?.Nominated == true,
                $"Not connected: {a.State} {a.SelectedPair}, {b.State} {b.SelectedPair}");
        }

        private static async Task<string> SendAndReceive(IceAgent from, IceAgent to, string text)
        {
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler<IceDataReceivedEventArgs> handler = (s, e) => received.TrySetResult(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            to.DataReceived += handler;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text);
                Assert.IsTrue(from.Send(bytes, 0, bytes.Length));
                Assert.AreSame(received.Task, await Task.WhenAny(received.Task, Task.Delay(Timeout)));
                return await received.Task;
            }
            finally
            {
                to.DataReceived -= handler;
            }
        }

        [TestMethod]
        public async Task ConnectsOverTcpAlone()
        {
            var options = Loopback(IceRole.Controlling);
            options.IncludeUdp = false;
            options.IncludeTcp = true;
            using var controlling = new IceAgent(options);
            options = Loopback();
            options.IncludeUdp = false;
            options.IncludeTcp = true;
            using var controlled = new IceAgent(options);

            await Connect(controlling, controlled);

            Assert.IsTrue(controlling.SelectedPair.IsTcp && controlled.SelectedPair.IsTcp);
            Assert.AreEqual(IceCandidate.TcpActive, controlling.SelectedPair.Local.TcpType, "the controlling one's active candidate, of the other's passive one");
            Assert.AreEqual(controlling.SelectedPair.LocalEndPoint, controlled.SelectedPair.RemoteEndPoint);
            Assert.AreEqual("hello", await SendAndReceive(controlling, controlled, "hello"));
            Assert.AreEqual("world", await SendAndReceive(controlled, controlling, "world"));

            // packets one after another come apart as they went, of their frames
            string large = new string('x', 1400);
            var received = new ConcurrentQueue<string>();
            controlled.DataReceived += (s, e) => received.Enqueue(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            for (int i = 0; i < 20; i++)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(i + large);
                Assert.IsTrue(controlling.Send(bytes, 0, bytes.Length));
            }
            await WaitUntil(() => received.Count == 20, $"{received.Count} of 20 received");
            CollectionAssert.AreEqual(Enumerable.Range(0, 20).Select(i => i + large).ToArray(), received.ToArray());
        }

        [TestMethod]
        public async Task PrefersUdpOverTcp()
        {
            var options = Loopback(IceRole.Controlling);
            options.IncludeTcp = true;
            using var controlling = new IceAgent(options);
            options = Loopback();
            options.IncludeTcp = true;
            using var controlled = new IceAgent(options);

            await Connect(controlling, controlled);

            Assert.AreEqual(3, controlling.LocalCandidates.Count, "of UDP, of TCP passive and of TCP active");
            Assert.IsFalse(controlling.SelectedPair.IsTcp);
            Assert.IsFalse(controlled.SelectedPair.IsTcp);
        }

        [TestMethod]
        public async Task FreezesThePairsOfAFoundationUntilOneSucceeds()
        {
            using var controlling = new IceAgent(Loopback(IceRole.Controlling));
            using var controlled = new IceAgent(Loopback());
            await controlling.GatherCandidatesAsync();
            await controlled.GatherCandidatesAsync();

            // a second candidate of the foundation of the controlled one's, of a port nothing answers on
            var real = controlled.LocalCandidates.Single();
            using var nothing = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            nothing.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var dead = IceCandidate.Parse(real.ToString());
            dead.Port = ((IPEndPoint)nothing.LocalEndPoint).Port;
            dead.Priority = real.Priority - 1;

            controlling.SetRemoteCredentials(controlled.LocalUfrag, controlled.LocalPassword);
            controlled.SetRemoteCredentials(controlling.LocalUfrag, controlling.LocalPassword);
            controlling.AddRemoteCandidate(real);
            controlling.AddRemoteCandidate(dead);
            controlled.AddRemoteCandidate(controlling.LocalCandidates.Single());

            var pairs = controlling.Pairs;
            Assert.AreEqual(2, pairs.Count);
            Assert.AreEqual(pairs[0].Foundation, pairs[1].Foundation);
            Assert.AreEqual(IceCandidatePairState.Waiting, pairs.Single(p => p.Remote == real).State);
            Assert.AreEqual(IceCandidatePairState.Frozen, pairs.Single(p => p.Remote == dead).State);

            controlling.Start();
            controlled.Start();
            await WaitUntil(() => controlling.SelectedPair?.Nominated == true, "not connected");

            // the frozen one unfrozen once the other succeeded, then checked, of no answer
            Assert.AreNotEqual(IceCandidatePairState.Frozen, controlling.Pairs.Single(p => p.Remote == dead).State);
            Assert.AreEqual(real, controlling.SelectedPair.Remote);
        }

        [TestMethod]
        public async Task FailsAtOnceOfTheEndOfThePeersCandidates()
        {
            var options = Loopback(IceRole.Controlling);
            options.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(20);
            options.MaxTransmissions = 2;
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            using var nothing = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            nothing.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            agent.SetRemoteCredentials("peer", "peerpasswordpeerpassword");
            agent.AddRemoteCandidate($"candidate:1 1 udp 2130706431 127.0.0.1 {((IPEndPoint)nothing.LocalEndPoint).Port} typ host");
            Assert.IsTrue(agent.AddRemoteCandidate("a=end-of-candidates"));
            Assert.IsTrue(agent.RemoteGatheringComplete);
            var started = DateTime.UtcNow;
            agent.Start();

            await WaitUntil(() => agent.State == IceConnectionState.Failed, $"not failed: {agent.State}");
            Assert.IsTrue(DateTime.UtcNow - started < TimeSpan.FromSeconds(3), "rather than waiting for more candidates");
        }

        [TestMethod]
        public async Task WaitsForMoreCandidatesOfNoEndOfCandidates()
        {
            var options = Loopback(IceRole.Controlling);
            options.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(20);
            options.MaxTransmissions = 2;
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            using var nothing = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            nothing.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            agent.SetRemoteCredentials("peer", "peerpasswordpeerpassword");
            agent.AddRemoteCandidate($"candidate:1 1 udp 2130706431 127.0.0.1 {((IPEndPoint)nothing.LocalEndPoint).Port} typ host");
            agent.Start();
            await WaitUntil(() => agent.Pairs.All(p => p.State == IceCandidatePairState.Failed), "the pair not failed");
            await Task.Delay(500);

            Assert.AreEqual(IceConnectionState.Checking, agent.State);
        }

        /// <summary>An mDNS responder of one name on the loopback: it answers each query of it, as of a port of the querier's own.</summary>
        private sealed class FakeMdnsResponder : IDisposable
        {
            private readonly Socket _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            public FakeMdnsResponder(string name, IPAddress address)
            {
                _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                Task.Run(async () =>
                {
                    byte[] buffer = new byte[1500];
                    while (true)
                    {
                        SocketReceiveFromResult result;
                        try
                        {
                            result = await _socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0));
                        }
                        catch (Exception)
                        {
                            return;
                        }
                        Interlocked.Increment(ref Queries);
                        int position = 12;
                        string asked = DnsMessage.ReadName(buffer, result.ReceivedBytes, ref position);
                        if (!string.Equals(asked, name, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // the ID, an authoritative answer, no question, one A record of the cache-flush bit
                        var answer = new List<byte> { buffer[0], buffer[1], 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 };
                        foreach (string label in name.Split('.'))
                        {
                            answer.Add((byte)label.Length);
                            answer.AddRange(Encoding.ASCII.GetBytes(label));
                        }
                        answer.AddRange(new byte[] { 0, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4 });
                        answer.AddRange(address.GetAddressBytes());
                        _socket.SendTo(answer.ToArray(), result.RemoteEndPoint);
                    }
                });
            }

            public int Queries;

            public IPEndPoint EndPoint => (IPEndPoint)_socket.LocalEndPoint;

            public void Dispose() => _socket.Dispose();
        }

        [TestMethod]
        public async Task ResolvesACandidateOfAnMdnsName()
        {
            const string Name = "0e3b5e1f-6d1c-4b8a-9d4a-1f2e3d4c5b6a.local";
            using var controlling = new IceAgent(Loopback(IceRole.Controlling));
            var options = Loopback();
            options.ResolveMdns = false;
            using var controlled = new IceAgent(options);
            await controlling.GatherCandidatesAsync();
            await controlled.GatherCandidatesAsync();
            using var responder = new FakeMdnsResponder(Name, IPAddress.Loopback);
            controlling.Mdns = new MdnsResolver(new[] { responder.EndPoint });

            // the controlled one's candidate of its address hidden behind a name, as a browser's
            var hidden = IceCandidate.Parse(controlled.LocalCandidates.Single().ToString());
            hidden.Address = Name;
            controlling.SetRemoteCredentials(controlled.LocalUfrag, controlled.LocalPassword);
            controlled.SetRemoteCredentials(controlling.LocalUfrag, controlling.LocalPassword);
            Assert.IsTrue(controlling.AddRemoteCandidate(hidden.ToString()));
            controlled.AddRemoteCandidate(controlling.LocalCandidates.Single());

            await WaitUntil(() => controlling.RemoteCandidates.Count == 1, "not resolved");
            Assert.AreEqual("127.0.0.1", controlling.RemoteCandidates[0].Address);
            Assert.AreEqual(IceCandidateType.Host, controlling.RemoteCandidates[0].Type);

            controlling.Start();
            controlled.Start();
            await WaitUntil(() => controlling.SelectedPair?.Nominated == true && controlled.SelectedPair?.Nominated == true, "not connected");
            Assert.AreEqual(IceCandidateType.Host, controlling.SelectedPair.Remote.Type, "of the name's address, not learnt of the peer's checks");
        }

        [TestMethod]
        public async Task LeavesOutACandidateOfAnMdnsNameNoOneAnswers()
        {
            var options = Loopback(IceRole.Controlling);
            options.MdnsTimeout = TimeSpan.FromMilliseconds(300);
            using var agent = new IceAgent(options);
            using var responder = new FakeMdnsResponder("other.local", IPAddress.Loopback);
            agent.Mdns = new MdnsResolver(new[] { responder.EndPoint });

            Assert.IsTrue(agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 nobody.local 50000 typ host"));
            await Task.Delay(800);

            Assert.AreEqual(0, agent.RemoteCandidates.Count);
            Assert.IsTrue(responder.Queries >= 1);
        }

        [TestMethod]
        public async Task HidesItsAddressBehindAnMdnsName()
        {
            var options = Loopback();
            options.MdnsCandidates = true;
            using var hiding = new IceAgent(options) { MdnsResponderEndPoint = new IPEndPoint(IPAddress.Loopback, 0) };
            using var resolving = new IceAgent(Loopback(IceRole.Controlling));
            await hiding.GatherCandidatesAsync();
            resolving.Mdns = new MdnsResolver(new[] { hiding.MdnsResponder.EndPoint });

            // of no address of its own: a name of a UUID, and ".local"
            var candidate = hiding.LocalCandidates.Single();
            Assert.IsNull(candidate.EndPoint);
            Assert.IsTrue(candidate.Address.EndsWith(".local", StringComparison.Ordinal));
            Assert.IsTrue(Guid.TryParse(candidate.Address.Substring(0, candidate.Address.Length - ".local".Length), out _));

            await Connect(resolving, hiding);

            Assert.AreEqual(IceCandidateType.Host, resolving.SelectedPair.Remote.Type, "of the name resolved, not learnt of the checks");
            Assert.AreEqual("127.0.0.1", resolving.SelectedPair.Remote.Address);
            Assert.AreEqual("hidden", await SendAndReceive(resolving, hiding, "hidden"));
            Assert.AreEqual("found", await SendAndReceive(hiding, resolving, "found"));
        }

        private static SharpTurnServer.TurnServer TurnServer(out string uri)
        {
            var server = new SharpTurnServer.TurnServer(new SharpTurnServer.TurnServerOptions
            {
                Stun = new SharpStunServer.StunServerOptions
                {
                    Realm = "example.org",
                    Users = new Dictionary<string, string> { ["user"] = "secret" },
                    AuthenticateBinding = false,
                },
                RelayAddress = IPAddress.Loopback,
                // the peers of the tests are of the loopback
                AllowPeer = peer => true,
            });
            uri = "turn:127.0.0.1:" + server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)).Port;
            return server;
        }

        private static IceAgentOptions Relayed(string uri, IceRole role)
        {
            var options = Loopback(role);
            options.RelayOnly = true;
            options.TurnServers.Add(new IceTurnServer { Uri = uri, Username = "user", Password = "secret" });
            return options;
        }

        [TestMethod]
        public async Task ConnectsThroughTurnRelaysAlone()
        {
            using var server = TurnServer(out string uri);
            var controlling = new IceAgent(Relayed(uri, IceRole.Controlling));
            var controlled = new IceAgent(Relayed(uri, IceRole.Controlled));
            try
            {
                await Connect(controlling, controlled);

                Assert.AreEqual(IceCandidateType.Relayed, controlling.LocalCandidates.Single().Type, "of the relay alone");
                Assert.AreEqual(IPAddress.Loopback.ToString(), controlling.LocalCandidates.Single().RelatedAddress, "of the mapped address the allocation saw");
                Assert.AreEqual(IceCandidateType.Relayed, controlling.SelectedPair.Local.Type);
                Assert.AreEqual(IceCandidateType.Relayed, controlled.SelectedPair.Local.Type);
                Assert.AreEqual(2, server.AllocationCount);
                Assert.AreEqual("relayed", await SendAndReceive(controlling, controlled, "relayed"));
                Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));
            }
            finally
            {
                controlling.Dispose();
                controlled.Dispose();
            }
            Assert.AreEqual(0, server.AllocationCount, "deleted as the agents closed");
        }

        [TestMethod]
        public async Task ConnectsARelayToAHost()
        {
            using var server = TurnServer(out string uri);
            using var relayed = new IceAgent(Relayed(uri, IceRole.Controlling));
            using var host = new IceAgent(Loopback());

            await Connect(relayed, host);

            Assert.AreEqual(IceCandidateType.Relayed, relayed.SelectedPair.Local.Type);
            Assert.AreEqual(IceCandidateType.Host, relayed.SelectedPair.Remote.Type);
            Assert.AreEqual(relayed.LocalCandidates.Single().EndPoint, host.SelectedPair.RemoteEndPoint, "of the relayed address, as the host sees it");
            Assert.AreEqual("through", await SendAndReceive(relayed, host, "through"));
            Assert.AreEqual("the relay", await SendAndReceive(host, relayed, "the relay"));
        }

        [TestMethod]
        public async Task ControlsALitePeer()
        {
            var traced = new ConcurrentQueue<string>();
            var options = Loopback(IceRole.Controlling);
            options.Lite = true;
            options.Trace = traced.Enqueue;
            using var lite = new IceAgent(options);
            using var full = new IceAgent(Loopback(IceRole.Controlled));
            Assert.AreEqual(IceRole.Controlled, lite.Role, "a lite agent is controlled");

            full.SetRemoteLite(true);
            Assert.AreEqual(IceRole.Controlling, full.Role, "of a lite peer, the full agent controls");

            await Connect(full, lite);

            Assert.AreEqual("to lite", await SendAndReceive(full, lite, "to lite"));
            Assert.AreEqual("from lite", await SendAndReceive(lite, full, "from lite"));
            Assert.IsFalse(traced.Any(line => line.StartsWith("Check ", StringComparison.Ordinal)), "the lite agent checked nothing");
        }

        [TestMethod]
        public async Task RestartsAndSendsOnMeanwhile()
        {
            using var controlling = new IceAgent(Loopback(IceRole.Controlling));
            using var controlled = new IceAgent(Loopback());
            await Connect(controlling, controlled);
            var before = controlling.SelectedPair;
            string ufrag = controlling.LocalUfrag;

            controlling.Restart();
            Assert.AreNotEqual(ufrag, controlling.LocalUfrag);
            Assert.IsNull(controlling.RemoteUfrag);

            // the data goes by the pair selected until another is
            Assert.AreEqual("during", await SendAndReceive(controlling, controlled, "during"));
            Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));

            // the new offer's credentials: the peer restarts too, and answers of its own new ones
            string controlledUfrag = controlled.LocalUfrag;
            Assert.IsTrue(controlled.SetRemoteCredentials(controlling.LocalUfrag, controlling.LocalPassword));
            Assert.AreNotEqual(controlledUfrag, controlled.LocalUfrag);
            Assert.IsFalse(controlling.SetRemoteCredentials(controlled.LocalUfrag, controlled.LocalPassword));
            foreach (var candidate in controlled.LocalCandidates)
                controlling.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in controlling.LocalCandidates)
                controlled.AddRemoteCandidate(candidate.ToString());

            await WaitUntil(() => controlling.SelectedPair != before && controlling.SelectedPair?.Nominated == true && controlled.SelectedPair?.Nominated == true,
                "no pair of the new credentials selected");
            Assert.AreEqual(IceConnectionState.Connected, controlling.State);
            Assert.AreEqual("after", await SendAndReceive(controlling, controlled, "after"));
            Assert.AreEqual("again", await SendAndReceive(controlled, controlling, "again"));
        }
    }
}
