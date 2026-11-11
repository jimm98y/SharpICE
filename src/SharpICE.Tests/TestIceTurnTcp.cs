using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// Relayed candidates of ICE-TCP (RFC 6544), of TCP allocations of a TURN server of TCP (RFC 6062): an agent's active one
    /// connected of Connect to a peer's passive one, a peer's connection to its passive one taken of a ConnectionAttempt, and
    /// two agents of relays alone of each other; each candidate exchanged chosen, of one path each.
    /// </summary>
    [TestClass]
    public class TestIceTurnTcp
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

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
            uri = $"turn:127.0.0.1:{server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0)).Port}?transport=tcp";
            return server;
        }

        private static IceAgentOptions Options(IceRole role, string relayUri = null)
        {
            var options = new IceAgentOptions
            {
                Role = role,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                IncludeUdp = false,
                IncludeTcp = true,
                IncludeIPv6 = false,
            };
            if (relayUri != null)
            {
                options.RelayOnly = true;
                options.TurnServers.Add(new IceTurnServer { Uri = relayUri, Username = "user", Password = "secret" });
            }
            return options;
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

        // the candidates of TCP of each, of those chosen alone, told to the other
        private static async Task Connect(IceAgent a, IceAgent b, Func<IceCandidate, bool> ofA, Func<IceCandidate, bool> ofB)
        {
            await a.GatherCandidatesAsync();
            await b.GatherCandidatesAsync();
            a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
            b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
            foreach (var candidate in b.LocalCandidates.Where(c => c.IsTcp && ofB(c)))
                Assert.IsTrue(a.AddRemoteCandidate(candidate.ToString()), candidate.ToString());
            foreach (var candidate in a.LocalCandidates.Where(c => c.IsTcp && ofA(c)))
                Assert.IsTrue(b.AddRemoteCandidate(candidate.ToString()), candidate.ToString());
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

        private static bool Relayed(IceCandidate c) => c.Type == IceCandidateType.Relayed;
        private static bool Active(IceCandidate c) => c.TcpType == IceCandidate.TcpActive;
        private static bool Passive(IceCandidate c) => c.TcpType == IceCandidate.TcpPassive;

        [TestMethod]
        public async Task GathersRelayedCandidatesOfTcp()
        {
            using var server = TurnServer(out string uri);
            using var agent = new IceAgent(Options(IceRole.Controlling, uri));
            await agent.GatherCandidatesAsync();

            var tcp = agent.LocalCandidates.Where(c => c.IsTcp).ToList();
            Assert.AreEqual(2, tcp.Count, string.Join("; ", agent.LocalCandidates));
            Assert.IsTrue(tcp.All(Relayed));
            var passive = tcp.Single(Passive);
            var active = tcp.Single(Active);
            Assert.AreEqual(9, active.Port, "an active candidate is of port 9 (RFC 6544 4.5)");
            Assert.AreEqual(passive.Address, active.Address);
            Assert.AreEqual(passive.Foundation, active.Foundation);
            Assert.IsTrue(passive.Priority < IceCandidate.ComputePriority(IceCandidateType.ServerReflexive, 0, 1, "tcp"), "below every other type");
            Assert.AreEqual(2, server.AllocationCount, "a UDP allocation over TCP, and a TCP one");
        }

        [TestMethod]
        public async Task ConnectsOfItsActiveRelayedCandidate()
        {
            using var server = TurnServer(out string uri);
            using var controlling = new IceAgent(Options(IceRole.Controlling, uri));
            using var controlled = new IceAgent(Options(IceRole.Controlled));

            // the one pair: the relay's active candidate of the controlling agent, of the controlled one's passive one
            await Connect(controlling, controlled, c => Relayed(c) && Active(c), Passive);

            var selected = controlling.SelectedPair;
            Assert.AreEqual(IceCandidateType.Relayed, selected.Local.Type);
            Assert.AreEqual(IceCandidate.TcpActive, selected.Local.TcpType);
            Assert.AreEqual(IceCandidateType.Host, selected.Remote.Type);
            Assert.AreEqual(controlling.LocalCandidates.Single(c => Relayed(c) && Passive(c)).Port, controlled.SelectedPair.RemoteEndPoint.Port,
                "the controlled agent is connected of the relayed address");
            Assert.AreEqual("out", await SendAndReceive(controlling, controlled, "out"));
            Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));
        }

        [TestMethod]
        public async Task TakesAConnectionToItsPassiveRelayedCandidate()
        {
            using var server = TurnServer(out string uri);
            using var controlling = new IceAgent(Options(IceRole.Controlling));
            using var controlled = new IceAgent(Options(IceRole.Controlled, uri));

            // the one pair: the controlling agent's active candidate, connected to the controlled one's relayed address - of
            // the permission of the active candidate's address it signalled
            await Connect(controlling, controlled, Active, c => Relayed(c) && Passive(c));

            Assert.AreEqual(IceCandidateType.Relayed, controlled.SelectedPair.Local.Type);
            Assert.AreEqual(IceCandidate.TcpPassive, controlled.SelectedPair.Local.TcpType);
            Assert.AreEqual(controlled.LocalCandidates.Single(c => Relayed(c) && Passive(c)).Port, controlling.SelectedPair.RemoteEndPoint.Port);
            Assert.AreEqual("in", await SendAndReceive(controlling, controlled, "in"));
            Assert.AreEqual("out", await SendAndReceive(controlled, controlling, "out"));
        }

        [TestMethod]
        public async Task ConnectsThroughTcpRelaysAlone()
        {
            using var server = TurnServer(out string uri);
            var controlling = new IceAgent(Options(IceRole.Controlling, uri));
            var controlled = new IceAgent(Options(IceRole.Controlled, uri));
            try
            {
                // of relayed candidates of TCP alone, both ways: one relay's Connect to the other's relayed address
                await Connect(controlling, controlled, Relayed, Relayed);

                Assert.IsTrue(controlling.SelectedPair.IsTcp && controlled.SelectedPair.IsTcp);
                // of two relays of one server, one of them connects: of the other's, two Connects of one 4-tuple would fail
                Assert.AreEqual(1, controlling.Pairs.Count(p => p.Local.TcpType == IceCandidate.TcpActive) + controlled.Pairs.Count(p => p.Local.TcpType == IceCandidate.TcpActive),
                    "one active pair of the two agents");
                Assert.AreEqual(IceCandidateType.Relayed, controlling.SelectedPair.Local.Type);
                Assert.AreEqual(IceCandidateType.Relayed, controlled.SelectedPair.Local.Type);
                Assert.AreEqual("relayed", await SendAndReceive(controlling, controlled, "relayed"));
                Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));
            }
            finally
            {
                controlling.Dispose();
                controlled.Dispose();
            }
            DateTime deadline = DateTime.UtcNow + Timeout;
            while (server.AllocationCount > 0 && DateTime.UtcNow < deadline)
                await Task.Delay(20);
            Assert.AreEqual(0, server.AllocationCount, "deleted as the agents closed");
        }
    }
}
