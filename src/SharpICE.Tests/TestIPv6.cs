using SharpStunServer;
using SharpTurnServer;
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
    /// IPv6 of the agent: the addresses it leaves out, the families intermingled IPv6 first (RFC 8421), agents of IPv6 alone and
    /// of both families on the loopback, relayed addresses of IPv6 of a dual allocation, and names of mDNS of AAAA records.
    /// </summary>
    [TestClass]
    public class TestIPv6
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        [TestMethod]
        [DataRow("2001:db8::1", true)]
        [DataRow("fd8f:ff1b:35a3:4d3d::1", true)]   // unique local, of a LAN
        [DataRow("::1", true)]
        [DataRow("fe80::1", false)]                  // link-local
        [DataRow("fec0::1", false)]                  // site-local
        [DataRow("ff02::fb", false)]                 // multicast
        [DataRow("::ffff:192.0.2.1", false)]         // IPv4-mapped
        [DataRow("::192.0.2.1", false)]              // IPv4-compatible
        [DataRow("2002:c000:201::1", false)]         // 6to4
        [DataRow("2001:0:4136:e378::1", false)]      // Teredo
        [DataRow("3ffe::1", false)]                  // 6bone
        public void LeavesOutWhatAPeerCannotReach(string address, bool usable)
        {
            Assert.AreEqual(usable, IceAgent.IsUsableIPv6(IPAddress.Parse(address)));
        }

        [TestMethod]
        public void InterminglesTheFamiliesIPv6First()
        {
            static string Order(params string[] addresses)
                => string.Concat(IceAgent.Intermingle(addresses.Select(IPAddress.Parse).ToList()).Select(a => a.AddressFamily == AddressFamily.InterNetworkV6 ? "6" : "4"));

            // RFC 8421 4: of 2 of IPv4 and 6 of IPv6, 3 of IPv6 before each of IPv4
            Assert.AreEqual("66646664", Order("::1", "::2", "::3", "::4", "::5", "::6", "10.0.0.1", "10.0.0.2"));
            Assert.AreEqual("64", Order("10.0.0.1", "::1"));
            Assert.AreEqual("6464", Order("10.0.0.1", "::1", "::2", "10.0.0.2"));
            Assert.AreEqual("664", Order("::1", "10.0.0.1", "::2"));
            Assert.AreEqual("66", Order("::1", "::2"));
            Assert.AreEqual("444", Order("10.0.0.1", "10.0.0.2", "10.0.0.3"));

            // the order within a family as it was
            var ordered = IceAgent.Intermingle(new[] { "10.0.0.2", "::2", "10.0.0.1", "::1" }.Select(IPAddress.Parse).ToList());
            CollectionAssert.AreEqual(new[] { "::2", "10.0.0.2", "::1", "10.0.0.1" }, ordered.Select(a => a.ToString()).ToArray());
        }

        private static IceAgentOptions Options(IceRole role, Func<IPAddress, bool> filter) => new IceAgentOptions
        {
            Role = role,
            IncludeLoopback = true,
            IncludeIPv6 = true,
            AddressFilter = filter,
        };

        private static async Task Connect(IceAgent a, IceAgent b)
        {
            await a.GatherCandidatesAsync();
            await b.GatherCandidatesAsync();
            a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
            b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
            foreach (var candidate in b.LocalCandidates)
                a.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in a.LocalCandidates)
                b.AddRemoteCandidate(candidate.ToString());
            a.Start();
            b.Start();
            DateTime deadline = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < deadline && !(a.SelectedPair?.Nominated == true && b.SelectedPair?.Nominated == true))
                await Task.Delay(20);
            Assert.IsTrue(a.SelectedPair?.Nominated == true && b.SelectedPair?.Nominated == true, $"Not connected: {a.SelectedPair}, {b.SelectedPair}");
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
        public async Task ConnectsOverIPv6()
        {
            Func<IPAddress, bool> v6 = a => a.Equals(IPAddress.IPv6Loopback);
            using var controlling = new IceAgent(Options(IceRole.Controlling, v6));
            using var controlled = new IceAgent(Options(IceRole.Controlled, v6));

            await Connect(controlling, controlled);

            Assert.AreEqual(AddressFamily.InterNetworkV6, controlling.LocalCandidates.Single().EndPoint.AddressFamily);
            Assert.AreEqual(IPAddress.IPv6Loopback, controlling.SelectedPair.RemoteEndPoint.Address);
            Assert.AreEqual("six", await SendAndReceive(controlling, controlled, "six"));
            Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));
        }

        [TestMethod]
        public async Task PrefersIPv6OfBothFamilies()
        {
            Func<IPAddress, bool> loopback = a => IPAddress.IsLoopback(a);
            using var controlling = new IceAgent(Options(IceRole.Controlling, loopback));
            using var controlled = new IceAgent(Options(IceRole.Controlled, loopback));

            await Connect(controlling, controlled);

            var candidates = controlling.LocalCandidates.OrderByDescending(c => c.Priority).ToList();
            Assert.AreEqual(2, candidates.Count);
            Assert.AreEqual(AddressFamily.InterNetworkV6, candidates[0].EndPoint.AddressFamily, "IPv6 first (RFC 8421)");
            // the IPv6 pair checked first, of its priority; the first pair that works is nominated, which of a busy machine may
            // be the IPv4 one, its check answered first
            Assert.AreEqual(AddressFamily.InterNetworkV6, controlling.Pairs.OrderByDescending(p => p.Priority).First().RemoteEndPoint.AddressFamily, "the IPv6 pair first");
            Assert.AreEqual(4, controlling.Pairs.Count + controlled.Pairs.Count, "no pair of two families");
        }

        [TestMethod]
        public async Task RelaysOfIPv6OfADualAllocation()
        {
            using var server = new TurnServer(new TurnServerOptions
            {
                Stun = new StunServerOptions
                {
                    Realm = "example.org",
                    Users = new Dictionary<string, string> { ["user"] = "secret" },
                    AuthenticateBinding = false,
                },
                RelayAddress = IPAddress.Loopback,
                RelayAddressV6 = IPAddress.IPv6Loopback,
                // the peers of the test are of the loopback
                AllowPeer = peer => true,
            });
            string uri = "turn:[::1]:" + server.ListenUdp(new IPEndPoint(IPAddress.IPv6Loopback, 0)).Port;
            IceAgentOptions Relayed(IceRole role)
            {
                var options = Options(role, a => IPAddress.IsLoopback(a));
                options.RelayOnly = true;
                options.TurnServers.Add(new IceTurnServer { Uri = uri, Username = "user", Password = "secret" });
                return options;
            }
            using var controlling = new IceAgent(Relayed(IceRole.Controlling));
            using var controlled = new IceAgent(Relayed(IceRole.Controlled));

            await Connect(controlling, controlled);

            var relayed = controlling.LocalCandidates.OrderByDescending(c => c.Priority).ToList();
            CollectionAssert.AreEqual(new[] { AddressFamily.InterNetworkV6, AddressFamily.InterNetwork }, relayed.Select(c => c.EndPoint.AddressFamily).ToArray(), "a relay of each family, IPv6 first");
            Assert.IsTrue(relayed.All(c => c.Type == IceCandidateType.Relayed));
            Assert.AreEqual(AddressFamily.InterNetworkV6, controlling.SelectedPair.LocalEndPoint.AddressFamily);
            Assert.AreEqual("relayed six", await SendAndReceive(controlling, controlled, "relayed six"));
            Assert.AreEqual("back", await SendAndReceive(controlled, controlling, "back"));
        }

        [TestMethod]
        public async Task ResolvesAnMdnsNameOfIPv6()
        {
            using var responder = new MdnsResponder(new[] { IPAddress.IPv6Loopback }, new IPEndPoint(IPAddress.IPv6Loopback, 0), null);
            string name = responder.Register(IPAddress.IPv6Loopback);
            var resolver = new MdnsResolver(new[] { responder.EndPoint });

            var address = await resolver.ResolveAsync(name, new[] { IPAddress.IPv6Loopback }, true, TimeSpan.FromSeconds(2));

            Assert.AreEqual(IPAddress.IPv6Loopback, address, "of a AAAA record");
            Assert.IsNull(await resolver.ResolveAsync(name, new[] { IPAddress.IPv6Loopback }, false, TimeSpan.FromMilliseconds(300)), "of no IPv6 asked for");
        }
    }
}
