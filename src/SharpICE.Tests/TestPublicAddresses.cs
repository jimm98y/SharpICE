using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// The public addresses of a NAT of one to one - a cloud host's - told of as candidates of each socket's port: of a full
    /// agent server reflexive of the socket, of a lite one host candidates; of the family's sockets alone.
    /// </summary>
    [TestClass]
    public class TestPublicAddresses
    {
        // TEST-NET-3 and the documentation prefix (RFC 5737, RFC 3849): addresses of no host
        private static readonly IPAddress PublicV4 = IPAddress.Parse("203.0.113.7");
        private static readonly IPAddress PublicV6 = IPAddress.Parse("2001:db8::7");

        // the first IPv4 address of an interface that is up, not the loopback's: of a host of none, the tests are inconclusive
        private static IPAddress LanAddress()
        {
            var address = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(u => u.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));
            if (address == null)
                Assert.Inconclusive("No IPv4 address but the loopback's.");
            return address;
        }

        private static IceAgentOptions Options(IPAddress lan, bool lite = false, bool tcp = false) => new IceAgentOptions
        {
            Role = IceRole.Controlling,
            Lite = lite,
            IncludeTcp = tcp,
            AddressFilter = address => address.Equals(lan),
            PublicAddresses = { PublicV4, PublicV6 },
        };

        [TestMethod]
        public async Task ToldOfAsServerReflexiveOfEachSocket()
        {
            var lan = LanAddress();
            using var agent = new IceAgent(Options(lan, tcp: true));

            var candidates = await agent.GatherCandidatesAsync();

            var host = candidates.Single(c => c.Type == IceCandidateType.Host && c.IsUdp);
            var mapped = candidates.Single(c => c.Address == PublicV4.ToString() && c.IsUdp);
            Assert.AreEqual(IceCandidateType.ServerReflexive, mapped.Type);
            Assert.AreEqual(host.Port, mapped.Port, "of the socket's port, as the NAT maps it");
            Assert.AreEqual(lan.ToString(), mapped.RelatedAddress);
            Assert.AreEqual(host.Port, mapped.RelatedPort);
            Assert.IsTrue(mapped.Priority < host.Priority);

            var passive = candidates.Single(c => c.IsTcp && c.Type == IceCandidateType.Host && c.TcpType == IceCandidate.TcpPassive);
            var mappedTcp = candidates.Single(c => c.Address == PublicV4.ToString() && c.IsTcp);
            Assert.AreEqual(IceCandidate.TcpPassive, mappedTcp.TcpType, "of the passive listener alone");
            Assert.AreEqual(passive.Port, mappedTcp.Port);

            Assert.IsFalse(candidates.Any(c => c.Address == PublicV6.ToString()), "of IPv6, no socket to map");
            Assert.AreEqual(1, candidates.Count(c => c.Address == PublicV4.ToString() && c.IsUdp), "once");
        }

        [TestMethod]
        public async Task ToldOfAsHostCandidatesOfALiteAgent()
        {
            var lan = LanAddress();
            using var agent = new IceAgent(Options(lan, lite: true));

            var candidates = await agent.GatherCandidatesAsync();

            var host = candidates.Single(c => c.Address == lan.ToString());
            var mapped = candidates.Single(c => c.Address == PublicV4.ToString());
            Assert.AreEqual(IceCandidateType.Host, mapped.Type, "a lite agent's candidates are host candidates alone (RFC 8445 2.5)");
            Assert.IsNull(mapped.RelatedAddress);
            Assert.AreEqual(host.Port, mapped.Port);
            Assert.IsTrue(mapped.Priority < host.Priority, "below its socket's own, of no two of one priority");
            Assert.AreNotEqual(host.Foundation, mapped.Foundation);
        }

        [TestMethod]
        public async Task NothingOfAnAddressOfTheHostsOwn()
        {
            var lan = LanAddress();
            var options = Options(lan);
            options.PublicAddresses = new[] { lan };
            using var agent = new IceAgent(options);

            var candidates = await agent.GatherCandidatesAsync();

            Assert.AreEqual(1, candidates.Count(c => c.Address == lan.ToString()), "the host candidate alone: of no NAT, nothing to tell of");
            Assert.IsFalse(candidates.Any(c => c.Type == IceCandidateType.ServerReflexive));
        }

        [TestMethod]
        public async Task NothingOfTheLoopback()
        {
            using var agent = new IceAgent(new IceAgentOptions
            {
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                PublicAddresses = { PublicV4 },
            });

            var candidates = await agent.GatherCandidatesAsync();

            Assert.IsFalse(candidates.Any(c => c.Address == PublicV4.ToString()), "the loopback is of no NAT");
        }
    }
}
