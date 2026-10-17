namespace SharpICE.Tests
{
    /// <summary>Candidates of SDP's "a=candidate" lines (RFC 8839 5.1) and their priorities (RFC 8445 5.1.2).</summary>
    [TestClass]
    public class TestIceCandidate
    {
        [TestMethod]
        public void ReadsAndWritesAHostCandidate()
        {
            var candidate = IceCandidate.Parse("a=candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host generation 0");

            Assert.AreEqual("1", candidate.Foundation);
            Assert.AreEqual(1, candidate.Component);
            Assert.AreEqual(2130706431u, candidate.Priority);
            Assert.AreEqual("192.168.1.10:50000", candidate.EndPoint.ToString());
            Assert.AreEqual(IceCandidateType.Host, candidate.Type);
            Assert.AreEqual("candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host generation 0", candidate.ToString());
        }

        [TestMethod]
        public void ReadsAServerReflexiveCandidate()
        {
            var candidate = IceCandidate.Parse("candidate:842163049 1 UDP 1677729535 203.0.113.7 61234 typ srflx raddr 10.0.0.2 rport 50000");

            Assert.AreEqual(IceCandidateType.ServerReflexive, candidate.Type);
            Assert.IsTrue(candidate.IsUdp);
            Assert.AreEqual("10.0.0.2", candidate.RelatedAddress);
            Assert.AreEqual(50000, candidate.RelatedPort);
            Assert.AreEqual("candidate:842163049 1 UDP 1677729535 203.0.113.7 61234 typ srflx raddr 10.0.0.2 rport 50000", candidate.ToString());
        }

        [TestMethod]
        public void ReadsAndWritesATcpCandidate()
        {
            // as Chrome writes them (RFC 6544 4.5): the type of TCP among the extensions, where SDP has it
            var candidate = IceCandidate.Parse("candidate:1340066476 1 tcp 1518280447 192.168.1.10 9 typ host tcptype active generation 0");

            Assert.IsTrue(candidate.IsTcp);
            Assert.IsFalse(candidate.IsUdp);
            Assert.AreEqual(IceCandidate.TcpActive, candidate.TcpType);
            Assert.AreEqual("candidate:1340066476 1 tcp 1518280447 192.168.1.10 9 typ host tcptype active generation 0", candidate.ToString());

            candidate.TcpType = IceCandidate.TcpPassive;
            Assert.AreEqual("candidate:1340066476 1 tcp 1518280447 192.168.1.10 9 typ host tcptype passive generation 0", candidate.ToString());

            var made = new IceCandidate { Foundation = "t1", Transport = "tcp", Priority = 1, Address = "10.0.0.1", Port = 5000, Type = IceCandidateType.Host };
            made.TcpType = IceCandidate.TcpPassive;
            Assert.AreEqual("candidate:t1 1 tcp 1 10.0.0.1 5000 typ host tcptype passive", made.ToString());
        }

        [TestMethod]
        public void ComputesThePrioritiesOfTcp()
        {
            // RFC 6544 4.2: a local preference of 2^13 times the direction's preference, and the address's
            Assert.AreEqual((6 << 13) + 8191, IceCandidate.TcpLocalPreference(IceCandidate.TcpActive, 8191));
            Assert.AreEqual((4 << 13) + 8191, IceCandidate.TcpLocalPreference(IceCandidate.TcpPassive, 8191));

            // of TCP, below every host and server reflexive candidate of UDP
            uint active = IceCandidate.ComputePriority(IceCandidateType.Host, IceCandidate.TcpLocalPreference(IceCandidate.TcpActive, 8191), 1, true);
            Assert.AreEqual((90u << 24) + (((6u << 13) + 8191) << 8) + 255, active);
            Assert.IsTrue(active < IceCandidate.ComputePriority(IceCandidateType.ServerReflexive, 0, 1));
            Assert.AreEqual((6 << 13) + 8191, IceCandidate.Parse($"candidate:1 1 tcp {active} 10.0.0.1 9 typ host tcptype active").LocalPreference);
        }

        [TestMethod]
        public void LeavesOutWhatIsNoCandidate()
        {
            Assert.IsNull(IceCandidate.Parse("candidate:1 1 udp x 1.2.3.4 5 typ host"));
            Assert.IsNull(IceCandidate.Parse("candidate:1 1 udp 1 1.2.3.4 5 type host"));
            Assert.IsNull(IceCandidate.Parse(""));
        }

        [TestMethod]
        public void ComputesThePriorities()
        {
            // RFC 8445 5.1.2.1: of the type preference, the local preference, the component
            Assert.AreEqual(2130706431u, IceCandidate.ComputePriority(IceCandidateType.Host, 65535, 1));
            Assert.AreEqual(1694498815u, IceCandidate.ComputePriority(IceCandidateType.ServerReflexive, 65535, 1));
            Assert.AreEqual(16777215u, IceCandidate.ComputePriority(IceCandidateType.Relayed, 65535, 1));

            // RFC 8445 6.1.2.3: of the controlling agent's first
            Assert.AreEqual((5UL << 32) + 2 * 7 + 1, IceCandidatePair.ComputePriority(7, 5));
            Assert.AreEqual((5UL << 32) + 2 * 7, IceCandidatePair.ComputePriority(5, 7));
        }
    }
}
