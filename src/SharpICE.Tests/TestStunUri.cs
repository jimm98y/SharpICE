using SharpStunClient;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SharpICE.Tests
{
    /// <summary>
    /// STUN and TURN URIs (RFC 7064, RFC 7065) and the DNS SRV records (RFC 2782) a host name of no port is looked up of: a
    /// query, an answer of compressed names, and the order of the records.
    /// </summary>
    [TestClass]
    public class TestStunUri
    {
        [TestMethod]
        [DataRow("stun:stun.example.org", "stun", "stun.example.org", null, "udp", 3478)]
        [DataRow("stun:stun.example.org:19302", "stun", "stun.example.org", 19302, "udp", 19302)]
        [DataRow("STUNS:stun.example.org", "stuns", "stun.example.org", null, "tcp", 5349)]
        [DataRow("stun.example.org:3479", "stun", "stun.example.org", 3479, "udp", 3479)]
        [DataRow("192.0.2.1", "stun", "192.0.2.1", null, "udp", 3478)]
        [DataRow("stun:[2001:db8::1]:3478", "stun", "2001:db8::1", 3478, "udp", 3478)]
        [DataRow("turn:turn.example.org?transport=tcp", "turn", "turn.example.org", null, "tcp", 3478)]
        [DataRow("turns:turn.example.org:443?transport=tcp", "turns", "turn.example.org", 443, "tcp", 443)]
        public void ParsesAUri(string text, string scheme, string host, int? port, string transport, int effectivePort)
        {
            var uri = StunUri.Parse(text);

            Assert.AreEqual(scheme, uri.Scheme);
            Assert.AreEqual(host, uri.Host);
            Assert.AreEqual(port, uri.Port);
            Assert.AreEqual(transport, uri.TransportProtocol);
            Assert.AreEqual(effectivePort, uri.EffectivePort);
        }

        [TestMethod]
        [DataRow("")]
        [DataRow("stun:")]
        [DataRow("stun:host:0")]
        [DataRow("stun:host:port")]
        [DataRow("stun:2001:db8::1")]
        [DataRow("stun:host?transport=tcp")]
        [DataRow("turn:host?transport=sctp")]
        [DataRow("stun:[2001:db8::1")]
        public void RefusesWhatIsNoUri(string text)
        {
            Assert.IsFalse(StunUri.TryParse(text, out _));
            Assert.ThrowsExactly<FormatException>(() => StunUri.Parse(text));
        }

        [TestMethod]
        public void WritesAUriBack()
        {
            Assert.AreEqual("stun:[2001:db8::1]:3478", StunUri.Parse("stun:[2001:db8::1]:3478").ToString());
            Assert.AreEqual("turns:turn.example.org?transport=tcp", StunUri.Parse("turns:turn.example.org?transport=tcp").ToString());
        }

        private static byte[] Hex(string hex)
        {
            hex = hex.Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            return bytes;
        }

        [TestMethod]
        public void WritesAnSrvQuery()
        {
            CollectionAssert.AreEqual(
                Hex("12 34 01 00 00 01 00 00 00 00 00 00 05 5f 73 74 75 6e 04 5f 75 64 70 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 00 21 00 01"),
                DnsSrv.BuildQuery(0x1234, "_stun._udp.example.org"));
        }

        [TestMethod]
        public void ReadsAnSrvAnswerOfCompressedNames()
        {
            byte[] answer = Hex(
                // ID, a response of recursion, 1 question, 2 answers
                "12 34 81 80 00 01 00 02 00 00 00 00" +
                // the question: _stun._udp.example.org SRV IN, at 12
                "05 5f 73 74 75 6e 04 5f 75 64 70 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 00 21 00 01" +
                // a pointer to the question's name, SRV IN, TTL 300, 10 bytes: 10 60 3478 a.example.org (a, then a pointer to example.org at 23)
                "c0 0c 00 21 00 01 00 00 01 2c 00 0a 00 0a 00 3c 0d 96 01 61 c0 17" +
                // the same name: 20 0 3479 b.example.org
                "c0 0c 00 21 00 01 00 00 01 2c 00 0a 00 14 00 00 0d 97 01 62 c0 17");
            var records = DnsSrv.ParseResponse(answer, answer.Length, 0x1234);

            Assert.AreEqual(2, records.Count);
            Assert.AreEqual("10 60 3478 a.example.org", records[0].ToString());
            Assert.AreEqual("20 0 3479 b.example.org", records[1].ToString());

            Assert.IsNull(DnsSrv.ParseResponse(answer, answer.Length, 0x4321), "of another query");
            Assert.IsNull(DnsSrv.ParseResponse(answer, 40, 0x1234), "cut short");

            byte[] nxdomain = Hex("12 34 81 83 00 01 00 00 00 00 00 00");
            Assert.AreEqual(0, DnsSrv.ParseResponse(nxdomain, nxdomain.Length, 0x1234).Count);

            // "." alone: no service there
            byte[] none = Hex("12 34 81 80 00 00 00 01 00 00 00 00 01 61 00 00 21 00 01 00 00 01 2c 00 07 00 00 00 00 00 00 00");
            Assert.AreEqual(0, DnsSrv.ParseResponse(none, none.Length, 0x1234).Count);

            // a pointer to itself
            byte[] loop = Hex("12 34 81 80 00 01 00 00 00 00 00 00 c0 0c 00 21 00 01");
            Assert.IsNull(DnsSrv.ParseResponse(loop, loop.Length, 0x1234));
        }

        [TestMethod]
        public void OrdersTheRecordsOfTheirPrioritiesAndWeights()
        {
            var records = new List<DnsSrvRecord>
            {
                new DnsSrvRecord { Priority = 20, Weight = 0, Port = 4, Target = "d" },
                new DnsSrvRecord { Priority = 10, Weight = 90, Port = 1, Target = "a" },
                new DnsSrvRecord { Priority = 10, Weight = 10, Port = 2, Target = "b" },
                new DnsSrvRecord { Priority = 10, Weight = 0, Port = 3, Target = "c" },
            };

            int aFirst = 0;
            var random = new Random(1);
            for (int i = 0; i < 1000; i++)
            {
                var ordered = DnsSrv.Order(records, random);
                CollectionAssert.AreEquivalent(new[] { "a", "b", "c" }, ordered.Take(3).Select(r => r.Target).ToArray(), "priority 10 first");
                Assert.AreEqual("d", ordered[3].Target);
                if (ordered[0].Target == "a")
                    aFirst++;
            }

            // a of weight 90 of 100: first about 9 times of 10
            Assert.IsTrue(aFirst > 850 && aFirst < 950, $"a first {aFirst} times of 1000");
        }
    }
}
