using SharpSTUN;
using SharpTURN;
using System;
using System.Linq;
using System.Net;

namespace SharpICE.Tests
{
    /// <summary>
    /// The test vectors of RFC 5769 - Test Vectors for Session Traversal Utilities for NAT (STUN): each read, of its attributes,
    /// its MESSAGE-INTEGRITY and FINGERPRINT checked; and messages written, read back and checked alike.
    /// </summary>
    [TestClass]
    public class TestRFC5769
    {
        private const string Password = "VOkJxbRl1RmTxUk/WvJxBt";

        private static byte[] Hex(string hex)
        {
            hex = hex.Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            return bytes;
        }

        private static byte[] Take(byte[] bytes, int count) => bytes.Take(count).ToArray();

        // 2.1. Sample Request
        private static readonly byte[] SampleRequest = Hex(
            "00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae" +
            "80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74" +
            "00 24 00 04 6e 00 01 ff" +
            "80 29 00 08 93 2f f9 b1 51 26 3b 36" +
            "00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20" +
            "00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2" +
            "80 28 00 04 e5 7a 3b cf");

        // 2.2. Sample IPv4 Response
        private static readonly byte[] SampleIPv4Response = Hex(
            "01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae" +
            "80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20" +
            "00 20 00 08 00 01 a1 47 e1 12 a6 43" +
            "00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7" +
            "80 28 00 04 c0 7d 4c 96");

        // 2.3. Sample IPv6 Response
        private static readonly byte[] SampleIPv6Response = Hex(
            "01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae" +
            "80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20" +
            "00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9" +
            "00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41" +
            "80 28 00 04 c8 fb 0b 4c");

        [TestMethod]
        public void ReadsTheSampleRequest()
        {
            Assert.IsTrue(StunMessage.IsStun(SampleRequest));
            var message = StunMessage.Parse(SampleRequest, 0, SampleRequest.Length);

            Assert.AreEqual(StunMethod.Binding, message.Method);
            Assert.AreEqual(StunMessageClass.Request, message.Class);
            Assert.AreEqual("STUN test client", message.GetString(StunAttributeType.Software));
            Assert.AreEqual(0x6e0001ffu, message.Priority);
            Assert.AreEqual(0x932ff9b151263b36UL, message.IceControlled);
            Assert.AreEqual("evtj:h6vY", message.Username);
            Assert.IsTrue(message.VerifyFingerprint());
            Assert.IsTrue(message.VerifyIntegrity(StunMessage.ShortTermKey(Password)));
            Assert.IsFalse(message.VerifyIntegrity(StunMessage.ShortTermKey("wrong")));
        }

        [TestMethod]
        public void ReadsTheSampleIPv4Response()
        {
            var message = StunMessage.Parse(SampleIPv4Response, 0, SampleIPv4Response.Length);

            Assert.AreEqual(StunMessageClass.SuccessResponse, message.Class);
            Assert.AreEqual("test vector", message.GetString(StunAttributeType.Software));
            Assert.AreEqual(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 32853), message.GetXorAddress());
            Assert.IsTrue(message.VerifyFingerprint());
            Assert.IsTrue(message.VerifyIntegrity(StunMessage.ShortTermKey(Password)));
        }

        [TestMethod]
        public void ReadsTheSampleIPv6Response()
        {
            var message = StunMessage.Parse(SampleIPv6Response, 0, SampleIPv6Response.Length);

            Assert.AreEqual(new IPEndPoint(IPAddress.Parse("2001:db8:1234:5678:11:2233:4455:6677"), 32853), message.GetXorAddress());
            Assert.IsTrue(message.VerifyFingerprint());
            Assert.IsTrue(message.VerifyIntegrity(StunMessage.ShortTermKey(Password)));
        }

        [TestMethod]
        public void DetectsATamperedMessage()
        {
            byte[] tampered = (byte[])SampleRequest.Clone();
            tampered[30] ^= 1; // in SOFTWARE
            var message = StunMessage.Parse(tampered, 0, tampered.Length);

            Assert.IsFalse(message.VerifyFingerprint());
            Assert.IsFalse(message.VerifyIntegrity(StunMessage.ShortTermKey(Password)));
        }

        [TestMethod]
        public void WritesWhatItReadsBack()
        {
            // the sample request's fields again, of zeros as padding rather than the vector's spaces
            var written = new StunMessage(StunMethod.Binding, StunMessageClass.Request, Hex("b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"))
                .AddString(StunAttributeType.Software, "STUN test client")
                .AddUInt32(StunAttributeType.Priority, 0x6e0001ff)
                .AddUInt64(StunAttributeType.IceControlled, 0x932ff9b151263b36)
                .AddString(StunAttributeType.Username, "evtj:h6vY")
                .ToBytes(StunMessage.ShortTermKey(Password));

            Assert.AreEqual(SampleRequest.Length, written.Length);
            var read = StunMessage.Parse(written, 0, written.Length);
            Assert.IsTrue(read.VerifyFingerprint());
            Assert.IsTrue(read.VerifyIntegrity(StunMessage.ShortTermKey(Password)));
            Assert.AreEqual("evtj:h6vY", read.Username);

            // what differs of the vector is the padding of USERNAME alone
            CollectionAssert.AreEqual(Take(SampleRequest, 73), Take(written, 73));
        }

        [TestMethod]
        public void WritesTheXorMappedAddressOfTheVectors()
        {
            var response = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, Hex("b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"))
                .AddXorAddress(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 32853));
            CollectionAssert.AreEqual(Hex("00 01 a1 47 e1 12 a6 43"), response.GetAttribute(StunAttributeType.XorMappedAddress).Value);

            response = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, Hex("b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"))
                .AddXorAddress(new IPEndPoint(IPAddress.Parse("2001:db8:1234:5678:11:2233:4455:6677"), 32853));
            CollectionAssert.AreEqual(Hex("00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9"), response.GetAttribute(StunAttributeType.XorMappedAddress).Value);
        }

        [TestMethod]
        public void EncodesTheMessageTypes()
        {
            Assert.AreEqual(0x0001, StunMessage.GetMessageType(StunMethod.Binding, StunMessageClass.Request));
            Assert.AreEqual(0x0011, StunMessage.GetMessageType(StunMethod.Binding, StunMessageClass.Indication));
            Assert.AreEqual(0x0101, StunMessage.GetMessageType(StunMethod.Binding, StunMessageClass.SuccessResponse));
            Assert.AreEqual(0x0111, StunMessage.GetMessageType(StunMethod.Binding, StunMessageClass.ErrorResponse));
            Assert.AreEqual(0x0003, StunMessage.GetMessageType(TurnMethod.Allocate, StunMessageClass.Request));
            Assert.AreEqual(0x0113, StunMessage.GetMessageType(TurnMethod.Allocate, StunMessageClass.ErrorResponse));
            Assert.AreEqual(0x0016, StunMessage.GetMessageType(TurnMethod.Send, StunMessageClass.Indication));
        }

        [TestMethod]
        public void TellsStunFromWhatSharesItsSocket()
        {
            Assert.IsFalse(StunMessage.IsStun(Hex("16 fe fd 00 00 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00"))); // DTLS
            Assert.IsFalse(StunMessage.IsStun(Hex("80 60 00 01 00 00 00 00 12 34 56 78 00 00 00 00 00 00 00 00"))); // RTP
            Assert.IsFalse(StunMessage.IsStun(Take(SampleRequest, SampleRequest.Length - 4)));
        }
    }
}
