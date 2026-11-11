using SharpStun;
using SharpTurn;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace SharpICE.Tests
{
    /// <summary>
    /// Long-term credentials of RFC 8489: the vectors of RFC 5769 2.4 - MESSAGE-INTEGRITY of the MD5 key - and of RFC 8489 B.1 -
    /// USERHASH and MESSAGE-INTEGRITY-SHA256 - read and written byte for byte; and the attributes of the mechanism.
    /// </summary>
    [TestClass]
    public class TestRFC8489
    {
        private const string Username = "マトリックス";
        private const string Realm = "example.org";

        // what OpaqueString makes of "The<U+00AD>M<U+00AA>tr<U+2168>" by the vectors: SASLprep's, rather than OpaqueString's
        // NFC, which leaves it as it is
        private const string Password = "TheMatrIX";

        private static byte[] Hex(string hex)
        {
            hex = hex.Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            return bytes;
        }

        private static readonly byte[] TransactionId = Hex("78 ad 34 33 c6 ad 72 c0 29 da 41 2e");

        // RFC 5769 2.4. Sample Request with Long-Term Authentication
        private static readonly byte[] LongTermRequest = Hex(
            "00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e" +
            "00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00" +
            "00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46 53 54 76 79 36 34 73 41" +
            "00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00" +
            "00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66");

        // RFC 8489 B.1. Sample Request with Long-Term Authentication with MESSAGE-INTEGRITY-SHA256 and USERHASH, as erratum
        // 6268 corrects it: the length of the message without its header, and the PASSWORD-ALGORITHM of the SHA-256 key it is
        // signed of, which the RFC's leaves out
        private static readonly byte[] Sha256Request = Hex(
            "00 01 00 90 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e" +
            "00 1e 00 20 4a 3c f3 8f ef 69 92 bd a9 52 c6 78 04 17 da 0f 24 81 94 15 56 9e 60 b2 05 c4 6e 41 40 7f 17 04" +
            "00 15 00 29 6f 62 4d 61 74 4a 6f 73 32 41 41 41 43 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39" +
            "46 53 54 76 79 36 34 73 41 00 00 00" +
            "00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00" +
            "00 1d 00 04 00 02 00 00" +
            "00 1c 00 20 b5 c7 bf 00 5b 6c 52 a2 1c 51 c5 e8 92 f8 19 24 13 62 96 cb 92 7c 43 14 93 09 27 8c c6 51 8e 65");

        [TestMethod]
        public void ReadsTheLongTermRequestOfRFC5769()
        {
            var message = StunMessage.Parse(LongTermRequest, 0, LongTermRequest.Length);

            Assert.AreEqual(Username, message.Username);
            Assert.AreEqual("f//499k954d6OL34oL9FSTvy64sA", message.Nonce);
            Assert.AreEqual(Realm, message.Realm);
            Assert.IsTrue(message.VerifyIntegrity(StunCredentials.LongTermKey(Username, Realm, Password)));
            Assert.IsTrue(message.VerifyAnyIntegrity(StunCredentials.LongTermKey(Username, Realm, Password)));
            Assert.IsFalse(message.VerifyIntegrity(StunCredentials.LongTermKey(Username, Realm, "TheMatrix")));
            Assert.IsNull(StunCredentials.GetSecurityFeatures(message.Nonce), "no nonce cookie");
        }

        [TestMethod]
        public void WritesTheLongTermRequestOfRFC5769()
        {
            var written = new StunMessage(StunMethod.Binding, StunMessageClass.Request, TransactionId)
                .AddString(StunAttributeType.Username, Username)
                .AddString(StunAttributeType.Nonce, "f//499k954d6OL34oL9FSTvy64sA")
                .AddString(StunAttributeType.Realm, Realm)
                .ToBytes(StunCredentials.LongTermKey(Username, Realm, Password), false);

            CollectionAssert.AreEqual(LongTermRequest, written);
        }

        [TestMethod]
        public void ReadsTheSha256RequestOfRFC8489()
        {
            var message = StunMessage.Parse(Sha256Request, 0, Sha256Request.Length);

            CollectionAssert.AreEqual(StunCredentials.UserHash(Username, Realm), message.GetAttribute(StunAttributeType.Userhash).Value);
            Assert.AreEqual(Realm, message.Realm);
            Assert.IsFalse(message.HasIntegrity);
            Assert.IsTrue(message.HasIntegritySha256);

            Assert.AreEqual((ushort)StunPasswordAlgorithm.Sha256, message.PasswordAlgorithm);
            Assert.IsTrue(message.VerifyIntegritySha256(StunCredentials.LongTermKey(Username, Realm, Password, StunPasswordAlgorithm.Sha256)));
            Assert.IsTrue(message.VerifyAnyIntegrity(StunCredentials.LongTermKey(Username, Realm, Password, StunPasswordAlgorithm.Sha256)));
            Assert.IsFalse(message.VerifyIntegritySha256(StunCredentials.LongTermKey(Username, Realm, Password)));
        }

        [TestMethod]
        public void WritesTheSha256RequestOfRFC8489()
        {
            var written = new StunMessage(StunMethod.Binding, StunMessageClass.Request, TransactionId)
                .AddAttribute(StunAttributeType.Userhash, StunCredentials.UserHash(Username, Realm))
                .AddString(StunAttributeType.Nonce, "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA")
                .AddString(StunAttributeType.Realm, Realm)
                .AddPasswordAlgorithm(StunPasswordAlgorithm.Sha256)
                .ToBytes(StunCredentials.LongTermKey(Username, Realm, Password, StunPasswordAlgorithm.Sha256), StunIntegrity.Sha256, false);

            CollectionAssert.AreEqual(Sha256Request, written);
        }

        [TestMethod]
        public void MakesTheKeyOfTheExampleOfRFC8489()
        {
            // 9.2.2: MD5("user:realm:pass")
            CollectionAssert.AreEqual(Hex("8493fbc53ba582fb4c044c456bdc40eb"), StunCredentials.LongTermKey("user", "realm", "pass"));
            Assert.AreEqual(32, StunCredentials.LongTermKey("user", "realm", "pass", StunPasswordAlgorithm.Sha256).Length);
        }

        [TestMethod]
        public void PreparesStringsOfOpaqueString()
        {
            Assert.AreEqual("a b", StunCredentials.OpaqueString("a b"), "a space of Unicode, a plain one");
            Assert.AreEqual("é", StunCredentials.OpaqueString("é"), "NFC");
            Assert.AreEqual("The­MªtrⅨ", StunCredentials.OpaqueString("The­MªtrⅨ"), "no NFKC, no mapping to nothing");
            Assert.ThrowsExactly<ArgumentException>(() => StunCredentials.OpaqueString(""));
            Assert.ThrowsExactly<ArgumentException>(() => StunCredentials.OpaqueString("a\tb"));
        }

        [TestMethod]
        public void ReadsTheSecurityFeaturesOfANonce()
        {
            Assert.AreEqual(StunSecurityFeatures.None, StunCredentials.GetSecurityFeatures("obMatJos2AAAAxyz"));
            Assert.AreEqual(StunSecurityFeatures.PasswordAlgorithms, StunCredentials.GetSecurityFeatures("obMatJos2gAAAxyz"));
            Assert.AreEqual(StunSecurityFeatures.PasswordAlgorithms | StunSecurityFeatures.UsernameAnonymity, StunCredentials.GetSecurityFeatures("obMatJos2wAAAxyz"));
            Assert.IsNull(StunCredentials.GetSecurityFeatures("obMatJos"));

            string nonce = StunCredentials.CreateNonce(StunSecurityFeatures.UsernameAnonymity, "rest");
            Assert.AreEqual("obMatJos2QAAArest", nonce);
            Assert.AreEqual(StunSecurityFeatures.UsernameAnonymity, StunCredentials.GetSecurityFeatures(nonce));
        }

        [TestMethod]
        public void SignsWithBothIntegritiesAndChecksEach()
        {
            byte[] key = StunCredentials.LongTermKey("user", "realm", "pass");
            byte[] bytes = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, TransactionId)
                .AddXorAddress(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 32853))
                .ToBytes(key, StunIntegrity.Sha1 | StunIntegrity.Sha256);
            var message = StunMessage.Parse(bytes, 0, bytes.Length);

            Assert.IsTrue(message.HasIntegrity && message.HasIntegritySha256 && message.HasFingerprint);
            Assert.IsTrue(message.VerifyIntegrity(key));
            Assert.IsTrue(message.VerifyIntegritySha256(key));
            Assert.IsTrue(message.VerifyFingerprint());
            Assert.IsFalse(message.VerifyIntegritySha256(StunCredentials.LongTermKey("user", "realm", "other")));
        }

        [TestMethod]
        public void IgnoresWhatFollowsTheIntegrityAndReadsATruncatedOne()
        {
            byte[] key = StunCredentials.LongTermKey("user", "realm", "pass");
            byte[] signed = new StunMessage(StunMethod.Binding, StunMessageClass.Request, TransactionId)
                .AddString(StunAttributeType.Software, "x")
                .ToBytes(key, StunIntegrity.Sha256, false);

            // SOFTWARE after MESSAGE-INTEGRITY-SHA256: ignored, though the header's length is of it
            byte[] extended = signed.Concat(Hex("80 22 00 04 79 79 79 79")).ToArray();
            extended[3] = (byte)(extended.Length - StunMessage.HeaderLength);
            var message = StunMessage.Parse(extended, 0, extended.Length);
            Assert.AreEqual("x", message.GetString(StunAttributeType.Software));
            Assert.IsTrue(message.VerifyIntegritySha256(key));

            // a MESSAGE-INTEGRITY-SHA256 of its first 16 bytes, as a usage that truncates it has it: of the HMAC of the message
            // whose length is to the end of the 16 bytes
            byte[] unsigned = signed.Take(signed.Length - 36).ToArray();
            unsigned[3] = (byte)(unsigned.Length - StunMessage.HeaderLength + 4 + 16);
            byte[] hmac;
            using (var sha256 = new System.Security.Cryptography.HMACSHA256(key))
                hmac = sha256.ComputeHash(unsigned);
            byte[] truncated = unsigned.Concat(Hex("00 1c 00 10")).Concat(hmac.Take(16)).ToArray();
            message = StunMessage.Parse(truncated, 0, truncated.Length);
            Assert.IsTrue(message.VerifyIntegritySha256(key), "its first 16 bytes, of the length it says");
            truncated[truncated.Length - 1] ^= 1;
            Assert.IsFalse(StunMessage.Parse(truncated, 0, truncated.Length).VerifyIntegritySha256(key));

            // shorter than 16 bytes: not well formed
            byte[] tooShort = signed.Take(signed.Length - 20).ToArray();
            tooShort[3] = (byte)(tooShort.Length - StunMessage.HeaderLength);
            tooShort[tooShort.Length - 12 - 1] = 12;
            Assert.IsNull(StunMessage.Parse(tooShort, 0, tooShort.Length));
        }

        [TestMethod]
        public void ReadsAndWritesThePasswordAlgorithms()
        {
            var message = new StunMessage(TurnMethod.Allocate, StunMessageClass.ErrorResponse, TransactionId)
                .AddPasswordAlgorithms(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5)
                .AddPasswordAlgorithm(StunPasswordAlgorithm.Sha256);
            CollectionAssert.AreEqual(Hex("00 02 00 00 00 01 00 00"), message.GetAttribute(StunAttributeType.PasswordAlgorithms).Value);

            byte[] bytes = message.ToBytes();
            var read = StunMessage.Parse(bytes, 0, bytes.Length);
            CollectionAssert.AreEqual(new List<ushort> { 2, 1 }, read.PasswordAlgorithms);
            Assert.AreEqual((ushort)2, read.PasswordAlgorithm);

            // an algorithm of parameters, padded: skipped over to the next
            var withParameters = new StunMessage(TurnMethod.Allocate, StunMessageClass.ErrorResponse, TransactionId)
                .AddAttribute(StunAttributeType.PasswordAlgorithms, Hex("00 07 00 03 aa bb cc 00 00 01 00 00"));
            CollectionAssert.AreEqual(new List<ushort> { 7, 1 }, withParameters.PasswordAlgorithms);
        }

        [TestMethod]
        public void ListsTheUnknownComprehensionRequiredAttributes()
        {
            var message = new StunMessage(StunMethod.Binding, StunMessageClass.Request, TransactionId)
                .AddString(StunAttributeType.Username, "a:b")
                .AddAttribute(0x7FFF, new byte[4])
                .AddAttribute(0x7FFF, new byte[4])
                .AddAttribute(0x0031, new byte[0])
                .AddAttribute(0xC001, new byte[4]); // comprehension-optional: no matter

            CollectionAssert.AreEqual(new List<ushort> { 0x7FFF, 0x0031 }, message.GetUnknownComprehensionRequired());
            CollectionAssert.AreEqual(new List<ushort> { 0x7FFF }, message.GetUnknownComprehensionRequired(t => t != 0x7FFF));

            var error = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse, TransactionId)
                .AddError(StunErrorCode.UnknownAttribute, "Unknown Attribute")
                .AddUnknownAttributes(new ushort[] { 0x7FFF, 0x0031 });
            byte[] bytes = error.ToBytes();
            var read = StunMessage.Parse(bytes, 0, bytes.Length);
            CollectionAssert.AreEqual(new List<ushort> { 0x7FFF, 0x0031 }, read.UnknownAttributeTypes);
            Assert.AreEqual(420, read.Error.Value.Code);
        }

        [TestMethod]
        public void ReadsTheAlternateServers()
        {
            var message = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse, TransactionId)
                .AddError(StunErrorCode.TryAlternate, "Try Alternate")
                .AddAddress(new IPEndPoint(IPAddress.Parse("192.0.2.7"), 3478), StunAttributeType.AlternateServer)
                .AddAddress(new IPEndPoint(IPAddress.Parse("2001:db8::7"), 3478), StunAttributeType.AlternateServer)
                .AddString(StunAttributeType.AlternateDomain, "stun.example.org");
            byte[] bytes = message.ToBytes();
            var read = StunMessage.Parse(bytes, 0, bytes.Length);

            CollectionAssert.AreEqual(new[] { new IPEndPoint(IPAddress.Parse("192.0.2.7"), 3478), new IPEndPoint(IPAddress.Parse("2001:db8::7"), 3478) }, read.AlternateServers);
            Assert.AreEqual("stun.example.org", read.AlternateDomain);
            Assert.AreEqual(300, read.Error.Value.Code);
        }
    }
}
