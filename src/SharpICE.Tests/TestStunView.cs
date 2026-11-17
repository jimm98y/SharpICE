using SharpSTUN;
using System;
using System.Net;
using System.Text;

namespace SharpICE.Tests
{
    /// <summary>
    /// StunView and StunWriter, which ICE reads its binding requests and responses of and writes its own with: the same as
    /// StunMessage reads and writes them, of no allocation.
    /// </summary>
    [TestClass]
    public class TestStunView
    {
        private const string Password = "VOkJxbRl1RmTxUk/WvJxBt";

        private static byte[] Hex(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            return bytes;
        }

        // RFC 5769 2.1, Sample Request
        private static readonly byte[] SampleRequest = Hex(
            "000100582112a442b7e7a701bc34d686fa87dfae" +
            "802200105354554e207465737420636c69656e74" +
            "002400046e0001ff" +
            "80290008932ff9b151263b36" +
            "000600096576746a3a68367659202020" +
            "000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2" +
            "80280004e57a3bcf");

        [TestMethod]
        public void ReadsTheSampleRequestAsStunMessageDoes()
        {
            Assert.IsTrue(StunView.TryParse(SampleRequest, out var view));
            var message = StunMessage.Parse(SampleRequest, 0, SampleRequest.Length);
            byte[] key = StunMessage.ShortTermKey(Password);

            Assert.AreEqual(message.Method, view.Method);
            Assert.AreEqual(message.Class, view.Class);
            CollectionAssert.AreEqual(message.TransactionId, view.TransactionId.ToArray());
            Assert.IsTrue(view.VerifyFingerprint());
            Assert.IsTrue(view.VerifyIntegrity(key));
            Assert.IsFalse(view.VerifyIntegrity(StunMessage.ShortTermKey("wrong")));
            Assert.IsTrue(view.UsernameStartsWith(Encoding.UTF8.GetBytes("evtj:")));
            Assert.IsFalse(view.UsernameStartsWith(Encoding.UTF8.GetBytes("h6vY:")));
            Assert.AreEqual(message.Priority, view.GetUInt32(StunAttributeType.Priority));
            Assert.AreEqual(message.IceControlled, view.GetUInt64(StunAttributeType.IceControlled));
            Assert.AreEqual(message.IceControlling, view.GetUInt64(StunAttributeType.IceControlling));
            Assert.IsFalse(view.HasUnknownComprehensionRequired());

            // a byte of the message changed: neither its fingerprint nor its integrity holds
            byte[] tampered = (byte[])SampleRequest.Clone();
            tampered[30] ^= 1;
            Assert.IsTrue(StunView.TryParse(tampered, out var bad));
            Assert.IsFalse(bad.VerifyFingerprint());
            Assert.IsFalse(bad.VerifyIntegrity(key));
        }

        [TestMethod]
        public void WritesABindingResponseAsToBytesDoes()
        {
            byte[] key = StunMessage.ShortTermKey(Password);
            byte[] transactionId = StunMessage.NewTransactionId();
            byte[] software = Encoding.UTF8.GetBytes("SharpICE");
            foreach (var from in new[] { new IPEndPoint(IPAddress.Parse("192.0.2.1"), 32853), new IPEndPoint(IPAddress.Parse("2001:db8::1"), 32853) })
            {
                var message = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, transactionId);
                message.AddXorAddress(from);
                message.AddString(StunAttributeType.Software, "SharpICE");
                byte[] expected = message.ToBytes(key);

                byte[] buffer = new byte[256];
                int position = StunMessage.HeaderLength;
                position += StunWriter.WriteXorAddress(buffer.AsSpan(position), StunAttributeType.XorMappedAddress, from, transactionId);
                position += StunWriter.WriteBytesAttribute(buffer.AsSpan(position), StunAttributeType.Software, software);
                StunWriter.WriteHeader(buffer, StunMethod.Binding, StunMessageClass.SuccessResponse, position - StunMessage.HeaderLength, transactionId);
                int length = StunWriter.WriteIntegrityAndFingerprint(buffer, position, key);

                CollectionAssert.AreEqual(expected, buffer.AsSpan(0, length).ToArray(), from.ToString());
            }
        }

#if NET
        [TestMethod]
        public void ReadingAndVerifyingAllocatesNothing()
        {
            byte[] key = StunMessage.ShortTermKey(Password);
            byte[] prefix = Encoding.UTF8.GetBytes("evtj:");
            int verified = 0;
            long Run(int count)
            {
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int i = 0; i < count; i++)
                {
                    if (StunView.TryParse(SampleRequest, out var view) && view.VerifyFingerprint() && view.VerifyIntegrity(key)
                        && view.UsernameStartsWith(prefix) && view.GetUInt64(StunAttributeType.IceControlled) != null)
                        verified++;
                }
                return GC.GetAllocatedBytesForCurrentThread() - before;
            }
            Run(100);
            verified = 0;
            long allocated = Run(1000);
            Assert.AreEqual(1000, verified);
            Assert.AreEqual(0L, allocated);
        }
#endif
    }
}
