// SharpStunClient
// Copyright (C) 2026 Lukas Volf
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SharpStunClient
{
    /// <summary>
    /// The class of a STUN message (RFC 8489 5): its two bits C1 and C0.
    /// </summary>
    public enum StunMessageClass
    {
        Request = 0,
        Indication = 1,
        SuccessResponse = 2,
        ErrorResponse = 3
    }

    /// <summary>
    /// STUN methods (RFC 8489 18.2; TURN's of RFC 8656 17).
    /// </summary>
    public static class StunMethod
    {
        public const ushort Binding = 0x001;
        public const ushort Allocate = 0x003;
        public const ushort Refresh = 0x004;
        public const ushort Send = 0x006;
        public const ushort Data = 0x007;
        public const ushort CreatePermission = 0x008;
        public const ushort ChannelBind = 0x009;
    }

    /// <summary>
    /// STUN attribute types (RFC 8489 18.3; ICE's of RFC 8445 16.1; TURN's of RFC 8656 18).
    /// </summary>
    public static class StunAttributeType
    {
        public const ushort MappedAddress = 0x0001;
        public const ushort Username = 0x0006;
        public const ushort MessageIntegrity = 0x0008;
        public const ushort ErrorCode = 0x0009;
        public const ushort UnknownAttributes = 0x000A;
        public const ushort ChannelNumber = 0x000C;
        public const ushort Lifetime = 0x000D;
        public const ushort XorPeerAddress = 0x0012;
        public const ushort Data = 0x0013;
        public const ushort Realm = 0x0014;
        public const ushort Nonce = 0x0015;
        public const ushort XorRelayedAddress = 0x0016;
        public const ushort RequestedTransport = 0x0019;
        public const ushort MessageIntegritySha256 = 0x001C;
        public const ushort XorMappedAddress = 0x0020;
        public const ushort Priority = 0x0024;
        public const ushort UseCandidate = 0x0025;
        public const ushort Software = 0x8022;
        public const ushort AlternateServer = 0x8023;
        public const ushort Fingerprint = 0x8028;
        public const ushort IceControlled = 0x8029;
        public const ushort IceControlling = 0x802A;
    }

    /// <summary>
    /// STUN error codes (RFC 8489 14.8, RFC 8445 7.3.1.1).
    /// </summary>
    public static class StunErrorCode
    {
        public const int BadRequest = 400;
        public const int Unauthorized = 401;
        public const int UnknownAttribute = 420;
        public const int StaleNonce = 438;
        public const int RoleConflict = 487;
        public const int ServerError = 500;
    }

    /// <summary>
    /// An attribute of a STUN message: its type, and its value as it is, without the padding to 4 bytes after it.
    /// </summary>
    public sealed class StunAttribute
    {
        public ushort Type { get; }
        public byte[] Value { get; }

        public StunAttribute(ushort type, byte[] value)
        {
            Type = type;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Whether a server that does not know the attribute must reject the message (RFC 8489 14): the types up to 0x7FFF.
        /// </summary>
        public bool IsComprehensionRequired => Type < 0x8000;

        public override string ToString() => $"0x{Type:X4} ({Value.Length} bytes)";
    }

    /// <summary>
    /// A STUN message (RFC 8489 5): its method and class, its transaction ID, and its attributes. Read, it keeps the bytes it
    /// was read of, which its MESSAGE-INTEGRITY and FINGERPRINT are checked against; written, they are added last, as their
    /// keys say.
    /// </summary>
    public sealed class StunMessage
    {
        public const int HeaderLength = 20;
        public const uint MagicCookie = 0x2112A442;
        public const int TransactionIdLength = 12;

        // RFC 8489 14.7: the CRC-32 of the message, XOR-ed with this
        private const uint FingerprintXor = 0x5354554E;
        private const int IntegrityLength = 20;

        private byte[] _raw;
        private int _integrityOffset = -1;
        private int _fingerprintOffset = -1;

        public ushort Method { get; set; }
        public StunMessageClass Class { get; set; }
        public byte[] TransactionId { get; set; }
        public List<StunAttribute> Attributes { get; } = new List<StunAttribute>();

        public StunMessage(ushort method, StunMessageClass messageClass, byte[] transactionId = null)
        {
            Method = method;
            Class = messageClass;
            TransactionId = transactionId ?? NewTransactionId();
            if (TransactionId.Length != TransactionIdLength)
                throw new ArgumentException($"A transaction ID is of {TransactionIdLength} bytes.", nameof(transactionId));
        }

        public static byte[] NewTransactionId()
        {
            byte[] id = new byte[TransactionIdLength];
            using (var random = RandomNumberGenerator.Create())
                random.GetBytes(id);
            return id;
        }

        /// <summary>The message's type, of its method and class interleaved as RFC 8489 5 lays them out.</summary>
        public static ushort GetMessageType(ushort method, StunMessageClass messageClass)
        {
            int c = (int)messageClass;
            return (ushort)((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | ((c & 1) << 4) | ((c & 2) << 7));
        }

        private static ushort MethodOf(ushort type) => (ushort)((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));

        private static StunMessageClass ClassOf(ushort type) => (StunMessageClass)(((type >> 4) & 1) | ((type >> 7) & 2));

        /// <summary>
        /// Whether a datagram is a STUN message: its first two bits 0, the magic cookie, and a length that is a multiple of 4 and
        /// what follows the header. Of the packets that share an ICE socket - DTLS, RTP and RTCP - the first byte is 0 to 3 of
        /// STUN alone (RFC 7983).
        /// </summary>
        public static bool IsStun(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < HeaderLength || (datagram[0] & 0xC0) != 0)
                return false;
            if (BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4)) != MagicCookie)
                return false;
            int length = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2));
            return (length & 3) == 0 && length + HeaderLength == datagram.Length;
        }

        /// <summary>A STUN message of a datagram; null of one that is not, or that is not well formed.</summary>
        public static StunMessage Parse(byte[] buffer, int offset, int count)
        {
            var datagram = new ReadOnlySpan<byte>(buffer, offset, count);
            if (!IsStun(datagram))
                return null;

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(datagram);
            var message = new StunMessage(MethodOf(type), ClassOf(type), datagram.Slice(8, TransactionIdLength).ToArray());
            message._raw = datagram.ToArray();

            int position = HeaderLength;
            while (position + 4 <= count)
            {
                ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(position));
                int length = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(position + 2));
                if (position + 4 + length > count)
                    return null;

                // what follows MESSAGE-INTEGRITY is FINGERPRINT alone, and nothing FINGERPRINT (RFC 8489 14.5, 14.7)
                if (message._fingerprintOffset >= 0)
                    return null;
                if (attributeType == StunAttributeType.MessageIntegrity)
                {
                    if (length != IntegrityLength)
                        return null;
                    message._integrityOffset = position;
                }
                else if (attributeType == StunAttributeType.Fingerprint)
                {
                    if (length != 4)
                        return null;
                    message._fingerprintOffset = position;
                }
                else if (message._integrityOffset >= 0)
                {
                    // after the integrity, of no integrity itself: left out, as RFC 8489 14.5 says to ignore it
                    position += 4 + ((length + 3) & ~3);
                    continue;
                }

                message.Attributes.Add(new StunAttribute(attributeType, datagram.Slice(position + 4, length).ToArray()));
                position += 4 + ((length + 3) & ~3);
            }
            return position == count ? message : null;
        }

        public bool HasIntegrity => _integrityOffset >= 0;

        public bool HasFingerprint => _fingerprintOffset >= 0;

        /// <summary>
        /// Whether its FINGERPRINT is the CRC-32 of the message before it (RFC 8489 14.7); false of a message that was not read,
        /// or has none.
        /// </summary>
        public bool VerifyFingerprint()
        {
            if (_raw == null || _fingerprintOffset < 0)
                return false;
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(_raw.AsSpan(_fingerprintOffset + 4));
            return (Crc32.Compute(_raw, 0, _fingerprintOffset) ^ FingerprintXor) == expected;
        }

        /// <summary>
        /// Whether its MESSAGE-INTEGRITY is the HMAC-SHA1 of the message before it, of the key given (RFC 8489 14.5): of the
        /// short-term credentials ICE uses, the password's UTF-8 bytes. Its header's length is of the message to the end of the
        /// integrity, whatever comes after it.
        /// </summary>
        public bool VerifyIntegrity(byte[] key)
        {
            if (_raw == null || _integrityOffset < 0 || key == null)
                return false;
            byte[] signed = new byte[_integrityOffset];
            Buffer.BlockCopy(_raw, 0, signed, 0, _integrityOffset);
            BinaryPrimitives.WriteUInt16BigEndian(signed.AsSpan(2), (ushort)(_integrityOffset - HeaderLength + 4 + IntegrityLength));
            byte[] hmac;
            using (var sha1 = new HMACSHA1(key))
                hmac = sha1.ComputeHash(signed);
            return FixedTimeEquals(hmac, _raw.AsSpan(_integrityOffset + 4, IntegrityLength));
        }

        private static bool FixedTimeEquals(byte[] a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
                return false;
            int difference = 0;
            for (int i = 0; i < a.Length; i++)
                difference |= a[i] ^ b[i];
            return difference == 0;
        }

        /// <summary>The key of short-term credentials (RFC 8489 9.1.1): the password's UTF-8 bytes.</summary>
        public static byte[] ShortTermKey(string password) => Encoding.UTF8.GetBytes(password ?? "");

        /// <summary>
        /// The message's bytes: its header, its attributes each padded to 4 bytes, then - of a key given - its MESSAGE-INTEGRITY,
        /// and its FINGERPRINT, if it is to have one.
        /// </summary>
        public byte[] ToBytes(byte[] integrityKey = null, bool fingerprint = true)
        {
            int length = 0;
            foreach (var attribute in Attributes)
                length += 4 + ((attribute.Value.Length + 3) & ~3);
            int integrityAt = HeaderLength + length;
            if (integrityKey != null)
                length += 4 + IntegrityLength;
            int fingerprintAt = HeaderLength + length;
            if (fingerprint)
                length += 8;

            byte[] bytes = new byte[HeaderLength + length];
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(0), GetMessageType(Method, Class));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), MagicCookie);
            Buffer.BlockCopy(TransactionId, 0, bytes, 8, TransactionIdLength);

            int position = HeaderLength;
            foreach (var attribute in Attributes)
            {
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(position), attribute.Type);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(position + 2), (ushort)attribute.Value.Length);
                Buffer.BlockCopy(attribute.Value, 0, bytes, position + 4, attribute.Value.Length);
                position += 4 + ((attribute.Value.Length + 3) & ~3);
            }

            if (integrityKey != null)
            {
                // the length of the message to the end of the integrity, as it is signed
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)(integrityAt - HeaderLength + 4 + IntegrityLength));
                byte[] hmac;
                using (var sha1 = new HMACSHA1(integrityKey))
                    hmac = sha1.ComputeHash(bytes, 0, integrityAt);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(integrityAt), StunAttributeType.MessageIntegrity);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(integrityAt + 2), IntegrityLength);
                Buffer.BlockCopy(hmac, 0, bytes, integrityAt + 4, IntegrityLength);
            }

            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)length);
            if (fingerprint)
            {
                uint crc = Crc32.Compute(bytes, 0, fingerprintAt) ^ FingerprintXor;
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(fingerprintAt), StunAttributeType.Fingerprint);
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(fingerprintAt + 2), 4);
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(fingerprintAt + 4), crc);
            }
            return bytes;
        }

        #region Attributes

        public StunAttribute GetAttribute(ushort type)
        {
            foreach (var attribute in Attributes)
            {
                if (attribute.Type == type)
                    return attribute;
            }
            return null;
        }

        public bool HasAttribute(ushort type) => GetAttribute(type) != null;

        public StunMessage AddAttribute(ushort type, byte[] value)
        {
            Attributes.Add(new StunAttribute(type, value));
            return this;
        }

        public string GetString(ushort type)
        {
            var attribute = GetAttribute(type);
            return attribute == null ? null : Encoding.UTF8.GetString(attribute.Value);
        }

        public StunMessage AddString(ushort type, string value) => AddAttribute(type, Encoding.UTF8.GetBytes(value));

        public uint? GetUInt32(ushort type)
        {
            var attribute = GetAttribute(type);
            return attribute == null || attribute.Value.Length < 4 ? (uint?)null : BinaryPrimitives.ReadUInt32BigEndian(attribute.Value);
        }

        public StunMessage AddUInt32(ushort type, uint value)
        {
            byte[] bytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            return AddAttribute(type, bytes);
        }

        public ulong? GetUInt64(ushort type)
        {
            var attribute = GetAttribute(type);
            return attribute == null || attribute.Value.Length < 8 ? (ulong?)null : BinaryPrimitives.ReadUInt64BigEndian(attribute.Value);
        }

        public StunMessage AddUInt64(ushort type, ulong value)
        {
            byte[] bytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
            return AddAttribute(type, bytes);
        }

        public string Username => GetString(StunAttributeType.Username);

        public uint? Priority => GetUInt32(StunAttributeType.Priority);

        public bool UseCandidate => HasAttribute(StunAttributeType.UseCandidate);

        public ulong? IceControlling => GetUInt64(StunAttributeType.IceControlling);

        public ulong? IceControlled => GetUInt64(StunAttributeType.IceControlled);

        /// <summary>The address of an XOR-MAPPED-ADDRESS (RFC 8489 14.2), XOR-PEER-ADDRESS or XOR-RELAYED-ADDRESS.</summary>
        public IPEndPoint GetXorAddress(ushort type = StunAttributeType.XorMappedAddress)
        {
            var attribute = GetAttribute(type);
            return attribute == null ? null : DecodeAddress(attribute.Value, TransactionId, true);
        }

        public StunMessage AddXorAddress(IPEndPoint endPoint, ushort type = StunAttributeType.XorMappedAddress)
            => AddAttribute(type, EncodeAddress(endPoint, TransactionId, true));

        /// <summary>The address of a MAPPED-ADDRESS (RFC 8489 14.1), of servers of RFC 3489.</summary>
        public IPEndPoint MappedAddress
        {
            get
            {
                var attribute = GetAttribute(StunAttributeType.MappedAddress);
                return attribute == null ? null : DecodeAddress(attribute.Value, TransactionId, false);
            }
        }

        /// <summary>The code and reason of an ERROR-CODE (RFC 8489 14.8); null of a message of none.</summary>
        public (int Code, string Reason)? Error
        {
            get
            {
                var attribute = GetAttribute(StunAttributeType.ErrorCode);
                if (attribute == null || attribute.Value.Length < 4)
                    return null;
                int code = (attribute.Value[2] & 0x7) * 100 + attribute.Value[3];
                return (code, Encoding.UTF8.GetString(attribute.Value, 4, attribute.Value.Length - 4));
            }
        }

        public StunMessage AddError(int code, string reason)
        {
            byte[] text = Encoding.UTF8.GetBytes(reason ?? "");
            byte[] value = new byte[4 + text.Length];
            value[2] = (byte)(code / 100);
            value[3] = (byte)(code % 100);
            Buffer.BlockCopy(text, 0, value, 4, text.Length);
            return AddAttribute(StunAttributeType.ErrorCode, value);
        }

        private static IPEndPoint DecodeAddress(byte[] value, byte[] transactionId, bool xor)
        {
            if (value.Length < 8)
                return null;
            int family = value[1];
            int port = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(2));
            int length = family == 1 ? 4 : family == 2 ? 16 : 0;
            if (length == 0 || value.Length < 4 + length)
                return null;

            byte[] address = new byte[length];
            Buffer.BlockCopy(value, 4, address, 0, length);
            if (xor)
            {
                port ^= (int)(MagicCookie >> 16);
                byte[] mask = AddressMask(transactionId);
                for (int i = 0; i < length; i++)
                    address[i] ^= mask[i];
            }
            return new IPEndPoint(new IPAddress(address), port);
        }

        private static byte[] EncodeAddress(IPEndPoint endPoint, byte[] transactionId, bool xor)
        {
            byte[] address = endPoint.Address.GetAddressBytes();
            byte[] value = new byte[4 + address.Length];
            value[1] = (byte)(endPoint.AddressFamily == AddressFamily.InterNetwork ? 1 : 2);
            int port = endPoint.Port;
            if (xor)
            {
                port ^= (int)(MagicCookie >> 16);
                byte[] mask = AddressMask(transactionId);
                for (int i = 0; i < address.Length; i++)
                    address[i] ^= mask[i];
            }
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), (ushort)port);
            Buffer.BlockCopy(address, 0, value, 4, address.Length);
            return value;
        }

        // the magic cookie, then the transaction ID: of an IPv4 address its first 4 bytes, of an IPv6 address all 16
        private static byte[] AddressMask(byte[] transactionId)
        {
            byte[] mask = new byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask, MagicCookie);
            Buffer.BlockCopy(transactionId, 0, mask, 4, TransactionIdLength);
            return mask;
        }

        #endregion // Attributes

        public bool IsTransaction(StunMessage other)
        {
            if (other?.TransactionId == null)
                return false;
            for (int i = 0; i < TransactionIdLength; i++)
            {
                if (TransactionId[i] != other.TransactionId[i])
                    return false;
            }
            return true;
        }

        public override string ToString() => $"STUN 0x{Method:X3} {Class} {BitConverter.ToString(TransactionId).Replace("-", "")}";
    }
}
