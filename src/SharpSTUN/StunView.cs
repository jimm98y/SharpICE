// SharpSTUN
// Copyright (C) 2026 Lukas Volf, assisted by Claude Code
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
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace SharpSTUN
{
    /// <summary>
    /// A STUN message read in place, of no <see cref="StunMessage"/> of it: of the same rules as
    /// <see cref="StunMessage.Parse(byte[], int, int)"/>, what ICE asks of its binding requests and responses, of no allocation.
    /// Valid while the datagram is.
    /// </summary>
    internal readonly ref struct StunView
    {
        private const int MaxAttributes = 64;
        private const int IntegrityLength = 20;
        private const int IntegritySha256Length = 32;

        private readonly ReadOnlySpan<byte> _datagram;
        private readonly int _integrityOffset;
        private readonly int _fingerprintOffset;
        // the attributes not ignored: those before the first integrity or fingerprint
        private readonly int _attributesEnd;

        private StunView(ReadOnlySpan<byte> datagram, int integrityOffset, int fingerprintOffset, int attributesEnd)
        {
            _datagram = datagram;
            _integrityOffset = integrityOffset;
            _fingerprintOffset = fingerprintOffset;
            _attributesEnd = attributesEnd;
        }

        /// <summary>A message of a datagram; false of one that is not, or that is not well formed, as Parse has it.</summary>
        public static bool TryParse(ReadOnlySpan<byte> datagram, out StunView message)
        {
            message = default;
            if (!StunMessage.IsStun(datagram))
                return false;

            int count = datagram.Length;
            int integrityOffset = -1, integritySha256Offset = -1, fingerprintOffset = -1, attributes = 0;
            int attributesEnd = -1;
            int position = StunMessage.HeaderLength;
            while (position + 4 <= count)
            {
                ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(position));
                int length = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(position + 2));
                if (position + 4 + length > count)
                    return false;
                if (fingerprintOffset >= 0)
                    return false;
                bool ignored;
                if (attributeType == StunAttributeType.MessageIntegrity)
                {
                    ignored = integrityOffset >= 0 || integritySha256Offset >= 0;
                    if (!ignored)
                    {
                        if (length != IntegrityLength)
                            return false;
                        integrityOffset = position;
                    }
                }
                else if (attributeType == StunAttributeType.MessageIntegritySha256)
                {
                    ignored = integritySha256Offset >= 0;
                    if (!ignored)
                    {
                        if (length < 16 || length > IntegritySha256Length || (length & 3) != 0)
                            return false;
                        integritySha256Offset = position;
                    }
                }
                else if (attributeType == StunAttributeType.Fingerprint)
                {
                    if (length != 4)
                        return false;
                    fingerprintOffset = position;
                }
                else
                {
                    ignored = integrityOffset >= 0 || integritySha256Offset >= 0;
                    if (!ignored && ++attributes > MaxAttributes)
                        return false;
                }
                if (attributesEnd < 0 && (integrityOffset >= 0 || integritySha256Offset >= 0 || fingerprintOffset >= 0))
                    attributesEnd = position;
                position += 4 + ((length + 3) & ~3);
            }
            if (position != count)
                return false;
            message = new StunView(datagram, integrityOffset, fingerprintOffset, attributesEnd < 0 ? count : attributesEnd);
            return true;
        }

        public ushort Method
        {
            get
            {
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(_datagram);
                return (ushort)((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
            }
        }

        public StunMessageClass Class
        {
            get
            {
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(_datagram);
                return (StunMessageClass)(((type >> 4) & 1) | ((type >> 7) & 2));
            }
        }

        public ReadOnlySpan<byte> TransactionId => _datagram.Slice(8, StunMessage.TransactionIdLength);

        public bool HasFingerprint => _fingerprintOffset >= 0;

        /// <summary>Whether its FINGERPRINT is the CRC-32 of the message before it (RFC 8489 14.7).</summary>
        public bool VerifyFingerprint()
        {
            if (_fingerprintOffset < 0)
                return false;
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(_datagram.Slice(_fingerprintOffset + 4));
            return (Crc32.Compute(_datagram.Slice(0, _fingerprintOffset)) ^ StunMessage.FingerprintXor) == expected;
        }

        /// <summary>Whether its MESSAGE-INTEGRITY is the HMAC-SHA1 of the message before it, of the key (RFC 8489 14.5).</summary>
        public bool VerifyIntegrity(byte[] key)
        {
            if (_integrityOffset < 0 || key == null)
                return false;
            int offset = _integrityOffset;
            // of the message up to it, its header's length to the end of the integrity, as it was signed
            byte[] rented = null;
            Span<byte> signed = offset <= 1024 ? stackalloc byte[offset] : (rented = ArrayPool<byte>.Shared.Rent(offset)).AsSpan(0, offset);
            try
            {
                _datagram.Slice(0, offset).CopyTo(signed);
                BinaryPrimitives.WriteUInt16BigEndian(signed.Slice(2), (ushort)(offset - StunMessage.HeaderLength + 4 + IntegrityLength));
                Span<byte> hmac = stackalloc byte[IntegrityLength];
                StunWriter.HmacSha1(key, signed, hmac);
                var expected = _datagram.Slice(offset + 4, IntegrityLength);
                int difference = 0;
                for (int i = 0; i < IntegrityLength; i++)
                    difference |= hmac[i] ^ expected[i];
                return difference == 0;
            }
            finally
            {
                if (rented != null)
                    ArrayPool<byte>.Shared.Return(rented);
            }
        }

        /// <summary>The value of the first attribute of the type, of those not ignored.</summary>
        public bool TryGetAttribute(ushort type, out ReadOnlySpan<byte> value)
        {
            int position = StunMessage.HeaderLength;
            while (position + 4 <= _attributesEnd)
            {
                ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position));
                int length = BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position + 2));
                if (attributeType == type)
                {
                    value = _datagram.Slice(position + 4, length);
                    return true;
                }
                position += 4 + ((length + 3) & ~3);
            }
            value = default;
            return false;
        }

        public bool HasAttribute(ushort type) => TryGetAttribute(type, out _);

        public uint? GetUInt32(ushort type)
            => TryGetAttribute(type, out var value) && value.Length >= 4 ? BinaryPrimitives.ReadUInt32BigEndian(value) : (uint?)null;

        public ulong? GetUInt64(ushort type)
            => TryGetAttribute(type, out var value) && value.Length >= 8 ? BinaryPrimitives.ReadUInt64BigEndian(value) : (ulong?)null;

        /// <summary>Whether its USERNAME begins with the bytes given.</summary>
        public bool UsernameStartsWith(ReadOnlySpan<byte> prefix)
            => TryGetAttribute(StunAttributeType.Username, out var value) && value.StartsWith(prefix);

        /// <summary>The code of an ERROR-CODE (RFC 8489 14.8); null of none.</summary>
        public int? ErrorCode
            => TryGetAttribute(StunAttributeType.ErrorCode, out var value) && value.Length >= 4 ? (value[2] & 0x7) * 100 + value[3] : (int?)null;

        /// <summary>The reason of an ERROR-CODE, a string of it: of an error alone.</summary>
        public string ErrorReason
            => TryGetAttribute(StunAttributeType.ErrorCode, out var value) && value.Length >= 4 ? Encoding.UTF8.GetString(value.Slice(4).ToArray()) : null;

        /// <summary>Whether it has an attribute it is not to be understood without, of those <see cref="StunAttributeType"/> knows.</summary>
        public bool HasUnknownComprehensionRequired()
        {
            int position = StunMessage.HeaderLength;
            while (position + 4 <= _attributesEnd)
            {
                ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position));
                if (attributeType < 0x8000 && !StunAttributeType.IsKnown(attributeType))
                    return true;
                position += 4 + ((BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position + 2)) + 3) & ~3);
            }
            return false;
        }

        /// <summary>The attributes it is not to be understood without, each once: of the error that lists them alone.</summary>
        public List<ushort> GetUnknownComprehensionRequired()
        {
            var unknown = new List<ushort>();
            int position = StunMessage.HeaderLength;
            while (position + 4 <= _attributesEnd)
            {
                ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position));
                if (attributeType < 0x8000 && !StunAttributeType.IsKnown(attributeType) && !unknown.Contains(attributeType))
                    unknown.Add(attributeType);
                position += 4 + ((BinaryPrimitives.ReadUInt16BigEndian(_datagram.Slice(position + 2)) + 3) & ~3);
            }
            return unknown;
        }
    }
}
