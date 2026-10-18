// SharpStunCommon
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
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SharpStunCommon
{
    /// <summary>
    /// STUN messages written straight into a span, of no <see cref="StunMessage"/> of them: what the data of TURN goes in, as
    /// each datagram of it is relayed.
    /// </summary>
    public static class StunWriter
    {
        private const int AttributeHeaderLength = 4;

#if !NETCOREAPP
        private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        [ThreadStatic]
        private static byte[] _transactionId;
#endif

        /// <summary>A new transaction ID, random (RFC 8489 5), of its 12 bytes.</summary>
        public static void NewTransactionId(Span<byte> destination)
        {
#if NETCOREAPP
            RandomNumberGenerator.Fill(destination.Slice(0, StunMessage.TransactionIdLength));
#else
            byte[] id = _transactionId ??= new byte[StunMessage.TransactionIdLength];
            lock (Random)
                Random.GetBytes(id);
            id.AsSpan().CopyTo(destination);
#endif
        }

        /// <summary>The header of a message (RFC 8489 5): of the length of its attributes, and of its transaction ID.</summary>
        public static void WriteHeader(Span<byte> destination, ushort method, StunMessageClass messageClass, int attributesLength, ReadOnlySpan<byte> transactionId)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination, StunMessage.GetMessageType(method, messageClass));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort)attributesLength);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), StunMessage.MagicCookie);
            transactionId.Slice(0, StunMessage.TransactionIdLength).CopyTo(destination.Slice(8));
        }

        /// <summary>An attribute's type and length; its value, padded to 4 bytes, follows.</summary>
        public static void WriteAttributeHeader(Span<byte> destination, ushort type, int length)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination, type);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort)length);
        }

        /// <summary>The padding of a value of the length: up to 4 bytes (RFC 8489 14).</summary>
        public static int Padding(int length) => (4 - (length & 3)) & 3;

        /// <summary>The bytes an XOR-ed address attribute of the endpoint takes, its header too.</summary>
        public static int XorAddressSize(IPEndPoint endPoint) => AttributeHeaderLength + 4 + (endPoint.AddressFamily == AddressFamily.InterNetwork ? 4 : 16);

        /// <summary>An XOR-ed address attribute (RFC 8489 14.2) of the type: its header and its value. The bytes written.</summary>
        public static int WriteXorAddress(Span<byte> destination, ushort type, IPEndPoint endPoint, ReadOnlySpan<byte> transactionId)
        {
            int length = endPoint.AddressFamily == AddressFamily.InterNetwork ? 4 : 16;
            WriteAttributeHeader(destination, type, 4 + length);
            var value = destination.Slice(AttributeHeaderLength, 4 + length);
            value[0] = 0;
            value[1] = (byte)(length == 4 ? 1 : 2);
            BinaryPrimitives.WriteUInt16BigEndian(value.Slice(2), (ushort)(endPoint.Port ^ (int)(StunMessage.MagicCookie >> 16)));
            var address = value.Slice(4, length);
#if NETCOREAPP
            endPoint.Address.TryWriteBytes(address, out _);
#else
            endPoint.Address.GetAddressBytes().AsSpan().CopyTo(address);
#endif
            // the magic cookie, then the transaction ID: of an IPv4 address its first 4 bytes, of an IPv6 address all 16
            Span<byte> cookie = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(cookie, StunMessage.MagicCookie);
            for (int i = 0; i < length; i++)
                address[i] ^= i < 4 ? cookie[i] : transactionId[i - 4];
            return AttributeHeaderLength + 4 + length;
        }
    }
}
