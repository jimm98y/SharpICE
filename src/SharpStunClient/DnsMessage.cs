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
using System.Text;

namespace SharpStunClient
{
    /// <summary>A resource record of a DNS message (RFC 1035 4.1.3): where its data is in the message it was read of.</summary>
    internal sealed class DnsRecord
    {
        public string Name { get; set; }
        public ushort Type { get; set; }
        public ushort Class { get; set; }
        public int DataOffset { get; set; }
        public int DataLength { get; set; }

        /// <summary>The address of an A or AAAA record; null of another, or of one of the wrong length.</summary>
        public IPAddress GetAddress(byte[] message)
        {
            if (Type == DnsMessage.TypeA && DataLength == 4 || Type == DnsMessage.TypeAaaa && DataLength == 16)
            {
                byte[] address = new byte[DataLength];
                Buffer.BlockCopy(message, DataOffset, address, 0, DataLength);
                return new IPAddress(address);
            }
            return null;
        }
    }

    /// <summary>The DNS messages of RFC 1035 that unicast DNS and multicast DNS (RFC 6762) have alike: a query, and the records of an answer.</summary>
    internal static class DnsMessage
    {
        public const ushort TypeA = 1;
        public const ushort TypeAaaa = 28;
        public const ushort TypeSrv = 33;
        public const ushort ClassIn = 1;

        // the top bit of a question's class in mDNS: an answer of unicast asked for (RFC 6762 5.4)
        public const ushort UnicastResponse = 0x8000;

        /// <summary>A query of RFC 1035 4.1 of one question.</summary>
        public static byte[] BuildQuery(ushort id, string name, ushort type, ushort questionClass, bool recursionDesired)
        {
            var bytes = new List<byte>(32 + name.Length);
            bytes.Add((byte)(id >> 8));
            bytes.Add((byte)id);
            bytes.AddRange(new byte[] { (byte)(recursionDesired ? 0x01 : 0x00), 0x00, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (string label in name.TrimEnd('.').Split('.'))
            {
                byte[] text = Encoding.UTF8.GetBytes(label);
                if (text.Length == 0 || text.Length > 63)
                    throw new ArgumentException($"{name} is no DNS name.", nameof(name));
                bytes.Add((byte)text.Length);
                bytes.AddRange(text);
            }
            bytes.Add(0);
            bytes.AddRange(new byte[] { (byte)(type >> 8), (byte)type, (byte)(questionClass >> 8), (byte)questionClass });
            return bytes.ToArray();
        }

        /// <summary>
        /// The records of a response's answer and additional sections, its RCODE given; null of what is no response - or of
        /// another ID, of an ID asked for - or is not well formed.
        /// </summary>
        public static List<DnsRecord> ParseResponse(byte[] message, int count, ushort? id, out int rcode)
        {
            rcode = -1;
            try
            {
                if (count < 12 || (message[2] & 0x80) == 0)
                    return null;
                if (id.HasValue && BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(0)) != id.Value)
                    return null;
                rcode = message[3] & 0x0F;

                int questions = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(4));
                int answers = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(6));
                int authorities = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(8));
                int additionals = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(10));
                int position = 12;
                for (int i = 0; i < questions; i++)
                {
                    ReadName(message, count, ref position);
                    position += 4;
                }

                var records = new List<DnsRecord>();
                int total = answers + authorities + additionals;
                for (int i = 0; i < total; i++)
                {
                    string name = ReadName(message, count, ref position);
                    if (position + 10 > count)
                        return null;
                    int length = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(position + 8));
                    var record = new DnsRecord
                    {
                        Name = name,
                        Type = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(position)),
                        // mDNS's top bit of the class: the cache-flush bit (RFC 6762 10.2)
                        Class = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(position + 2)) & 0x7FFF),
                        DataOffset = position + 10,
                        DataLength = length,
                    };
                    position += 10;
                    if (position + length > count)
                        return null;
                    position += length;
                    // the authority section's are of no use here
                    if (i < answers || i >= answers + authorities)
                        records.Add(record);
                }
                return records;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        /// <summary>A name of labels and of pointers to names before it (RFC 1035 4.1.4); the position after it.</summary>
        public static string ReadName(byte[] message, int count, ref int position)
        {
            var name = new StringBuilder();
            int at = position;
            bool jumped = false;
            int jumps = 0;
            while (true)
            {
                if (at >= count)
                    throw new FormatException();
                int length = message[at];
                if ((length & 0xC0) == 0xC0)
                {
                    if (at + 1 >= count || ++jumps > 16)
                        throw new FormatException();
                    if (!jumped)
                        position = at + 2;
                    jumped = true;
                    at = (length & 0x3F) << 8 | message[at + 1];
                    continue;
                }
                if ((length & 0xC0) != 0)
                    throw new FormatException();
                at++;
                if (length == 0)
                    break;
                if (at + length > count)
                    throw new FormatException();
                if (name.Length > 0)
                    name.Append('.');
                name.Append(Encoding.UTF8.GetString(message, at, length));
                at += length;
            }
            if (!jumped)
                position = at;
            return name.ToString();
        }
    }
}
