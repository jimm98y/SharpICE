// SharpTurnCommon
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

using SharpStunCommon;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpTurnCommon
{
    /// <summary>TURN's methods (RFC 8656 17).</summary>
    public static class TurnMethod
    {
        public const ushort Allocate = 0x003;
        public const ushort Refresh = 0x004;
        public const ushort Send = 0x006;
        public const ushort Data = 0x007;
        public const ushort CreatePermission = 0x008;
        public const ushort ChannelBind = 0x009;

        /// <summary>Of a TCP allocation (RFC 6062 6.1): a connection to a peer the server is to make.</summary>
        public const ushort Connect = 0x00A;

        /// <summary>Of a TCP allocation (RFC 6062 6.1): a new connection of the client's bound to a peer's, of its CONNECTION-ID.</summary>
        public const ushort ConnectionBind = 0x00B;

        /// <summary>Of a TCP allocation (RFC 6062 6.1): an indication of a peer that connected to the relayed address.</summary>
        public const ushort ConnectionAttempt = 0x00C;
    }

    /// <summary>TURN's attributes (RFC 8656 18).</summary>
    public static class TurnAttributeType
    {
        public const ushort ChannelNumber = 0x000C;
        public const ushort Lifetime = 0x000D;
        public const ushort XorPeerAddress = 0x0012;
        public const ushort Data = 0x0013;
        public const ushort XorRelayedAddress = 0x0016;
        public const ushort RequestedAddressFamily = 0x0017;
        public const ushort EvenPort = 0x0018;
        public const ushort RequestedTransport = 0x0019;
        public const ushort DontFragment = 0x001A;
        public const ushort ReservationToken = 0x0022;

        /// <summary>Of a TCP allocation (RFC 6062 6.2.1): the 32 bit number of a peer's connection.</summary>
        public const ushort ConnectionId = 0x002A;

        public const ushort AdditionalAddressFamily = 0x8000;
        public const ushort AddressErrorCode = 0x8001;
        public const ushort Icmp = 0x8004;

        private static readonly HashSet<ushort> Known = new HashSet<ushort>
        {
            ChannelNumber, Lifetime, XorPeerAddress, Data, XorRelayedAddress, RequestedAddressFamily, EvenPort, RequestedTransport,
            DontFragment, ReservationToken, ConnectionId, AdditionalAddressFamily, AddressErrorCode, Icmp,
        };

        /// <summary>Whether the attribute is one of TURN's.</summary>
        public static bool IsKnown(ushort type) => Known.Contains(type);

        /// <summary>Whether the attribute is one of STUN's or of TURN's: what a TURN client or server reads.</summary>
        public static bool IsKnownOfTurn(ushort type) => StunAttributeType.IsKnown(type) || Known.Contains(type);
    }

    /// <summary>TURN's error codes (RFC 8656 19).</summary>
    public static class TurnErrorCode
    {
        public const int Forbidden = 403;
        public const int AllocationMismatch = 437;
        public const int AddressFamilyNotSupported = 440;
        public const int WrongCredentials = 441;
        public const int UnsupportedTransportProtocol = 442;
        public const int PeerAddressFamilyMismatch = 443;

        /// <summary>Of a Connect to a peer a connection is of, or being made to, already (RFC 6062 6.3).</summary>
        public const int ConnectionAlreadyExists = 446;

        /// <summary>Of a Connect whose connection to the peer failed, or timed out (RFC 6062 6.3).</summary>
        public const int ConnectionTimeoutOrFailure = 447;

        public const int AllocationQuotaReached = 486;
        public const int InsufficientCapacity = 508;
    }

    /// <summary>TURN's fixed values (RFC 8656): the transport of its relays, the range of its channels, its lifetimes.</summary>
    public static class TurnConstants
    {
        /// <summary>The REQUESTED-TRANSPORT of UDP, the only one of RFC 8656 (18.8): its protocol number.</summary>
        public const byte Udp = 17;

        /// <summary>The REQUESTED-TRANSPORT of TCP, of a TCP allocation (RFC 6062 4.1): its protocol number.</summary>
        public const byte Tcp = 6;

        /// <summary>
        /// Of a TCP allocation (RFC 6062 5.2, 5.3): how long a peer's connection waits for its ConnectionBind, and how long the
        /// server tries a Connect's connection at least.
        /// </summary>
        public static readonly TimeSpan ConnectionBindTimeout = TimeSpan.FromSeconds(30);
        public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

        /// <summary>The channel numbers (RFC 8656 12).</summary>
        public const ushort MinChannel = 0x4000;
        public const ushort MaxChannel = 0x4FFF;

        /// <summary>An allocation's default lifetime (RFC 8656 6), and the longest RFC 8656 7.2 recommends.</summary>
        public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(600);
        public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(3600);

        /// <summary>A permission's lifetime (RFC 8656 9) and a channel's (12).</summary>
        public static readonly TimeSpan PermissionLifetime = TimeSpan.FromSeconds(300);
        public static readonly TimeSpan ChannelLifetime = TimeSpan.FromSeconds(600);
    }

    /// <summary>TURN's attributes of a message, read and written (RFC 8656 18).</summary>
    public static class TurnMessageExtensions
    {
        /// <summary>REQUESTED-TRANSPORT (18.8): the protocol number, three bytes of RFFU after it.</summary>
        public static StunMessage AddRequestedTransport(this StunMessage message, byte protocol = TurnConstants.Udp)
            => message.AddAttribute(TurnAttributeType.RequestedTransport, new byte[] { protocol, 0, 0, 0 });

        /// <summary>The protocol of a REQUESTED-TRANSPORT; null of none, or of one not well formed.</summary>
        public static byte? GetRequestedTransport(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.RequestedTransport);
            return attribute == null || attribute.Value.Length != 4 ? (byte?)null : attribute.Value[0];
        }

        /// <summary>CONNECTION-ID (RFC 6062 6.2.1): the number of a peer's connection.</summary>
        public static StunMessage AddConnectionId(this StunMessage message, uint connectionId)
            => message.AddUInt32(TurnAttributeType.ConnectionId, connectionId);

        /// <summary>The number of a CONNECTION-ID; null of none, or of one not well formed.</summary>
        public static uint? GetConnectionId(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.ConnectionId);
            return attribute == null || attribute.Value.Length != 4 ? (uint?)null : BinaryPrimitives.ReadUInt32BigEndian(attribute.Value);
        }

        /// <summary>REQUESTED-ADDRESS-FAMILY or ADDITIONAL-ADDRESS-FAMILY (18.6, 18.11): 0x01 of IPv4, 0x02 of IPv6.</summary>
        public static StunMessage AddAddressFamily(this StunMessage message, ushort type, AddressFamily family)
            => message.AddAttribute(type, new byte[] { FamilyCode(family), 0, 0, 0 });

        /// <summary>
        /// The family of a REQUESTED-ADDRESS-FAMILY or ADDITIONAL-ADDRESS-FAMILY; null of none; <see cref="AddressFamily.Unknown"/>
        /// of a code of no family.
        /// </summary>
        public static AddressFamily? GetAddressFamily(this StunMessage message, ushort type)
        {
            var attribute = message.GetAttribute(type);
            if (attribute == null)
                return null;
            return attribute.Value.Length < 1 ? AddressFamily.Unknown : FamilyOf(attribute.Value[0]);
        }

        /// <summary>EVEN-PORT (18.7): of its R bit, the next port reserved too.</summary>
        public static StunMessage AddEvenPort(this StunMessage message, bool reserveNext)
            => message.AddAttribute(TurnAttributeType.EvenPort, new byte[] { (byte)(reserveNext ? 0x80 : 0) });

        /// <summary>Of an EVEN-PORT, whether its R bit asks for the next port reserved; null of none.</summary>
        public static bool? GetEvenPort(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.EvenPort);
            if (attribute == null)
                return null;
            return attribute.Value.Length >= 1 && (attribute.Value[0] & 0x80) != 0;
        }

        /// <summary>CHANNEL-NUMBER (18.1): the number, two bytes of RFFU after it.</summary>
        public static StunMessage AddChannelNumber(this StunMessage message, ushort channel)
        {
            byte[] value = new byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(value, channel);
            return message.AddAttribute(TurnAttributeType.ChannelNumber, value);
        }

        /// <summary>The number of a CHANNEL-NUMBER; null of none, or of one not well formed.</summary>
        public static ushort? GetChannelNumber(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.ChannelNumber);
            return attribute == null || attribute.Value.Length != 4 ? (ushort?)null : BinaryPrimitives.ReadUInt16BigEndian(attribute.Value);
        }

        /// <summary>LIFETIME (18.2), of whole seconds.</summary>
        public static StunMessage AddLifetime(this StunMessage message, TimeSpan lifetime)
            => message.AddUInt32(TurnAttributeType.Lifetime, (uint)Math.Max(0, Math.Round(lifetime.TotalSeconds)));

        /// <summary>The lifetime of a LIFETIME; null of none.</summary>
        public static TimeSpan? GetLifetime(this StunMessage message)
        {
            uint? seconds = message.GetUInt32(TurnAttributeType.Lifetime);
            return seconds.HasValue ? TimeSpan.FromSeconds(seconds.Value) : (TimeSpan?)null;
        }

        /// <summary>ADDRESS-ERROR-CODE (18.12): the family not allocated, then its code and reason as an ERROR-CODE has them.</summary>
        public static StunMessage AddAddressError(this StunMessage message, AddressFamily family, int code, string reason)
        {
            byte[] text = Encoding.UTF8.GetBytes(reason ?? "");
            byte[] value = new byte[4 + text.Length];
            value[0] = FamilyCode(family);
            value[2] = (byte)(code / 100);
            value[3] = (byte)(code % 100);
            Buffer.BlockCopy(text, 0, value, 4, text.Length);
            return message.AddAttribute(TurnAttributeType.AddressErrorCode, value);
        }

        /// <summary>The family, code and reason of an ADDRESS-ERROR-CODE; null of none.</summary>
        public static (AddressFamily Family, int Code, string Reason)? GetAddressError(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.AddressErrorCode);
            if (attribute == null || attribute.Value.Length < 4)
                return null;
            byte[] value = attribute.Value;
            return (FamilyOf(value[0]), (value[2] & 0x7) * 100 + value[3], Encoding.UTF8.GetString(value, 4, value.Length - 4));
        }

        /// <summary>The type and code of an ICMP (18.13); null of none.</summary>
        public static (byte Type, byte Code)? GetIcmp(this StunMessage message)
        {
            var attribute = message.GetAttribute(TurnAttributeType.Icmp);
            return attribute == null || attribute.Value.Length < 4 ? ((byte, byte)?)null : (attribute.Value[2], attribute.Value[3]);
        }

        private static byte FamilyCode(AddressFamily family) => family == AddressFamily.InterNetworkV6 ? (byte)2 : (byte)1;

        private static AddressFamily FamilyOf(byte code)
            => code == 1 ? AddressFamily.InterNetwork : code == 2 ? AddressFamily.InterNetworkV6 : AddressFamily.Unknown;
    }

    /// <summary>A ChannelData message (RFC 8656 12.4): its channel number, its length, its data - padded to 4 bytes over a stream.</summary>
    public static class TurnChannelData
    {
        /// <summary>A ChannelData message of the data, padded to 4 bytes of a stream (RFC 8656 12.5).</summary>
        public static byte[] Create(ushort channel, byte[] buffer, int offset, int count, bool padded)
        {
            byte[] message = new byte[StunFraming.ChannelDataSize(count, padded)];
            Write(message, channel, new ReadOnlySpan<byte>(buffer, offset, count), padded);
            return message;
        }

        /// <summary>
        /// A ChannelData message of the data into the destination, of <see cref="StunFraming.ChannelDataSize"/> bytes at least,
        /// padded with zeros of a stream: the bytes written.
        /// </summary>
        public static int Write(Span<byte> destination, ushort channel, ReadOnlySpan<byte> data, bool padded)
        {
            data.CopyTo(destination.Slice(StunFraming.ChannelDataHeaderLength));
            return Frame(destination, channel, data.Length, padded);
        }

        /// <summary>
        /// The header of a ChannelData message whose data is in the destination already, past its 4 bytes, and the padding of a
        /// stream after it: the bytes the message takes.
        /// </summary>
        public static int Frame(Span<byte> destination, ushort channel, int dataLength, bool padded)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination, channel);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort)dataLength);
            int size = StunFraming.ChannelDataSize(dataLength, padded);
            destination.Slice(StunFraming.ChannelDataHeaderLength + dataLength, size - StunFraming.ChannelDataHeaderLength - dataLength).Clear();
            return size;
        }

        /// <summary>
        /// The channel number of a ChannelData message, and where its data is; false of one not well formed - of a number out of
        /// the channels' range, or of a length past what there is (RFC 8656 12.6).
        /// </summary>
        public static bool TryRead(byte[] buffer, int offset, int count, out ushort channel, out int dataOffset, out int dataLength)
        {
            channel = 0;
            dataOffset = offset + StunFraming.ChannelDataHeaderLength;
            dataLength = 0;
            if (count < StunFraming.ChannelDataHeaderLength)
                return false;
            channel = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset));
            dataLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset + 2));
            return channel >= TurnConstants.MinChannel && channel <= TurnConstants.MaxChannel
                && StunFraming.ChannelDataHeaderLength + dataLength <= count;
        }
    }

    /// <summary>
    /// A Send or Data indication (RFC 8656 10.1, 11.4) written straight into a span: its header, XOR-PEER-ADDRESS and DATA - and
    /// of a Send indication of the DF bit, DONT-FRAGMENT - of no FINGERPRINT, as no indication of TURN needs one.
    /// </summary>
    public static class TurnIndication
    {
        private const int DataAttributeHeaderLength = 4;

        /// <summary>The bytes of an indication before its data: its header, XOR-PEER-ADDRESS, and DATA's own header.</summary>
        public static int HeaderSize(IPEndPoint peer) => StunMessage.HeaderLength + StunWriter.XorAddressSize(peer) + DataAttributeHeaderLength;

        /// <summary>The bytes of an indication of the data in all.</summary>
        public static int Size(IPEndPoint peer, int dataLength, bool dontFragment)
            => HeaderSize(peer) + dataLength + StunWriter.Padding(dataLength) + (dontFragment ? 4 : 0);

        /// <summary>An indication of the data into the destination, of <see cref="Size"/> bytes at least: the bytes written.</summary>
        public static int Write(Span<byte> destination, ushort method, IPEndPoint peer, ReadOnlySpan<byte> data, bool dontFragment = false)
        {
            data.CopyTo(destination.Slice(HeaderSize(peer)));
            return Frame(destination, method, peer, data.Length, dontFragment);
        }

        /// <summary>
        /// The header of an indication whose data is in the destination already, past <see cref="HeaderSize"/> bytes, and its
        /// padding and DONT-FRAGMENT after it: the bytes the indication takes.
        /// </summary>
        public static int Frame(Span<byte> destination, ushort method, IPEndPoint peer, int dataLength, bool dontFragment = false)
        {
            int size = Size(peer, dataLength, dontFragment);
            Span<byte> transactionId = stackalloc byte[StunMessage.TransactionIdLength];
            StunWriter.NewTransactionId(transactionId);
            StunWriter.WriteHeader(destination, method, StunMessageClass.Indication, size - StunMessage.HeaderLength, transactionId);
            int position = StunMessage.HeaderLength;
            position += StunWriter.WriteXorAddress(destination.Slice(position), TurnAttributeType.XorPeerAddress, peer, transactionId);
            StunWriter.WriteAttributeHeader(destination.Slice(position), TurnAttributeType.Data, dataLength);
            position += DataAttributeHeaderLength + dataLength;
            int padding = StunWriter.Padding(dataLength);
            destination.Slice(position, padding).Clear();
            position += padding;
            if (dontFragment)
            {
                StunWriter.WriteAttributeHeader(destination.Slice(position), TurnAttributeType.DontFragment, 0);
                position += 4;
            }
            return position;
        }
    }
}
