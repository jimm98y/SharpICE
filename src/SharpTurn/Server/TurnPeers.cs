// SharpTurn
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
using System.Net;
using System.Net.Sockets;

namespace SharpTurn
{
    /// <summary>
    /// Which peers a TURN server relays to of its default: those of public unicast addresses alone. A relay to the loopback,
    /// to private or link-local networks, or to multicast, would let its clients reach what is behind the server - its own
    /// services, its network's (RFC 8656 21.2.3, as coturn's "no-loopback-peers" and "denied-peer-ip" refuse them).
    /// </summary>
    public static class TurnPeers
    {
        /// <summary>
        /// Whether the address is of the public internet: not of the ranges of RFC 6890's special purposes - the unspecified,
        /// the loopback, the private, shared (CGNAT), link-local, benchmarking, multicast and reserved ones, and IPv6's unique
        /// local, link-local and multicast ones. An IPv4 address embedded in IPv6 - mapped, NAT64's (RFC 6052), 6to4's - is
        /// judged as the IPv4 address it is.
        /// </summary>
        public static bool IsPublic(IPEndPoint endPoint) => endPoint != null && endPoint.Port != 0 && IsPublic(endPoint.Address);

        /// <inheritdoc cref="IsPublic(IPEndPoint)"/>
        public static bool IsPublic(IPAddress address)
        {
            if (address == null)
                return false;
            address = Embedded(address) ?? address;
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return IsPublicV4(address.GetAddressBytes());
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            byte[] b = address.GetAddressBytes();
            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.IPv6Any))
                return false;
            if ((b[0] & 0xFE) == 0xFC)                          // fc00::/7, unique local
                return false;
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)          // fe80::/10, link-local
                return false;
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0)          // fec0::/10, site-local (deprecated)
                return false;
            if (b[0] == 0xFF)                                   // ff00::/8, multicast
                return false;
            if (b[0] == 0x01 && b[1] == 0x00 && IsZero(b, 2, 6)) // 100::/64, discard
                return false;
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) // 2001:db8::/32, documentation
                return false;
            // the rest of ::/8: the IPv4-compatible and other reserved addresses
            if (b[0] == 0x00)
                return false;
            return true;
        }

        // the IPv4 address an IPv6 one carries: of ::ffff:0:0/96, of NAT64's 64:ff9b::/96 and 64:ff9b:1::/48, of 6to4's 2002::/16
        private static IPAddress Embedded(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                return null;
            if (address.IsIPv4MappedToIPv6)
                return address.MapToIPv4();
            byte[] b = address.GetAddressBytes();
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && (IsZero(b, 4, 8) || b[4] == 0x00 && b[5] == 0x01))
                return new IPAddress(new[] { b[12], b[13], b[14], b[15] });
            if (b[0] == 0x20 && b[1] == 0x02)
                return new IPAddress(new[] { b[2], b[3], b[4], b[5] });
            return null;
        }

        private static bool IsPublicV4(byte[] b)
        {
            switch (b[0])
            {
                case 0:     // 0.0.0.0/8, this network
                case 10:    // 10.0.0.0/8, private
                case 127:   // 127.0.0.0/8, loopback
                    return false;
                case 100:   // 100.64.0.0/10, shared address space (CGNAT)
                    return (b[1] & 0xC0) != 64;
                case 169:   // 169.254.0.0/16, link-local
                    return b[1] != 254;
                case 172:   // 172.16.0.0/12, private
                    return (b[1] & 0xF0) != 16;
                case 192:
                    if (b[1] == 168)                                // 192.168.0.0/16, private
                        return false;
                    if (b[1] == 0 && (b[2] == 0 || b[2] == 2))      // 192.0.0.0/24 IETF, 192.0.2.0/24 documentation
                        return false;
                    if (b[1] == 88 && b[2] == 99)                   // 192.88.99.0/24, 6to4 relay anycast
                        return false;
                    return true;
                case 198:
                    if ((b[1] & 0xFE) == 18)                        // 198.18.0.0/15, benchmarking
                        return false;
                    return !(b[1] == 51 && b[2] == 100);            // 198.51.100.0/24, documentation
                case 203:
                    return !(b[1] == 0 && b[2] == 113);             // 203.0.113.0/24, documentation
            }
            // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255 broadcast
            return b[0] < 224;
        }

        private static bool IsZero(byte[] bytes, int offset, int count)
        {
            for (int i = offset; i < offset + count; i++)
            {
                if (bytes[i] != 0)
                    return false;
            }
            return true;
        }
    }
}
