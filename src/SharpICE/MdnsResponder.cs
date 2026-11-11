// SharpICE
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

using SharpStunClient;
using SharpStunCommon;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE
{
    /// <summary>
    /// A responder of multicast DNS (RFC 6762) of the names the agent hides its addresses behind (draft-ietf-mmusic-mdns-ice-
    /// candidates): of a query of one of them, its A - or AAAA - record. To a query of a port of its own (legacy unicast, 6.7),
    /// of unicast, its ID and question with it; to one that asks for unicast (5.4), of unicast; else of multicast, to the
    /// group. Its port is 5353, shared with the system's own responder, its socket a member of the group on each of the
    /// addresses. Names of 128 bits of randomness, it does not probe for them first (8.1).
    /// </summary>
    internal sealed class MdnsResponder : IDisposable
    {
        // a record's time to live: 120 seconds, of one of a host name (RFC 6762 10); of legacy unicast, 10 at most (6.7)
        private const uint Ttl = 120;
        private const uint LegacyTtl = 10;

        private readonly Dictionary<string, IPAddress> _names = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);
        private readonly List<Socket> _sockets = new List<Socket>();
        private readonly bool _multicast;
        private readonly Action<string> _trace;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>
        /// Of port 5353 and the groups, of each of the addresses given; or, of a test's endpoint, of it alone, no group joined.
        /// </summary>
        public MdnsResponder(IEnumerable<IPAddress> addresses, IPEndPoint endPoint, Action<string> trace)
        {
            _trace = trace;
            _multicast = endPoint == null;
            var list = addresses.Distinct().ToList();
            if (!_multicast)
            {
                var socket = new Socket(endPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(endPoint);
                _sockets.Add(socket);
            }
            else
            {
                foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
                {
                    var ofFamily = list.Where(a => a.AddressFamily == family && !IPAddress.IsLoopback(a)).ToList();
                    if (ofFamily.Count == 0)
                        continue;
                    var socket = Open(family, ofFamily);
                    if (socket != null)
                        _sockets.Add(socket);
                }
            }
            foreach (var socket in _sockets)
                _ = ReceiveAsync(socket);
        }

        /// <summary>The endpoint of a test's responder.</summary>
        public IPEndPoint EndPoint => _sockets.Count > 0 ? (IPEndPoint)_sockets[0].LocalEndPoint : null;

        /// <summary>A name of 128 bits of randomness, as a browser makes them, for the address.</summary>
        public string Register(IPAddress address)
        {
            lock (_names)
            {
                var existing = _names.FirstOrDefault(n => n.Value.Equals(address));
                if (existing.Key != null)
                    return existing.Key;
                string name = Guid.NewGuid().ToString() + ".local";
                _names[name] = address;
                return name;
            }
        }

        private Socket Open(AddressFamily family, List<IPAddress> addresses)
        {
            var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                // shared with the system's responder, and the browsers'
                socket.ExclusiveAddressUse = false;
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                bool v4 = family == AddressFamily.InterNetwork;
                socket.Bind(new IPEndPoint(v4 ? IPAddress.Any : IPAddress.IPv6Any, MdnsResolver.Port));
                foreach (var address in addresses)
                {
                    try
                    {
                        if (v4)
                            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(MdnsResolver.GroupV4, address));
                        else
                            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(MdnsResolver.GroupV6, InterfaceIndex(address)));
                    }
                    catch (SocketException ex)
                    {
                        _trace?.Invoke($"mDNS: no group on {address}: {ex.SocketErrorCode}");
                    }
                }
                socket.SetSocketOption(v4 ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                return socket;
            }
            catch (SocketException ex)
            {
                _trace?.Invoke($"mDNS: no responder of {family}: {ex.SocketErrorCode}");
                socket.Dispose();
                return null;
            }
        }

        private static long InterfaceIndex(IPAddress address)
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                var properties = nic.GetIPProperties();
                if (properties.UnicastAddresses.Any(u => u.Address.Equals(address)))
                    return properties.GetIPv6Properties()?.Index ?? 0;
            }
            return 0;
        }

        private async Task ReceiveAsync(Socket socket)
        {
            byte[] buffer = new byte[9000];
            var any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            while (!_cts.IsCancellationRequested)
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                try
                {
                    Answer(socket, buffer, result.ReceivedBytes, (IPEndPoint)result.RemoteEndPoint);
                }
                catch (Exception ex) when (ex is FormatException || ex is SocketException || ex is ArgumentException)
                {
                }
            }
        }

        private void Answer(Socket socket, byte[] query, int count, IPEndPoint from)
        {
            // a query (QR 0, opcode 0) of questions alone
            if (count < 12 || (query[2] & 0xF8) != 0)
                return;
            // of the link alone (RFC 6762 5.5, 11): a query of another network is not one of mDNS, and the addresses the names
            // hide are not for it
            if (!IsOnLink(from.Address))
                return;
            int questions = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(4));
            int position = 12;
            // each name answered once, however many times the query asks of it
            var answered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < questions; i++)
            {
                int start = position;
                string name = DnsMessage.ReadName(query, count, ref position);
                if (position + 4 > count)
                    return;
                ushort type = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(position));
                ushort questionClass = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(position + 2));
                position += 4;

                IPAddress address;
                lock (_names)
                {
                    if (!_names.TryGetValue(name, out address))
                        continue;
                }
                ushort wanted = address.AddressFamily == AddressFamily.InterNetwork ? DnsMessage.TypeA : DnsMessage.TypeAaaa;
                if (type != wanted && type != 255 || (questionClass & 0x7FFF) != DnsMessage.ClassIn && (questionClass & 0x7FFF) != 255)
                    continue;
                if (!answered.Add(name))
                    continue;

                bool legacy = from.Port != MdnsResolver.Port;
                bool unicast = legacy || (questionClass & DnsMessage.UnicastResponse) != 0 || !_multicast;
                byte[] response = BuildResponse(legacy ? BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(0)) : (ushort)0,
                    legacy ? query.Skip(start).Take(position - start).ToArray() : null, name, address, legacy ? LegacyTtl : Ttl);
                var to = unicast ? from : new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? MdnsResolver.GroupV4 : MdnsResolver.GroupV6, MdnsResolver.Port);
                if (!unicast && socket.AddressFamily == AddressFamily.InterNetwork)
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, address.GetAddressBytes());
                socket.SendTo(response, to);
                _trace?.Invoke($"mDNS: {name} is {address}, told {(unicast ? from.ToString() : "the group")}");
            }
        }

        // the networks of this host's interfaces, of their prefixes: what a source of the link is of
        private static readonly Lazy<List<(byte[] Network, int Prefix)>> Links = new Lazy<List<(byte[], int)>>(() =>
        {
            var links = new List<(byte[], int)>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                    {
                        int prefix;
                        try
                        {
                            prefix = unicast.PrefixLength;
                        }
                        catch (PlatformNotSupportedException)
                        {
                            continue;
                        }
                        links.Add((unicast.Address.GetAddressBytes(), prefix));
                    }
                }
            }
            catch (NetworkInformationException)
            {
            }
            return links;
        });

        // whether the source is on a link of this host: of IPv6 link-local, or of a network of one of its interfaces
        internal static bool IsOnLink(IPAddress source)
        {
            if (source.IsIPv4MappedToIPv6)
                source = source.MapToIPv4();
            if (source.IsIPv6LinkLocal || IPAddress.IsLoopback(source))
                return true;
            byte[] bytes = source.GetAddressBytes();
            if (bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254)
                return true;
            foreach (var (network, prefix) in Links.Value)
            {
                if (network.Length == bytes.Length && prefix > 0 && SamePrefix(network, bytes, prefix))
                    return true;
            }
            return false;
        }

        private static bool SamePrefix(byte[] a, byte[] b, int bits)
        {
            int whole = bits / 8;
            for (int i = 0; i < whole; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            int rest = bits % 8;
            if (rest == 0)
                return true;
            int mask = 0xFF << (8 - rest) & 0xFF;
            return (a[whole] & mask) == (b[whole] & mask);
        }

        // an authoritative answer of one record, its cache-flush bit set as of a name of its own (RFC 6762 10.2); of legacy
        // unicast, of the query's ID and question
        private static byte[] BuildResponse(ushort id, byte[] question, string name, IPAddress address, uint ttl)
        {
            var bytes = new List<byte>(64);
            bytes.Add((byte)(id >> 8));
            bytes.Add((byte)id);
            bytes.AddRange(new byte[] { 0x84, 0x00, 0, (byte)(question != null ? 1 : 0), 0, 1, 0, 0, 0, 0 });
            if (question != null)
                bytes.AddRange(question);
            foreach (string label in name.Split('.'))
            {
                byte[] text = Encoding.UTF8.GetBytes(label);
                bytes.Add((byte)text.Length);
                bytes.AddRange(text);
            }
            bytes.Add(0);
            ushort type = address.AddressFamily == AddressFamily.InterNetwork ? DnsMessage.TypeA : DnsMessage.TypeAaaa;
            // of legacy unicast, no cache-flush bit (RFC 6762 6.7)
            ushort answerClass = (ushort)(DnsMessage.ClassIn | (question != null ? 0 : 0x8000));
            bytes.AddRange(new[] { (byte)(type >> 8), (byte)type, (byte)(answerClass >> 8), (byte)answerClass });
            bytes.AddRange(new[] { (byte)(ttl >> 24), (byte)(ttl >> 16), (byte)(ttl >> 8), (byte)ttl });
            byte[] data = address.GetAddressBytes();
            bytes.Add((byte)(data.Length >> 8));
            bytes.Add((byte)data.Length);
            bytes.AddRange(data);
            return bytes.ToArray();
        }

        public void Dispose()
        {
            _cts.Cancel();
            foreach (var socket in _sockets)
                socket.Dispose();
        }
    }
}
