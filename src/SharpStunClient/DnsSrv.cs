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

using SharpStunCommon;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>A DNS SRV record (RFC 2782): where a service is, and in what order to try it.</summary>
    internal sealed class DnsSrvRecord
    {
        public ushort Priority { get; set; }
        public ushort Weight { get; set; }
        public ushort Port { get; set; }
        public string Target { get; set; }

        public override string ToString() => $"{Priority} {Weight} {Port} {Target}";
    }

    /// <summary>
    /// SRV lookups (RFC 2782) of the system's DNS servers over UDP, which .NET has none of: a query of RFC 1035 sent to each
    /// server in turn until one answers. A truncated answer is taken as it is.
    /// </summary>
    internal static class DnsSrv
    {
        private const int DnsPort = 53;

        private static readonly Random Random = new Random();

        /// <summary>
        /// The records of the name, in the order RFC 2782 says to try them; empty of none, or of a name with "." alone as its
        /// target - the service is not there - or of no server that answers in time.
        /// </summary>
        public static async Task<List<DnsSrvRecord>> QueryAsync(string name, TimeSpan timeout, CancellationToken cancellationToken)
        {
            foreach (var server in GetDnsServers())
            {
                var records = await QueryAsync(server, name, timeout, cancellationToken).ConfigureAwait(false);
                if (records != null)
                {
                    lock (Random)
                        return Order(records, Random);
                }
            }
            return new List<DnsSrvRecord>();
        }

        private static async Task<List<DnsSrvRecord>> QueryAsync(IPAddress server, string name, TimeSpan timeout, CancellationToken cancellationToken)
        {
            ushort id;
            lock (Random)
                id = (ushort)Random.Next(0x10000);
            byte[] query = BuildQuery(id, name);
            using (var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                var endPoint = new IPEndPoint(server, DnsPort);
                byte[] buffer = new byte[4096];
                DateTime deadline = DateTime.UtcNow + timeout;
                try
                {
                    socket.SendTo(query, endPoint);
                    while (DateTime.UtcNow < deadline)
                    {
                        var receive = socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                        var completed = await Task.WhenAny(receive, Task.Delay(deadline - DateTime.UtcNow, cancellationToken)).ConfigureAwait(false);
                        if (completed != receive)
                            return null;
                        var result = await receive.ConfigureAwait(false);
                        if (!((IPEndPoint)result.RemoteEndPoint).Address.Equals(server))
                            continue;
                        var records = ParseResponse(buffer, result.ReceivedBytes, id);
                        if (records != null)
                            return records;
                    }
                }
                catch (SocketException)
                {
                }
                catch (OperationCanceledException)
                {
                }
                return null;
            }
        }

        /// <summary>The DNS servers of the interfaces that are up: IPv4 ones first, and no site-local IPv6 one of Windows' defaults.</summary>
        private static List<IPAddress> GetDnsServers()
        {
            var servers = new List<IPAddress>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;
                    foreach (var address in nic.GetIPProperties().DnsAddresses)
                    {
                        if (address.IsIPv6SiteLocal || servers.Contains(address))
                            continue;
                        servers.Add(address);
                    }
                }
            }
            catch (NetworkInformationException)
            {
            }
            return servers.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).Take(3).ToList();
        }

        /// <summary>A query of RFC 1035 4.1 of the SRV records of the name, recursion desired.</summary>
        internal static byte[] BuildQuery(ushort id, string name) => DnsMessage.BuildQuery(id, name, DnsMessage.TypeSrv, DnsMessage.ClassIn, true);

        /// <summary>
        /// The SRV records of an answer to the query of the ID: empty of a name that does not exist, or of no records; null of
        /// what is not that answer, or not well formed, or of a server that failed.
        /// </summary>
        internal static List<DnsSrvRecord> ParseResponse(byte[] message, int count, ushort id)
        {
            var answers = DnsMessage.ParseResponse(message, count, id, out int rcode);
            if (rcode == 3) // NXDOMAIN
                return new List<DnsSrvRecord>();
            if (answers == null || rcode != 0)
                return null;

            var records = new List<DnsSrvRecord>();
            try
            {
                // a CNAME the server followed comes first: of the records, the SRV ones alone
                foreach (var answer in answers)
                {
                    if (answer.Type != DnsMessage.TypeSrv || answer.Class != DnsMessage.ClassIn || answer.DataLength < 7)
                        continue;
                    int data = answer.DataOffset;
                    var record = new DnsSrvRecord
                    {
                        Priority = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(data)),
                        Weight = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(data + 2)),
                        Port = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(data + 4)),
                    };
                    data += 6;
                    record.Target = DnsMessage.ReadName(message, count, ref data);
                    records.Add(record);
                }
            }
            catch (FormatException)
            {
                return null;
            }

            // "." alone: the service is decidedly not available at the domain (RFC 2782)
            if (records.Count == 1 && records[0].Target.Length == 0)
                records.Clear();
            return records;
        }

        /// <summary>
        /// The records in the order RFC 2782 says to try them: the lowest priority first, and of one priority, each picked at
        /// random, as likely as its weight is of the weights left - one of weight 0 seldom, but not never.
        /// </summary>
        internal static List<DnsSrvRecord> Order(List<DnsSrvRecord> records, Random random)
        {
            var ordered = new List<DnsSrvRecord>(records.Count);
            foreach (var group in records.GroupBy(r => r.Priority).OrderBy(g => g.Key))
            {
                // those of weight 0 first, as RFC 2782 lays the running sums out
                var left = group.OrderBy(r => r.Weight == 0 ? 0 : 1).ToList();
                while (left.Count > 0)
                {
                    int total = left.Sum(r => r.Weight);
                    int pick = random.Next(total + 1);
                    int sum = 0;
                    int index = 0;
                    for (; index < left.Count; index++)
                    {
                        sum += left[index].Weight;
                        if (sum >= pick)
                            break;
                    }
                    ordered.Add(left[index]);
                    left.RemoveAt(index);
                }
            }
            return ordered;
        }
    }
}
