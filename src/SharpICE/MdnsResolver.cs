// SharpICE
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

using SharpStunClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE
{
    /// <summary>
    /// The names of mDNS - ".local" - a browser hides its addresses behind in its candidates (draft-ietf-mmusic-mdns-ice-
    /// candidates), resolved of a one-shot query of multicast DNS (RFC 6762 5.1) from a port of its own, its answer asked for
    /// of unicast (5.4): sent from each of the local addresses, as the peer is on the link of one of them.
    /// </summary>
    internal sealed class MdnsResolver
    {
        public const int Port = 5353;
        public static readonly IPAddress GroupV4 = IPAddress.Parse("224.0.0.251");
        public static readonly IPAddress GroupV6 = IPAddress.Parse("ff02::fb");

        private static readonly Random Random = new Random();

        // where the queries go: of none, the groups; of a test's, a responder of its own
        private readonly IReadOnlyList<IPEndPoint> _targets;

        public MdnsResolver(IReadOnlyList<IPEndPoint> targets = null)
        {
            _targets = targets;
        }

        /// <summary>
        /// The address of the name, of an A record - or of AAAA, of IPv6 asked for - of the first responder that answers, from
        /// any of the local addresses given; null of none in time.
        /// </summary>
        public async Task<IPAddress> ResolveAsync(string name, IEnumerable<IPAddress> localAddresses, bool includeIPv6, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            var sockets = new List<Socket>();
            try
            {
                foreach (var address in localAddresses.Distinct())
                {
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && !includeIPv6)
                        continue;
                    var socket = Open(address);
                    if (socket != null)
                        sockets.Add(socket);
                }
                if (sockets.Count == 0)
                    return null;

                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    cts.CancelAfter(timeout);
                    var answered = new TaskCompletionSource<IPAddress>(TaskCreationOptions.RunContinuationsAsynchronously);
                    using (cts.Token.Register(() => answered.TrySetResult(null)))
                    {
                        foreach (var socket in sockets)
                            _ = ReceiveAsync(socket, name, answered, cts.Token);

                        // the query, and again half a second and a second and a half after it, of one lost
                        var delays = new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(1.5) };
                        foreach (var delay in delays)
                        {
                            if (delay > TimeSpan.Zero && await Task.WhenAny(answered.Task, Task.Delay(delay, cts.Token)).ConfigureAwait(false) == answered.Task)
                                break;
                            foreach (var socket in sockets)
                                Query(socket, name);
                        }
                        return await answered.Task.ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            finally
            {
                foreach (var socket in sockets)
                    socket.Dispose();
            }
        }

        // a socket of the address, its multicast going out of its interface, of a TTL of 255 (RFC 6762 11)
        private Socket Open(IPAddress address)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(new IPEndPoint(address, 0));
                if (_targets == null)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, address.GetAddressBytes());
                        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
                    }
                    else
                    {
                        socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, InterfaceIndex(address));
                        socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    }
                }
                return socket;
            }
            catch (SocketException)
            {
                socket.Dispose();
                return null;
            }
        }

        // the index of the interface of an IPv6 address, as IPV6_MULTICAST_IF takes it
        private static int InterfaceIndex(IPAddress address)
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                var properties = nic.GetIPProperties();
                if (properties.UnicastAddresses.Any(u => u.Address.Equals(address)))
                    return properties.GetIPv6Properties()?.Index ?? 0;
            }
            return 0;
        }

        private void Query(Socket socket, string name)
        {
            ushort id;
            lock (Random)
                id = (ushort)Random.Next(0x10000);
            var targets = _targets?.Where(t => t.AddressFamily == socket.AddressFamily)
                ?? new[] { new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? GroupV4 : GroupV6, Port) };
            ushort type = socket.AddressFamily == AddressFamily.InterNetwork ? DnsMessage.TypeA : DnsMessage.TypeAaaa;
            byte[] query = DnsMessage.BuildQuery(id, name, type, DnsMessage.ClassIn | DnsMessage.UnicastResponse, false);
            foreach (var target in targets)
            {
                try
                {
                    socket.SendTo(query, target);
                }
                catch (SocketException)
                {
                    // an interface of no route to the group
                }
            }
        }

        private static async Task ReceiveAsync(Socket socket, string name, TaskCompletionSource<IPAddress> answered, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[9000];
            var any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            while (!cancellationToken.IsCancellationRequested && !answered.Task.IsCompleted)
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

                // any ID: a responder answers a query of a port of its own of its ID, one of multicast of 0
                var records = DnsMessage.ParseResponse(buffer, result.ReceivedBytes, null, out int rcode);
                if (records == null || rcode != 0)
                    continue;
                foreach (var record in records)
                {
                    if (!string.Equals(record.Name, name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                        continue;
                    var address = record.GetAddress(buffer);
                    if (address != null)
                    {
                        answered.TrySetResult(address);
                        return;
                    }
                }
            }
        }
    }
}
