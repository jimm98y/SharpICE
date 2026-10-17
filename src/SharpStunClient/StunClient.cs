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
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>
    /// A STUN client of the Binding method (RFC 8489): what address and port a STUN server sees a socket's requests come from -
    /// the address a NAT maps it to.
    /// </summary>
    public static class StunClient
    {
        public const int DefaultPort = 3478;

        /// <summary>
        /// The endpoint of a STUN server of "host", "host:port", "stun:host:port" or "[ipv6]:port", of the address family given.
        /// Null of one that does not resolve.
        /// </summary>
        public static async Task<IPEndPoint> ResolveAsync(string server, AddressFamily family = AddressFamily.InterNetwork)
        {
            if (string.IsNullOrWhiteSpace(server))
                return null;
            string text = server.Trim();
            if (text.StartsWith("stun:", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(5);

            string host = text;
            int port = DefaultPort;
            if (text.StartsWith("[", StringComparison.Ordinal))
            {
                int end = text.IndexOf(']');
                if (end < 0)
                    return null;
                host = text.Substring(1, end - 1);
                if (end + 2 < text.Length && text[end + 1] == ':')
                    port = int.Parse(text.Substring(end + 2), CultureInfo.InvariantCulture);
            }
            else
            {
                int colon = text.LastIndexOf(':');
                if (colon > 0 && text.IndexOf(':') == colon)
                {
                    host = text.Substring(0, colon);
                    port = int.Parse(text.Substring(colon + 1), CultureInfo.InvariantCulture);
                }
            }

            if (IPAddress.TryParse(host, out IPAddress address))
                return address.AddressFamily == family ? new IPEndPoint(address, port) : null;

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                var match = addresses.FirstOrDefault(a => a.AddressFamily == family);
                return match == null ? null : new IPEndPoint(match, port);
            }
            catch (SocketException)
            {
                return null;
            }
        }

        /// <summary>A Binding request (RFC 8489 6.1), of a new transaction ID.</summary>
        public static StunMessage CreateBindingRequest(string software = null)
        {
            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request);
            if (software != null)
                request.AddString(StunAttributeType.Software, software);
            return request;
        }

        /// <summary>
        /// The address a server sees a Binding request come from: of its XOR-MAPPED-ADDRESS, or of a server of RFC 3489, its
        /// MAPPED-ADDRESS. Null of a message that is no success response, or has neither.
        /// </summary>
        public static IPEndPoint GetMappedAddress(StunMessage response)
        {
            if (response == null || response.Class != StunMessageClass.SuccessResponse)
                return null;
            return response.GetXorAddress() ?? response.MappedAddress;
        }

        /// <summary>
        /// Sends a Binding request from a socket of its own to the server and waits for its answer, retransmitting it (RFC 8489
        /// 6.2.1) until the time given is up. The mapped address; null of no answer.
        /// </summary>
        public static async Task<IPEndPoint> GetMappedAddressAsync(IPEndPoint server, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            using (var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                return await GetMappedAddressAsync(socket, server, timeout, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Sends a Binding request from a bound socket - one nothing else reads at the time - to the server and waits for its
        /// answer. The mapped address; null of no answer.
        /// </summary>
        public static async Task<IPEndPoint> GetMappedAddressAsync(Socket socket, IPEndPoint server, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            var request = CreateBindingRequest();
            byte[] bytes = request.ToBytes();
            byte[] buffer = new byte[1500];
            DateTime deadline = DateTime.UtcNow + timeout;
            TimeSpan rto = TimeSpan.FromMilliseconds(250);

            // one receive at a time, kept across the retransmissions: one left behind would take a datagram of its own
            Task<SocketReceiveFromResult> receive = null;
            var any = new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
            {
                socket.SendTo(bytes, server);
                TimeSpan wait = TimeSpan.FromTicks(Math.Min(rto.Ticks, (deadline - DateTime.UtcNow).Ticks));
                DateTime until = DateTime.UtcNow + wait;
                while (DateTime.UtcNow < until)
                {
                    receive ??= socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any);
                    TimeSpan left = until - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero)
                        break;
                    var completed = await Task.WhenAny(receive, Task.Delay(left, cancellationToken)).ConfigureAwait(false);
                    if (completed != receive)
                        break;

                    SocketReceiveFromResult result;
                    try
                    {
                        result = await receive.ConfigureAwait(false);
                    }
                    catch (SocketException)
                    {
                        // an ICMP port unreachable of a request before, reported by Windows as a reset
                        receive = null;
                        continue;
                    }
                    receive = null;

                    var response = StunMessage.Parse(buffer, 0, result.ReceivedBytes);
                    if (response != null && response.IsTransaction(request) && (!response.HasFingerprint || response.VerifyFingerprint()))
                        return GetMappedAddress(response);
                }
                rto = TimeSpan.FromTicks(rto.Ticks * 2);
            }
            return null;
        }
    }
}
