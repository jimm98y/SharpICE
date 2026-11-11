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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpSTUN
{
    /// <summary>Endpoints as STUN tells them apart: an IPv4 address mapped to IPv6, of a dual socket, as the IPv4 address it is.</summary>
    internal static class EndPoints
    {
        public static IPEndPoint Normalize(IPEndPoint endPoint)
            => endPoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port) : endPoint;
    }

    /// <summary>
    /// The datagrams of a UDP socket, one read at a time - of one loop - and whom each is of. Of .NET 8 and later, of no
    /// allocation: the sender's address read into one <see cref="SocketAddress"/>, the endpoint of each sender made once and
    /// kept. Else of the socket's own ReceiveFromAsync, an endpoint of each datagram.
    /// </summary>
    internal sealed class UdpReceiver
    {
        // the senders kept: past these, forgotten all, as of a server of many clients
        private const int MaxEndPoints = 4096;

        private readonly Socket _socket;
        private readonly IPEndPoint _any;
#if NET8_0_OR_GREATER
        private readonly SocketAddress _address;
        private readonly Dictionary<SocketAddress, IPEndPoint> _endPoints = new Dictionary<SocketAddress, IPEndPoint>();
#else
        private IPEndPoint _from;
#endif

        public UdpReceiver(Socket socket)
        {
            _socket = socket;
            _any = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
#if NET8_0_OR_GREATER
            _address = new SocketAddress(socket.AddressFamily);
#endif
        }

#if NET8_0_OR_GREATER
        /// <summary>A datagram into the buffer: its length; whom of, <see cref="RemoteEndPoint"/>.</summary>
        public ValueTask<int> ReceiveAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
            => _socket.ReceiveFromAsync(buffer.AsMemory(offset, count), SocketFlags.None, _address, cancellationToken);

        /// <summary>The sender of the last datagram, normalized: one instance of each sender.</summary>
        public IPEndPoint RemoteEndPoint
        {
            get
            {
                if (_endPoints.TryGetValue(_address, out var endPoint))
                    return endPoint;
                if (_endPoints.Count >= MaxEndPoints)
                    _endPoints.Clear();
                var key = new SocketAddress(_address.Family, _address.Size);
                _address.Buffer.Span.Slice(0, _address.Size).CopyTo(key.Buffer.Span);
                endPoint = EndPoints.Normalize((IPEndPoint)_any.Create(key));
                _endPoints[key] = endPoint;
                return endPoint;
            }
        }
#else
        /// <summary>A datagram into the buffer: its length; whom of, <see cref="RemoteEndPoint"/>.</summary>
        public async Task<int> ReceiveAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            var result = await _socket.ReceiveFromAsync(new ArraySegment<byte>(buffer, offset, count), SocketFlags.None, _any).ConfigureAwait(false);
            _from = EndPoints.Normalize((IPEndPoint)result.RemoteEndPoint);
            return result.ReceivedBytes;
        }

        /// <summary>The sender of the last datagram, normalized.</summary>
        public IPEndPoint RemoteEndPoint => _from;
#endif
    }

    /// <summary>
    /// Datagrams of a UDP socket to its peers: of .NET 8 and later, of each peer's <see cref="SocketAddress"/> made once and kept,
    /// of no allocation of each datagram. Safe of any thread.
    /// </summary>
    internal sealed class UdpSender
    {
        private const int MaxAddresses = 4096;

        private readonly Socket _socket;
#if NET8_0_OR_GREATER
        private readonly Dictionary<IPEndPoint, SocketAddress> _addresses = new Dictionary<IPEndPoint, SocketAddress>();
#endif

        public UdpSender(Socket socket) => _socket = socket;

        public Socket Socket => _socket;

        public int SendTo(byte[] buffer, int offset, int count, IPEndPoint to)
        {
#if NET8_0_OR_GREATER
            return _socket.SendTo(buffer.AsSpan(offset, count), SocketFlags.None, AddressOf(to));
#else
            return _socket.SendTo(buffer, offset, count, SocketFlags.None, to);
#endif
        }

#if NET8_0_OR_GREATER
        public int SendTo(ReadOnlySpan<byte> data, IPEndPoint to) => _socket.SendTo(data, SocketFlags.None, AddressOf(to));

        private SocketAddress AddressOf(IPEndPoint to)
        {
            lock (_addresses)
            {
                if (_addresses.TryGetValue(to, out var address))
                    return address;
                if (_addresses.Count >= MaxAddresses)
                    _addresses.Clear();
                // of a dual socket, an IPv4 address as the IPv6 one it is mapped to, as SendTo of an endpoint has it
                var endPoint = _socket.AddressFamily == AddressFamily.InterNetworkV6 && to.AddressFamily == AddressFamily.InterNetwork
                    ? new IPEndPoint(to.Address.MapToIPv6(), to.Port)
                    : to;
                address = endPoint.Serialize();
                _addresses[to] = address;
                return address;
            }
        }
#endif
    }
}
