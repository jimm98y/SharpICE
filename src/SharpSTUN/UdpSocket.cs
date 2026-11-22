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
        private sealed class Peer
        {
            internal readonly IPEndPoint EndPoint;
            internal readonly SocketAddress Address;
            internal Peer(IPEndPoint endPoint, SocketAddress address) { EndPoint = endPoint; Address = address; }
        }

        private readonly Dictionary<IPEndPoint, Peer> _addresses = new Dictionary<IPEndPoint, Peer>();
        // the peer of the last datagram, read without the lock: a socket sends to its selected pair's peer above all
        private volatile Peer _last;
#endif

        public UdpSender(Socket socket) => _socket = socket;

        public Socket Socket => _socket;

        public int SendTo(byte[] buffer, int offset, int count, IPEndPoint to)
        {
#if NET8_0_OR_GREATER
            return SendTo(buffer.AsSpan(offset, count), to);
#else
            return _socket.SendTo(buffer, offset, count, SocketFlags.None, to);
#endif
        }

        /// <summary>
        /// Datagrams of <paramref name="segment"/> bytes each, the last of what is left, back to back in the buffer: of one send
        /// the system splits, of UDP segmentation offload - Windows 10 2004 (build 19041) and later, of UDP_SEND_MSG_SIZE, and
        /// Linux 4.18 and later, of UDP_SEGMENT, set of the socket's options - or of a send of each, of any other system, of
        /// .NET before 8, or of a socket of which the option or such a send ever failed.
        /// </summary>
        public void SendSegments(byte[] buffer, int offset, int count, int segment, IPEndPoint to)
        {
#if NET8_0_OR_GREATER
            if (Segmentation && !_unsegmented && count > segment)
            {
                lock (_segmentGate)
                {
                    if (!_unsegmented)
                    {
                        try
                        {
                            if (_segment != segment)
                                SetSegment(segment);
                            _socket.SendTo(buffer.AsSpan(offset, count), SocketFlags.None, AddressOf(to));
                            return;
                        }
                        catch (SocketException)
                        {
                            // not of this socket, or of its interface: of a send of each from now on
                            _unsegmented = true;
                            try { SetSegment(0); } catch (SocketException) { }
                        }
                    }
                }
            }
#endif
            for (int at = 0; at < count; at += segment)
                SendTo(buffer, offset + at, Math.Min(segment, count - at), to);
        }

#if NET8_0_OR_GREATER
        // of the systems of segmentation offload, of their versions
        private static readonly bool Segmentation = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)
            || (OperatingSystem.IsLinux() && Environment.OSVersion.Version >= new Version(4, 18));
        // the segment size the socket has, 0 of none; of a socket of which it ever failed, a send of each. A send of more than the
        //  size would be split of it, so of a system of segmentation each send is of the gate, and such a send puts it back to 0
        private readonly object _segmentGate = new object();
        private int _segment;
        private volatile bool _unsegmented;

        private void SetSegment(int segment)
        {
            if (OperatingSystem.IsWindows())
                _socket.SetSocketOption(SocketOptionLevel.Udp, (SocketOptionName)2, segment); // UDP_SEND_MSG_SIZE
            else
                _socket.SetRawSocketOption(17, 103, BitConverter.GetBytes(segment)); // SOL_UDP, UDP_SEGMENT
            _segment = segment;
        }

        public int SendTo(ReadOnlySpan<byte> data, IPEndPoint to)
        {
            if (!Segmentation)
                return _socket.SendTo(data, SocketFlags.None, AddressOf(to));
            lock (_segmentGate)
            {
                if (_segment != 0 && data.Length > _segment)
                {
                    try { SetSegment(0); } catch (SocketException) { _unsegmented = true; }
                }
                return _socket.SendTo(data, SocketFlags.None, AddressOf(to));
            }
        }

        private SocketAddress AddressOf(IPEndPoint to)
        {
            var last = _last;
            if (last != null && (ReferenceEquals(last.EndPoint, to) || last.EndPoint.Equals(to)))
                return last.Address;
            lock (_addresses)
            {
                if (!_addresses.TryGetValue(to, out var peer))
                {
                    if (_addresses.Count >= MaxAddresses)
                        _addresses.Clear();
                    // of a dual socket, an IPv4 address as the IPv6 one it is mapped to, as SendTo of an endpoint has it
                    var endPoint = _socket.AddressFamily == AddressFamily.InterNetworkV6 && to.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(to.Address.MapToIPv6(), to.Port)
                        : to;
                    peer = new Peer(to, endPoint.Serialize());
                    _addresses[to] = peer;
                }
                _last = peer;
                return peer.Address;
            }
        }
#endif
    }
}
