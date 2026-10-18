// SharpStunServer
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

using Org.BouncyCastle.Tls;
using SharpStunCommon;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace SharpStunServer
{
    /// <summary>
    /// The datagrams of one peer of a socket a server shares among its peers: those the server's reader hands it, queued - each
    /// in a buffer of a pool, its own again once read - and its own sent to the peer.
    /// </summary>
    internal sealed class QueuedDatagramTransport : DatagramTransport, DatagramSender
    {
        private readonly UdpSender _sender;
        private readonly IPEndPoint _remote;
        private readonly BlockingCollection<ArraySegment<byte>> _received = new BlockingCollection<ArraySegment<byte>>(64);

        public QueuedDatagramTransport(UdpSender sender, IPEndPoint remote)
        {
            _sender = sender;
            _remote = remote;
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)_sender.Socket.LocalEndPoint;

        public DateTime LastReceived { get; private set; } = DateTime.UtcNow;

        /// <summary>A datagram of the peer's, copied; false of one dropped, of a queue full.</summary>
        public bool Enqueue(byte[] buffer, int offset, int count)
        {
            LastReceived = DateTime.UtcNow;
            byte[] datagram = ArrayPool<byte>.Shared.Rent(count);
            Buffer.BlockCopy(buffer, offset, datagram, 0, count);
            try
            {
                if (_received.TryAdd(new ArraySegment<byte>(datagram, 0, count)))
                    return true;
            }
            catch (InvalidOperationException)
            {
            }
            ArrayPool<byte>.Shared.Return(datagram);
            return false;
        }

        public int GetReceiveLimit() => ushort.MaxValue;

        public int GetSendLimit() => DtlsDefaults.Mtu - 28;

        public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(new Span<byte>(buf, off, len), waitMillis);

#if NETCOREAPP
        public int Receive(Span<byte> buffer, int waitMillis)
#else
        private int Receive(Span<byte> buffer, int waitMillis)
#endif
        {
            ArraySegment<byte> datagram;
            try
            {
                if (!_received.TryTake(out datagram, waitMillis))
                    return -1;
            }
            catch (Exception ex) when (ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                throw new IOException("The peer's datagrams ended.", ex);
            }
            int count = Math.Min(buffer.Length, datagram.Count);
            datagram.AsSpan(0, count).CopyTo(buffer);
            ArrayPool<byte>.Shared.Return(datagram.Array);
            return count;
        }

        public void Send(byte[] buf, int off, int len) => _sender.SendTo(buf, off, len, _remote);

#if NET8_0_OR_GREATER
        public void Send(ReadOnlySpan<byte> buffer) => _sender.SendTo(buffer, _remote);
#endif

        public void Close() => _received.CompleteAdding();
    }
}
