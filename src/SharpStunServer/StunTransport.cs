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
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace SharpStunServer
{
    /// <summary>
    /// The datagrams of one peer of a socket a server shares among its peers: those the server's reader hands it, queued, and
    /// its own sent to the peer.
    /// </summary>
    internal sealed class QueuedDatagramTransport : DatagramTransport, DatagramSender
    {
        private readonly Socket _socket;
        private readonly EndPoint _remote;
        private readonly BlockingCollection<byte[]> _received = new BlockingCollection<byte[]>(64);

        public QueuedDatagramTransport(Socket socket, EndPoint remote)
        {
            _socket = socket;
            _remote = remote;
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint;

        public DateTime LastReceived { get; private set; } = DateTime.UtcNow;

        /// <summary>A datagram of the peer's; false of one dropped, of a queue full.</summary>
        public bool Enqueue(byte[] datagram)
        {
            LastReceived = DateTime.UtcNow;
            try
            {
                return _received.TryAdd(datagram);
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        public int GetReceiveLimit() => ushort.MaxValue;

        public int GetSendLimit() => DtlsDefaults.Mtu - 28;

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            try
            {
                if (!_received.TryTake(out byte[] datagram, waitMillis))
                    return -1;
                int count = Math.Min(len, datagram.Length);
                Buffer.BlockCopy(datagram, 0, buf, off, count);
                return count;
            }
            catch (Exception ex) when (ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                throw new IOException("The peer's datagrams ended.", ex);
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            byte[] datagram = new byte[len];
            Buffer.BlockCopy(buf, off, datagram, 0, len);
            _socket.SendTo(datagram, _remote);
        }

#if NETCOREAPP
        public int Receive(Span<byte> buffer, int waitMillis)
        {
            byte[] array = new byte[buffer.Length];
            int count = Receive(array, 0, array.Length, waitMillis);
            if (count > 0)
                array.AsSpan(0, count).CopyTo(buffer);
            return count;
        }

        public void Send(ReadOnlySpan<byte> buffer) => Send(buffer.ToArray(), 0, buffer.Length);
#endif

        public void Close() => _received.CompleteAdding();
    }
}
