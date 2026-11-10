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

using SharpDTLS.UDP;
using SharpStunCommon;
using System;
using System.Net;
using System.Net.Sockets;

namespace SharpStunServer
{
    /// <summary>
    /// The datagrams of a socket a DTLS listener shares among its peers, as SharpDTLS's server reads and writes them: those
    /// the listener's reader hands it, of each peer, and the server's own sent to the peer. Safe of any thread, as the server
    /// retransmits of its timers.
    /// </summary>
    internal sealed class DtlsServerTransport : IServerTransport
    {
        private readonly UdpSender _sender;

        public DtlsServerTransport(UdpSender sender) => _sender = sender;

        public event EventHandler<byte[]> OnDataReceived;

        /// <summary>A datagram of the peer's, an array of its own, to the server: of the listener's one loop.</summary>
        public void Deliver(IPEndPoint from, byte[] datagram) => OnDataReceived?.Invoke(from, datagram);

        public void Send(EndPoint endpoint, byte[] buf)
        {
            try
            {
                _sender.SendTo(buf, 0, buf.Length, (IPEndPoint)endpoint);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException)
            {
                // a datagram lost, as of UDP: a handshake's flight is retransmitted
            }
        }
    }
}
