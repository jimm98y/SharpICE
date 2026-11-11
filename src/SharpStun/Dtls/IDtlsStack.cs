// SharpStun
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
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStun
{
    /// <summary>
    /// A DTLS implementation STUN and TURN run over (RFC 8489 6.2.3, RFC 7350), of no type of its library's own in what it
    /// takes and gives: <see cref="SharpDtlsStack"/>, the default - DTLS 1.3 and 1.2 - or <see cref="BcDtlsStack"/>, of
    /// BouncyCastle - DTLS 1.2 alone.
    /// </summary>
    public interface IDtlsStack
    {
        /// <summary>The name of the implementation, as traces tell of it.</summary>
        string Name { get; }

        /// <summary>
        /// A client's association with the server a UDP socket is connected to, of a handshake: the socket the association's
        /// own from then on, read of it, and closed with it.
        /// </summary>
        /// <exception cref="System.IO.IOException">Of a handshake that failed, timed out, or of a certificate refused.</exception>
        Task<IDtlsAssociation> ConnectAsync(Socket socket, DtlsClientSettings settings, CancellationToken cancellationToken = default);

        /// <summary>
        /// A server of the peers of one UDP socket, of a cookie exchange of each before any state of it (RFC 6347 4.2.1, RFC
        /// 9147 5.1): the datagrams of the socket handed to it of <see cref="IDtlsServer.Receive"/>, its own sent of the
        /// settings' sender.
        /// </summary>
        IDtlsServer CreateServer(DtlsServerSettings settings);
    }

    /// <summary>What a client's association is of.</summary>
    public sealed class DtlsClientSettings
    {
        /// <summary>The server's name, of SNI (RFC 6066 3); none, of null or of an address.</summary>
        public string ServerName { get; set; }

        /// <summary>
        /// Whether the server's certificate chain - the DER of each, the server's own first - is to be taken; of none, any is.
        /// </summary>
        public Func<IReadOnlyList<byte[]>, bool> ValidateServerCertificate { get; set; }

        /// <summary>How long the handshake is given.</summary>
        public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>The data of each record the server sends, once the handshake is done: the buffer the caller's alone while it runs.</summary>
        public Action<byte[], int, int> RecordReceived { get; set; }

        /// <summary>The association ended once established - of the server's close_notify, an alert, or its port unreachable - of the error, or of null.</summary>
        public Action<Exception> Closed { get; set; }
    }

    /// <summary>A client's association of DTLS, established.</summary>
    public interface IDtlsAssociation : IDisposable
    {
        /// <summary>The version negotiated, as on the wire: 0xFEFD of DTLS 1.2, 0xFEFC of DTLS 1.3.</summary>
        ushort NegotiatedVersion { get; }

        /// <summary>The bytes as one record's data, the caller's again once it returns.</summary>
        /// <exception cref="System.IO.IOException">Of an association that ended.</exception>
        void Send(byte[] buffer, int offset, int count);
    }

    /// <summary>What a server of DTLS is of: its certificate, and what it tells of its peers' associations.</summary>
    public sealed class DtlsServerSettings
    {
        /// <summary>The server's certificate, of an exportable private key: of RSA, or of ECDSA.</summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>A datagram to a peer, of the socket: the buffer the caller's again once it returns. Safe of any thread.</summary>
        public Action<IPEndPoint, byte[], int, int> SendDatagram { get; set; }

        /// <summary>How long a peer's handshake is given.</summary>
        public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>A peer's association is established.</summary>
        public Action<IPEndPoint> Established { get; set; }

        /// <summary>The data of each record of a peer's established association: the buffer the caller's alone while it runs.</summary>
        public Action<IPEndPoint, byte[], int, int> RecordReceived { get; set; }

        /// <summary>A peer's association - established, or of its handshake - ended, of the peer or of <see cref="IDtlsServer.Close"/>.</summary>
        public Action<IPEndPoint> Closed { get; set; }
    }

    /// <summary>A server of DTLS of the peers of one UDP socket.</summary>
    public interface IDtlsServer : IDisposable
    {
        /// <summary>A datagram of a peer's, of the socket's one reading loop: the buffer the caller's again once it returns.</summary>
        void Receive(IPEndPoint from, byte[] buffer, int offset, int count);

        /// <summary>Whether the peer has an association - established, or of a handshake past its cookie exchange.</summary>
        bool HasAssociation(IPEndPoint peer);

        /// <summary>The peers of an association, of <see cref="HasAssociation"/>.</summary>
        IReadOnlyCollection<IPEndPoint> Peers { get; }

        /// <summary>How many peers have an association, of <see cref="HasAssociation"/>: of no copy of them.</summary>
        int Count { get; }

        /// <summary>The bytes as one record's data to the peer, the caller's again once it returns.</summary>
        /// <exception cref="System.IO.IOException">Of no established association of the peer's.</exception>
        void Send(IPEndPoint peer, byte[] buffer, int offset, int count);

        /// <summary>Ends the peer's association, of its close_notify.</summary>
        void Close(IPEndPoint peer);
    }

    /// <summary>The DTLS implementations there are.</summary>
    public static class DtlsStacks
    {
        /// <summary>Of SharpDTLS: DTLS 1.3 and 1.2, a fragmented ClientHello reassembled. The default.</summary>
        public static IDtlsStack SharpDtls { get; } = new SharpDtlsStack();

        /// <summary>Of BouncyCastle: DTLS 1.2 alone, a thread of each peer's association of a server's.</summary>
        public static IDtlsStack BouncyCastle { get; } = new BcDtlsStack();

        /// <summary>What a client or server of no other given runs over: <see cref="SharpDtls"/>.</summary>
        public static IDtlsStack Default => SharpDtls;
    }
}
