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
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>
    /// STUN over DTLS (RFC 8489 6.2.3): a STUN message in each record of a DTLS association of the server's, of a DTLS stack -
    /// SharpDTLS's, the default, of DTLS 1.3 and 1.2, or BouncyCastle's, of DTLS 1.2 - its certificate checked as one of TLS
    /// is: of the host name given, of the system's checks or of a callback's. Requests over it are retransmitted, as over UDP.
    /// </summary>
    public sealed class StunDtlsTransport : StunTransport
    {
        private readonly Socket _socket;
        private readonly string _host;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly IDtlsStack _stack;
        private IDtlsAssociation _dtls;
        private volatile bool _closed;

        private StunDtlsTransport(Socket socket, IPEndPoint server, string host, RemoteCertificateValidationCallback validation, IDtlsStack stack)
        {
            _socket = socket;
            _host = host;
            _validation = validation;
            _stack = stack;
            RemoteEndPoint = server;
        }

        /// <summary>The DTLS stack the association is of.</summary>
        public IDtlsStack Stack => _stack;

        /// <summary>The version negotiated, as on the wire: 0xFEFD of DTLS 1.2, 0xFEFC of DTLS 1.3.</summary>
        public ushort NegotiatedVersion => _dtls.NegotiatedVersion;

        /// <summary>
        /// The association of a handshake with the server, of the default DTLS stack: its certificate checked of the host
        /// name, or of the callback given rather than the system's checks.
        /// </summary>
        /// <exception cref="IOException">Of a handshake that failed, as of a certificate refused.</exception>
        public static Task<StunDtlsTransport> ConnectAsync(IPEndPoint server, string host, RemoteCertificateValidationCallback validation = null, CancellationToken cancellationToken = default)
            => ConnectAsync(server, host, validation, null, cancellationToken);

        /// <summary>The association of a handshake with the server, of the DTLS stack given: of null, <see cref="DtlsStacks.Default"/>.</summary>
        /// <exception cref="IOException">Of a handshake that failed, as of a certificate refused.</exception>
        public static async Task<StunDtlsTransport> ConnectAsync(IPEndPoint server, string host, RemoteCertificateValidationCallback validation, IDtlsStack stack, CancellationToken cancellationToken = default)
        {
            if (host == null)
                throw new ArgumentNullException(nameof(host));
            stack ??= DtlsStacks.Default;
            var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                socket.Connect(server);
                var transport = new StunDtlsTransport(socket, server, host, validation, stack);
                transport._dtls = await stack.ConnectAsync(socket, new DtlsClientSettings
                {
                    ServerName = host,
                    ValidateServerCertificate = chain => DtlsCertificates.Validate(chain, host, validation, transport),
                    RecordReceived = transport.OnRecord,
                    Closed = transport.OnEnded,
                }, cancellationToken).ConfigureAwait(false);
                return transport;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public override bool IsReliable => false;

        public override IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint;

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default) => SendAsync(message, 0, message.Length, cancellationToken);

        public override Task SendAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_closed)
                throw new IOException("The DTLS association ended.");
            _dtls.Send(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override async Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
            => await ConnectAsync(server, domain ?? _host, _validation, _stack, cancellationToken).ConfigureAwait(false);

        // a record's data: a STUN message, or of TURN, ChannelData
        private void OnRecord(byte[] buffer, int offset, int count)
        {
            if (_closed)
                return;
            var message = StunMessage.Parse(buffer, offset, count);
            if (message != null)
                OnMessageReceived(message, RemoteEndPoint);
            else if (count >= 4 && StunFraming.IsChannelData(buffer[offset]))
                OnDataReceived(buffer, offset, count);
        }

        // the association ended of the server's close_notify, of an alert, or of its port unreachable
        private void OnEnded(Exception error)
        {
            if (_closed)
                return;
            _closed = true;
            _socket.Dispose();
            OnClosed(error);
        }

        public override void Dispose()
        {
            if (_closed)
                return;
            _closed = true;
            _dtls?.Dispose();
            _socket.Dispose();
        }
    }
}
