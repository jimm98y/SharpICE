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

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SharpStunCommon;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>
    /// STUN over DTLS (RFC 8489 6.2.3): a STUN message in each record of a DTLS 1.2 association of the server's, its certificate
    /// checked as one of TLS is - of the host name given, of the system's checks or of a callback's. Requests over it are
    /// retransmitted, as over UDP.
    /// </summary>
    public sealed class StunDtlsTransport : StunTransport
    {
        private static readonly int HandshakeTimeout = 10000;

        private readonly Socket _socket;
        private readonly DtlsTransport _dtls;
        private readonly string _host;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly Thread _receiver;
        private volatile bool _closed;

        private StunDtlsTransport(Socket socket, DtlsTransport dtls, IPEndPoint server, string host, RemoteCertificateValidationCallback validation)
        {
            _socket = socket;
            _dtls = dtls;
            _host = host;
            _validation = validation;
            RemoteEndPoint = server;
            _receiver = new Thread(Receive) { IsBackground = true, Name = "STUN over DTLS" };
            _receiver.Start();
        }

        /// <summary>
        /// The association of a handshake with the server: its certificate checked of the host name, or of the callback given
        /// rather than the system's checks.
        /// </summary>
        /// <exception cref="IOException">Of a handshake that failed, as of a certificate refused.</exception>
        public static async Task<StunDtlsTransport> ConnectAsync(IPEndPoint server, string host, RemoteCertificateValidationCallback validation = null, CancellationToken cancellationToken = default)
        {
            if (host == null)
                throw new ArgumentNullException(nameof(host));
            var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                socket.Connect(server);
                var client = new DtlsStunClient(new BcTlsCrypto(new SecureRandom()), host, validation, HandshakeTimeout);
                var datagrams = new SocketDatagramTransport(socket);
                using (cancellationToken.Register(() => socket.Dispose()))
                {
                    var dtls = await Task.Run(() => new DtlsClientProtocol().Connect(client, datagrams), cancellationToken).ConfigureAwait(false);
                    return new StunDtlsTransport(socket, dtls, server, host, validation);
                }
            }
            catch (Exception ex) when (ex is TlsException || ex is IOException || ex is ObjectDisposedException)
            {
                socket.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
                throw ex as IOException ?? new IOException("The DTLS handshake failed: " + ex.Message, ex);
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
            _dtls.Send(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override async Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
            => await ConnectAsync(server, domain ?? _host, _validation, cancellationToken).ConfigureAwait(false);

        private void Receive()
        {
            byte[] buffer = new byte[ushort.MaxValue];
            Exception error = null;
            try
            {
                while (!_closed)
                {
                    int count = _dtls.Receive(buffer, 0, buffer.Length, 1000);
                    if (count < 0)
                        continue;
                    var message = StunMessage.Parse(buffer, 0, count);
                    if (message != null)
                        OnMessageReceived(message, RemoteEndPoint);
                    else if (count >= 4 && StunFraming.IsChannelData(buffer[0]))
                        OnDataReceived(buffer, 0, count);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException || ex is SocketException)
            {
                error = ex;
            }
            if (!_closed)
                OnClosed(error);
        }

        public override void Dispose()
        {
            if (_closed)
                return;
            _closed = true;
            try
            {
                // its close_notify
                _dtls.Close();
            }
            catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException || ex is SocketException)
            {
            }
            _socket.Dispose();
        }
    }

    /// <summary>A DTLS 1.2 client of the server's name, of SNI, its certificate checked as <see cref="DtlsCertificates.Validate"/> checks it.</summary>
    internal sealed class DtlsStunClient : DefaultTlsClient
    {
        private readonly string _host;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly int _timeout;

        public DtlsStunClient(TlsCrypto crypto, string host, RemoteCertificateValidationCallback validation, int timeout) : base(crypto)
        {
            _host = host;
            _validation = validation;
            _timeout = timeout;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        protected override IList<ServerName> GetSniServerNames()
        {
            // a name, not an address (RFC 6066 3)
            if (IPAddress.TryParse(_host, out _))
                return null;
            return new List<ServerName> { new ServerName(NameType.host_name, System.Text.Encoding.ASCII.GetBytes(_host)) };
        }

        public override int GetHandshakeTimeoutMillis() => _timeout;

        public override TlsAuthentication GetAuthentication() => new Authentication(this);

        private sealed class Authentication : TlsAuthentication
        {
            private readonly DtlsStunClient _client;

            public Authentication(DtlsStunClient client) => _client = client;

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                if (!DtlsCertificates.Validate(serverCertificate.Certificate, _client._host, _client._validation, _client))
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;
        }
    }

    /// <summary>The datagrams of a socket connected to the peer, as BouncyCastle's DTLS reads and writes them.</summary>
    internal sealed class SocketDatagramTransport : DatagramTransport
    {
        private readonly Socket _socket;

        public SocketDatagramTransport(Socket socket) => _socket = socket;

        public int GetReceiveLimit() => ushort.MaxValue;

        public int GetSendLimit() => DtlsDefaults.Mtu - 28;

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
#if NETCOREAPP
            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public int Receive(Span<byte> buffer, int waitMillis)
        {
#endif
            try
            {
                if (!_socket.Poll(Math.Max(1, waitMillis) * 1000, SelectMode.SelectRead))
                    return -1;
#if NETCOREAPP
                return _socket.Receive(buffer, SocketFlags.None);
#else
                return _socket.Receive(buf, off, len, SocketFlags.None);
#endif
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // an ICMP port unreachable, as the socket is connected: no server there, as of a TCP connection refused
                throw new IOException("The server's port is unreachable.", ex);
            }
            catch (SocketException)
            {
                return -1;
            }
        }

        public void Send(byte[] buf, int off, int len) => _socket.Send(buf, off, len, SocketFlags.None);

#if NETCOREAPP
        public void Send(ReadOnlySpan<byte> buffer) => _socket.Send(buffer, SocketFlags.None);
#endif

        public void Close()
        {
        }
    }
}
