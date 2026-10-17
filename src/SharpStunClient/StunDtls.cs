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
        // of an IPv4 path of a link of 1500 bytes: what a record is to fit in, unfragmented (RFC 6347 4.1.1)
        internal const int Mtu = 1472;
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

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default)
        {
            _dtls.Send(message, 0, message.Length);
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
                    else if (count >= 4 && IsChannelData(buffer[0]))
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

    /// <summary>
    /// A DTLS 1.2 server of an X.509 certificate of .NET's, its private key exportable: of RSA, or of ECDSA, its cipher suites
    /// of ECDHE of that key.
    /// </summary>
    internal sealed class DtlsStunServer : DefaultTlsServer
    {
        private readonly DtlsCredentials _credentials;
        private readonly int _timeout;

        public DtlsStunServer(TlsCrypto crypto, DtlsCredentials credentials, int timeout) : base(crypto)
        {
            _credentials = credentials;
            _timeout = timeout;
        }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        public override int GetHandshakeTimeoutMillis() => _timeout;

        protected override int[] GetSupportedCipherSuites() => _credentials.IsEcdsa
            ? new[]
            {
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            }
            : new[]
            {
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            };

        protected override TlsCredentialedSigner GetRsaSignerCredentials() => Signer(SignatureAlgorithm.rsa);

        protected override TlsCredentialedSigner GetECDsaSignerCredentials() => Signer(SignatureAlgorithm.ecdsa);

        // of the client's signature algorithms, the first of the key's, of SHA-256 if it has it
        private TlsCredentialedSigner Signer(short signature)
        {
            var offered = m_context.SecurityParameters.ClientSigAlgs ?? new List<SignatureAndHashAlgorithm>();
            var chosen = offered.Where(a => a.Signature == signature).OrderBy(a => a.Hash == HashAlgorithm.sha256 ? 0 : 1).FirstOrDefault()
                ?? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, signature);
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _credentials.PrivateKey, _credentials.Certificate, chosen);
        }
    }

    /// <summary>A certificate of .NET's as BouncyCastle has it: its chain, and its private key.</summary>
    internal sealed class DtlsCredentials
    {
        public Certificate Certificate { get; set; }
        public AsymmetricKeyParameter PrivateKey { get; set; }
        public bool IsEcdsa { get; set; }
    }

    internal static class DtlsCertificates
    {
        /// <summary>The certificate and its private key, of a PKCS #12 export of it: its key is to be exportable.</summary>
        /// <exception cref="ArgumentException">Of no private key, or of one that is not exportable.</exception>
        public static DtlsCredentials Load(TlsCrypto crypto, X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("A certificate of DTLS is of its private key.", nameof(certificate));
            byte[] pfx;
            const string Password = "dtls";
            try
            {
                pfx = certificate.Export(X509ContentType.Pkcs12, Password);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new ArgumentException("A certificate of DTLS is of an exportable private key: of X509KeyStorageFlags.Exportable.", nameof(certificate), ex);
            }

            var store = new Pkcs12StoreBuilder().Build();
            using (var stream = new MemoryStream(pfx))
                store.Load(stream, Password.ToCharArray());
            string alias = store.Aliases.First(a => store.IsKeyEntry(a));
            var key = store.GetKey(alias).Key;
            var chain = store.GetCertificateChain(alias).Select(e => crypto.CreateCertificate(e.Certificate.GetEncoded())).ToArray();
            return new DtlsCredentials
            {
                Certificate = new Certificate(chain),
                PrivateKey = key,
                IsEcdsa = key is Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters,
            };
        }

        /// <summary>
        /// Whether a server's certificate is to be taken: of the system's chain, and of the host name - of a DNS name of its
        /// subject alternative names, a wildcard the leftmost label, or of an IP address of them; or of its common name, of
        /// none - as SslStream checks one (RFC 6125); of a callback given, as it says, told of what failed.
        /// </summary>
        public static bool Validate(Certificate chain, string host, RemoteCertificateValidationCallback validation, object sender)
        {
            if (chain == null || chain.IsEmpty)
                return false;
            var certificates = Enumerable.Range(0, chain.Length).Select(i => new X509Certificate2(chain.GetCertificateAt(i).GetEncoded())).ToList();
            var leaf = certificates[0];
            var errors = SslPolicyErrors.None;
            using (var x509Chain = new X509Chain())
            {
                x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                foreach (var intermediate in certificates.Skip(1))
                    x509Chain.ChainPolicy.ExtraStore.Add(intermediate);
                if (!x509Chain.Build(leaf))
                    errors |= SslPolicyErrors.RemoteCertificateChainErrors;
                if (!MatchesHost(chain.GetCertificateAt(0).GetEncoded(), host))
                    errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                return validation != null ? validation(sender, leaf, x509Chain, errors) : errors == SslPolicyErrors.None;
            }
        }

        internal static bool MatchesHost(byte[] encoded, string host)
        {
            var certificate = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(encoded);
            bool isAddress = IPAddress.TryParse(host, out IPAddress address);
            var names = certificate.GetSubjectAlternativeNames();
            bool anyDns = false;
            if (names != null)
            {
                foreach (var name in names)
                {
                    int type = Convert.ToInt32(name[0]);
                    string value = name[1] as string;
                    if (type == GeneralName.DnsName && value != null)
                    {
                        anyDns = true;
                        if (!isAddress && MatchesDnsName(value, host))
                            return true;
                    }
                    else if (type == GeneralName.IPAddress && value != null && isAddress && IPAddress.TryParse(value, out IPAddress named) && named.Equals(address))
                    {
                        return true;
                    }
                }
            }
            if (anyDns || isAddress)
                return false;
            // of no DNS name, its common name (RFC 6125 6.4.4)
            var commonNames = certificate.SubjectDN.GetValueList(X509Name.CN);
            return commonNames.Any(cn => MatchesDnsName(cn, host));
        }

        private static bool MatchesDnsName(string pattern, string host)
        {
            pattern = pattern.TrimEnd('.');
            host = host.TrimEnd('.');
            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                int dot = host.IndexOf('.');
                return dot > 0 && string.Equals(pattern.Substring(1), host.Substring(dot), StringComparison.OrdinalIgnoreCase);
            }
            return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>The datagrams of a socket connected to the peer, as BouncyCastle's DTLS reads and writes them.</summary>
    internal sealed class SocketDatagramTransport : DatagramTransport
    {
        private readonly Socket _socket;

        public SocketDatagramTransport(Socket socket) => _socket = socket;

        public int GetReceiveLimit() => ushort.MaxValue;

        public int GetSendLimit() => StunDtlsTransport.Mtu - 28;

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            try
            {
                if (!_socket.Poll(Math.Max(1, waitMillis) * 1000, SelectMode.SelectRead))
                    return -1;
                return _socket.Receive(buf, off, len, SocketFlags.None);
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

        public void Close()
        {
        }
    }

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

        public int GetSendLimit() => StunDtlsTransport.Mtu - 28;

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
