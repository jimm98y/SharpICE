// SharpICE
// Copyright (C) 2026 Lukas Volf, assisted by Claude Code, assisted by Claude Code
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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunCommon
{
    /// <summary>
    /// DTLS of BouncyCastle: DTLS 1.2 alone, as BouncyCastle has no DTLS 1.3; of ECDHE, of AES-GCM, ChaCha20-Poly1305 or
    /// AES-CBC. Of a server, a thread of each peer's association, and a ClientHello of one record alone, as BouncyCastle's
    /// cookie exchange does not reassemble one fragmented.
    /// </summary>
    public sealed class BcDtlsStack : IDtlsStack
    {
        // of an IPv4 path of a link of 1500 bytes: what a record is to fit in, unfragmented (RFC 6347 4.1.1)
        private const int Mtu = 1472;

        public string Name => "BouncyCastle";

        public async Task<IDtlsAssociation> ConnectAsync(Socket socket, DtlsClientSettings settings, CancellationToken cancellationToken = default)
        {
            if (socket == null)
                throw new ArgumentNullException(nameof(socket));
            settings ??= new DtlsClientSettings();
            var client = new Client(new BcTlsCrypto(new SecureRandom()), settings);
            var datagrams = new SocketDatagramTransport(socket);
            try
            {
                using (cancellationToken.Register(() => socket.Dispose()))
                {
                    var dtls = await Task.Run(() => new DtlsClientProtocol().Connect(client, datagrams), cancellationToken).ConfigureAwait(false);
                    return new Association(dtls, settings, client.NegotiatedVersion);
                }
            }
            catch (Exception ex) when (ex is TlsException || ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw ex as IOException ?? new IOException("The DTLS handshake failed: " + ex.Message, ex);
            }
        }

        public IDtlsServer CreateServer(DtlsServerSettings settings) => new Server(settings ?? throw new ArgumentNullException(nameof(settings)));

        // the credentials of a certificate of .NET's, as BouncyCastle's TLS has them
        private static (Certificate Chain, AsymmetricKeyParameter Key, bool IsEcdsa) Credentials(TlsCrypto crypto, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            var loaded = DtlsCertificates.Load(certificate);
            var chain = new[] { loaded.Certificate }.Concat(loaded.Intermediates).Select(c => crypto.CreateCertificate(c.GetEncoded())).ToArray();
            return (new Certificate(chain), loaded.KeyPair.Private, loaded.KeyPair.Private is ECPrivateKeyParameters);
        }

        private sealed class Association : IDtlsAssociation
        {
            private readonly DtlsTransport _dtls;
            private readonly DtlsClientSettings _settings;
            private readonly Thread _receiver;
            private readonly object _writing = new object();
            private volatile bool _closed;

            public Association(DtlsTransport dtls, DtlsClientSettings settings, ushort version)
            {
                _dtls = dtls;
                _settings = settings;
                NegotiatedVersion = version;
                _receiver = new Thread(Receive) { IsBackground = true, Name = "DTLS of BouncyCastle" };
                _receiver.Start();
            }

            public ushort NegotiatedVersion { get; }

            public void Send(byte[] buffer, int offset, int count)
            {
                if (_closed)
                    throw new IOException("The DTLS association ended.");
                try
                {
                    lock (_writing)
                        _dtls.Send(buffer, offset, count);
                }
                catch (Exception ex) when (ex is TlsException || ex is SocketException || ex is ObjectDisposedException)
                {
                    throw new IOException("The DTLS association ended: " + ex.Message, ex);
                }
            }

            private void Receive()
            {
                byte[] buffer = new byte[ushort.MaxValue];
                Exception error = null;
                try
                {
                    while (!_closed)
                    {
                        int count = _dtls.Receive(buffer, 0, buffer.Length, 1000);
                        if (count >= 0)
                            _settings.RecordReceived?.Invoke(buffer, 0, count);
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException || ex is SocketException)
                {
                    error = ex;
                }
                if (!_closed)
                {
                    _closed = true;
                    _settings.Closed?.Invoke(error);
                }
            }

            public void Dispose()
            {
                if (_closed)
                    return;
                _closed = true;
                try
                {
                    // its close_notify
                    lock (_writing)
                        _dtls.Close();
                }
                catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException || ex is SocketException)
                {
                }
            }
        }

        /// <summary>A DTLS 1.2 client of the server's name, of SNI, its certificate taken of the settings' check.</summary>
        private sealed class Client : DefaultTlsClient
        {
            private readonly DtlsClientSettings _settings;

            public Client(TlsCrypto crypto, DtlsClientSettings settings) : base(crypto) => _settings = settings;

            public ushort NegotiatedVersion { get; private set; }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

            public override void NotifyServerVersion(ProtocolVersion serverVersion)
            {
                base.NotifyServerVersion(serverVersion);
                NegotiatedVersion = (ushort)((serverVersion.MajorVersion << 8) | serverVersion.MinorVersion);
            }

            protected override IList<ServerName> GetSniServerNames()
            {
                // a name, not an address (RFC 6066 3)
                string name = _settings.ServerName;
                if (string.IsNullOrEmpty(name) || IPAddress.TryParse(name, out _))
                    return null;
                return new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(name)) };
            }

            public override int GetHandshakeTimeoutMillis() => (int)_settings.HandshakeTimeout.TotalMilliseconds;

            public override TlsAuthentication GetAuthentication() => new Authentication(_settings);

            private sealed class Authentication : TlsAuthentication
            {
                private readonly DtlsClientSettings _settings;

                public Authentication(DtlsClientSettings settings) => _settings = settings;

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    var certificate = serverCertificate.Certificate;
                    if (certificate == null || certificate.IsEmpty)
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    var chain = Enumerable.Range(0, certificate.Length).Select(i => certificate.GetCertificateAt(i).GetEncoded()).ToList();
                    if (_settings.ValidateServerCertificate != null && !_settings.ValidateServerCertificate(chain))
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) => null;
            }
        }

        /// <summary>The datagrams of a socket connected to the server, as BouncyCastle's DTLS reads and writes them.</summary>
        private sealed class SocketDatagramTransport : DatagramTransport
        {
            private readonly Socket _socket;

            public SocketDatagramTransport(Socket socket) => _socket = socket;

            public int GetReceiveLimit() => ushort.MaxValue;

            public int GetSendLimit() => Mtu - 28;

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

#if NETCOREAPP
            public int Receive(Span<byte> buffer, int waitMillis)
            {
                byte[] bytes = new byte[buffer.Length];
                int count = Receive(bytes, 0, bytes.Length, waitMillis);
                if (count > 0)
                    bytes.AsSpan(0, count).CopyTo(buffer);
                return count;
            }

            public void Send(ReadOnlySpan<byte> buffer) => _socket.Send(buffer, SocketFlags.None);
#endif

            public void Send(byte[] buf, int off, int len) => _socket.Send(buf, off, len, SocketFlags.None);

            public void Close()
            {
            }
        }

        /// <summary>
        /// A server of BouncyCastle's DTLS of the peers of one socket: the cookie exchange of its verifier of each unknown
        /// peer, then a thread of each peer's association, of the datagrams handed to it queued.
        /// </summary>
        private sealed class Server : IDtlsServer
        {
            private readonly DtlsServerSettings _settings;
            private readonly BcTlsCrypto _crypto = new BcTlsCrypto(new SecureRandom());
            private readonly DtlsVerifier _verifier;
            private readonly (Certificate Chain, AsymmetricKeyParameter Key, bool IsEcdsa) _credentials;
            private readonly ConcurrentDictionary<IPEndPoint, Peer> _peers = new ConcurrentDictionary<IPEndPoint, Peer>();

            private sealed class Peer
            {
                public QueuedDatagramTransport Datagrams;
                public volatile DtlsTransport Dtls;
                public readonly object Writing = new object();
            }

            public Server(DtlsServerSettings settings)
            {
                if (settings.Certificate == null)
                    throw new ArgumentException("A server of DTLS takes a certificate.", nameof(settings));
                _settings = settings;
                _verifier = new DtlsVerifier(_crypto);
                _credentials = Credentials(_crypto, settings.Certificate);
            }

            public void Receive(IPEndPoint from, byte[] buffer, int offset, int count)
            {
                if (_peers.TryGetValue(from, out var peer))
                {
                    peer.Datagrams.Enqueue(buffer, offset, count);
                    return;
                }

                // a peer of no association: its ClientHello of the verifier's cookie, else a HelloVerifyRequest of one back
                DtlsRequest request;
                try
                {
                    request = _verifier.VerifyRequest(Encoding.UTF8.GetBytes(from.ToString()), buffer, offset, count, new QueuedDatagramTransport(_settings.SendDatagram, from));
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is TlsException)
                {
                    return;
                }
                if (request == null)
                    return;
                peer = new Peer { Datagrams = new QueuedDatagramTransport(_settings.SendDatagram, from) };
                if (!_peers.TryAdd(from, peer))
                    return;
                StartPeer(from, peer, request);
            }

            // a thread of the peer's association: of a method of its own, as a lambda in the loop of the datagrams would make the
            // compiler allocate its closure at each of them
            private void StartPeer(IPEndPoint from, Peer peer, DtlsRequest request)
            {
                var thread = new Thread(() => Serve(from, peer, request)) { IsBackground = true, Name = "DTLS of BouncyCastle " + from };
                thread.Start();
            }

            private void Serve(IPEndPoint from, Peer peer, DtlsRequest request)
            {
                try
                {
                    peer.Dtls = new DtlsServerProtocol().Accept(new BcServer(_crypto, _credentials, (int)_settings.HandshakeTimeout.TotalMilliseconds), peer.Datagrams, request);
                    _settings.Established?.Invoke(from);
                    byte[] buffer = new byte[ushort.MaxValue];
                    while (_peers.ContainsKey(from))
                    {
                        int count = peer.Dtls.Receive(buffer, 0, buffer.Length, 1000);
                        if (count >= 0)
                            _settings.RecordReceived?.Invoke(from, buffer, 0, count);
                    }
                }
                catch (Exception)
                {
                    // of a thread of its own: whatever ends it is the association's alone, never the process's
                }
                finally
                {
                    End(from, peer);
                }
            }

            public bool HasAssociation(IPEndPoint peer) => _peers.ContainsKey(peer);

            public IReadOnlyCollection<IPEndPoint> Peers => _peers.Keys.ToList();

            public void Send(IPEndPoint peer, byte[] buffer, int offset, int count)
            {
                if (!_peers.TryGetValue(peer, out var state) || state.Dtls == null)
                    throw new IOException($"No DTLS association of {peer}.");
                try
                {
                    lock (state.Writing)
                        state.Dtls.Send(buffer, offset, count);
                }
                catch (Exception ex) when (ex is TlsException || ex is SocketException || ex is ObjectDisposedException)
                {
                    throw new IOException("The DTLS association ended: " + ex.Message, ex);
                }
            }

            public void Close(IPEndPoint peer)
            {
                if (_peers.TryGetValue(peer, out var state))
                    End(peer, state);
            }

            // the association ended: of its close_notify, its datagrams ended, and told of once
            private void End(IPEndPoint from, Peer peer)
            {
                if (!_peers.TryRemove(from, out _))
                    return;
                try
                {
                    lock (peer.Writing)
                        peer.Dtls?.Close();
                }
                catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException || ex is SocketException)
                {
                }
                peer.Datagrams.Close();
                _settings.Closed?.Invoke(from);
            }

            public void Dispose()
            {
                foreach (var peer in _peers.Keys.ToList())
                    Close(peer);
            }
        }

        /// <summary>
        /// A DTLS 1.2 server of an X.509 certificate of .NET's, its private key exportable: of RSA, or of ECDSA, its cipher suites
        /// of ECDHE of that key.
        /// </summary>
        private sealed class BcServer : DefaultTlsServer
        {
            private readonly (Certificate Chain, AsymmetricKeyParameter Key, bool IsEcdsa) _credentials;
            private readonly int _timeout;

            public BcServer(TlsCrypto crypto, (Certificate Chain, AsymmetricKeyParameter Key, bool IsEcdsa) credentials, int timeout) : base(crypto)
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
                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)m_context.Crypto, _credentials.Key, _credentials.Chain, chosen);
            }
        }

        /// <summary>
        /// The datagrams of one peer of a socket a server shares among its peers: those the server's reader hands it, queued -
        /// each in a buffer of a pool, its own again once read - and its own sent to the peer.
        /// </summary>
        private sealed class QueuedDatagramTransport : DatagramTransport, DatagramSender
        {
            private readonly Action<IPEndPoint, byte[], int, int> _send;
            private readonly IPEndPoint _remote;
            private readonly BlockingCollection<ArraySegment<byte>> _received = new BlockingCollection<ArraySegment<byte>>(64);

            public QueuedDatagramTransport(Action<IPEndPoint, byte[], int, int> send, IPEndPoint remote)
            {
                _send = send;
                _remote = remote;
            }

            /// <summary>A datagram of the peer's, copied; false of one dropped, of a queue full.</summary>
            public bool Enqueue(byte[] buffer, int offset, int count)
            {
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

            public int GetSendLimit() => Mtu - 28;

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

            public void Send(byte[] buf, int off, int len) => _send?.Invoke(_remote, buf, off, len);

#if NETCOREAPP
            public void Send(ReadOnlySpan<byte> buffer)
            {
                byte[] bytes = buffer.ToArray();
                _send?.Invoke(_remote, bytes, 0, bytes.Length);
            }
#endif

            public void Close() => _received.CompleteAdding();
        }
    }
}
