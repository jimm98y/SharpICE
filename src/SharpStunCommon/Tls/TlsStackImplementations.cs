// SharpStunCommon
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

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunCommon
{
    /// <summary>TLS of SharpDTLS: TLS 1.3 and 1.2, its cipher suites and groups SharpDTLS's defaults.</summary>
    public sealed class SharpDtlsTlsStack : ITlsStack
    {
        public string Name => "SharpDTLS";

        public async Task<Stream> ConnectAsync(Stream inner, TlsClientSettings settings, CancellationToken cancellationToken = default)
        {
            if (inner == null)
                throw new ArgumentNullException(nameof(inner));
            settings ??= new TlsClientSettings();
            try
            {
                return await SharpDTLS.TlsStream.ConnectAsync(inner, client =>
                {
                    if (!string.IsNullOrEmpty(settings.ServerName) && !IPAddress.TryParse(settings.ServerName, out _))
                        client.ServerName = settings.ServerName;
                    client.ServerCertificateValidator = (leaf, chain) => settings.ValidateServerCertificate?.Invoke(chain) ?? true;
                }, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SharpDTLS.DtlsException || ex is InvalidOperationException || ex is InvalidDataException)
            {
                throw new IOException("The TLS handshake failed: " + ex.Message, ex);
            }
        }

        public ITlsServer CreateServer(X509Certificate2 certificate) => new Server(certificate ?? throw new ArgumentNullException(nameof(certificate)));

        private sealed class Server : ITlsServer
        {
            private readonly SharpDTLS.TlsServer _server;

            public Server(X509Certificate2 certificate)
            {
                var credentials = DtlsCertificates.Load(certificate);
                _server = new SharpDTLS.TlsServer(credentials.KeyPair, credentials.Certificate) { IntermediateCertificates = credentials.Intermediates };
            }

            public async Task<Stream> AcceptAsync(Stream inner, CancellationToken cancellationToken = default)
            {
                try
                {
                    return await SharpDTLS.TlsStream.AcceptAsync(_server, inner, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SharpDTLS.DtlsException || ex is InvalidOperationException || ex is InvalidDataException)
                {
                    throw new IOException("The TLS handshake failed: " + ex.Message, ex);
                }
            }

            public void Dispose() => _server.Dispose();
        }
    }

    /// <summary>
    /// TLS of BouncyCastle: TLS 1.2 alone, as its DTLS is; of ECDHE, of AES-GCM, ChaCha20-Poly1305 or AES-CBC. Each handshake
    /// of a thread of the pool, as BouncyCastle's is blocking.
    /// </summary>
    public sealed class BcTlsStack : ITlsStack
    {
        public string Name => "BouncyCastle";

        public async Task<Stream> ConnectAsync(Stream inner, TlsClientSettings settings, CancellationToken cancellationToken = default)
        {
            if (inner == null)
                throw new ArgumentNullException(nameof(inner));
            settings ??= new TlsClientSettings();
            var protocol = new TlsClientProtocol(inner);
            try
            {
                // of a handshake that blocks: cancelled of the stream closed under it
                using (cancellationToken.Register(() => inner.Dispose()))
                    await Task.Run(() => protocol.Connect(new Client(new BcTlsCrypto(new SecureRandom()), settings)), cancellationToken).ConfigureAwait(false);
                return new BlockingStream(protocol.Stream);
            }
            catch (Exception ex) when (ex is TlsException || ex is ObjectDisposedException)
            {
                inner.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
                throw new IOException("The TLS handshake failed: " + ex.Message, ex);
            }
        }

        public ITlsServer CreateServer(X509Certificate2 certificate) => new Server(certificate ?? throw new ArgumentNullException(nameof(certificate)));

        /// <summary>
        /// BouncyCastle's stream of a connection, of a read and a write at once: its async calls of its blocking ones, each of
        /// a thread of the pool - as Stream's own run one at a time, a read waiting for data holding up every write - as
        /// BouncyCastle reads of one thread and writes of another.
        /// </summary>
        private sealed class BlockingStream : Stream
        {
            private readonly Stream _inner;

            public BlockingStream(Stream inner) => _inner = inner;

            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

            public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
                => Task.Run(() => _inner.Read(buffer, offset, count), cancellationToken);

            public override Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
                => Task.Run(() => _inner.Write(buffer, offset, count), cancellationToken);

#if NETCOREAPP
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, System.Threading.CancellationToken cancellationToken = default)
            {
                if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray<byte>(buffer, out var segment))
                    return new ValueTask<int>(ReadAsync(segment.Array, segment.Offset, segment.Count, cancellationToken));
                return new ValueTask<int>(ReadCopyAsync(buffer, cancellationToken));
            }

            private async Task<int> ReadCopyAsync(Memory<byte> buffer, System.Threading.CancellationToken cancellationToken)
            {
                byte[] bytes = new byte[buffer.Length];
                int count = await ReadAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);
                bytes.AsMemory(0, count).CopyTo(buffer);
                return count;
            }

            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, System.Threading.CancellationToken cancellationToken = default)
            {
                byte[] bytes = buffer.ToArray();
                return new ValueTask(WriteAsync(bytes, 0, bytes.Length, cancellationToken));
            }
#endif

            public override void Flush() => _inner.Flush();

            public override Task FlushAsync(System.Threading.CancellationToken cancellationToken) => Task.Run(() => _inner.Flush(), cancellationToken);

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    try
                    {
                        // its close_notify, and the stream under it closed
                        _inner.Dispose();
                    }
                    catch (Exception ex) when (ex is IOException || ex is TlsException || ex is ObjectDisposedException)
                    {
                    }
                }
                base.Dispose(disposing);
            }
        }

        private sealed class Client : DefaultTlsClient
        {
            private readonly TlsClientSettings _settings;

            public Client(TlsCrypto crypto, TlsClientSettings settings) : base(crypto) => _settings = settings;

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            protected override IList<ServerName> GetSniServerNames()
            {
                // a name, not an address (RFC 6066 3)
                string name = _settings.ServerName;
                if (string.IsNullOrEmpty(name) || IPAddress.TryParse(name, out _))
                    return null;
                return new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(name)) };
            }

            public override TlsAuthentication GetAuthentication() => new Authentication(_settings);

            private sealed class Authentication : TlsAuthentication
            {
                private readonly TlsClientSettings _settings;

                public Authentication(TlsClientSettings settings) => _settings = settings;

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    var certificate = serverCertificate.Certificate;
                    if (certificate == null || certificate.IsEmpty)
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    var chain = Enumerable.Range(0, certificate.Length).Select(i => certificate.GetCertificateAt(i).GetEncoded()).ToList();
                    if (_settings.ValidateServerCertificate != null && !_settings.ValidateServerCertificate(chain))
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;
            }
        }

        private sealed class Server : ITlsServer
        {
            private readonly BcTlsCrypto _crypto = new BcTlsCrypto(new SecureRandom());
            private readonly (Certificate Chain, Org.BouncyCastle.Crypto.AsymmetricKeyParameter Key, bool IsEcdsa) _credentials;

            public Server(X509Certificate2 certificate) => _credentials = BcDtlsStack.Credentials(_crypto, certificate);

            public async Task<Stream> AcceptAsync(Stream inner, CancellationToken cancellationToken = default)
            {
                var protocol = new TlsServerProtocol(inner);
                try
                {
                    using (cancellationToken.Register(() => inner.Dispose()))
                        await Task.Run(() => protocol.Accept(new BcDtlsStack.BcServer(_crypto, _credentials, 0, ProtocolVersion.TLSv12.Only())), cancellationToken).ConfigureAwait(false);
                    return new BlockingStream(protocol.Stream);
                }
                catch (Exception ex) when (ex is TlsException || ex is ObjectDisposedException)
                {
                    inner.Dispose();
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new IOException("The TLS handshake failed: " + ex.Message, ex);
                }
            }

            public void Dispose()
            {
            }
        }
    }

    /// <summary>TLS of .NET's SslStream: the versions and cipher suites of the system's, its certificate chain the system's.</summary>
    public sealed class SystemTlsStack : ITlsStack
    {
        public string Name => "SslStream";

        public async Task<Stream> ConnectAsync(Stream inner, TlsClientSettings settings, CancellationToken cancellationToken = default)
        {
            if (inner == null)
                throw new ArgumentNullException(nameof(inner));
            settings ??= new TlsClientSettings();
            var ssl = new SslStream(inner, false, (sender, certificate, chain, errors) =>
            {
                if (settings.ValidateServerCertificate == null)
                    return true;
                // the chain as the server sent it, its own first; of none built, the server's own alone
                var der = chain != null && chain.ChainElements.Count > 0
                    ? chain.ChainElements.Cast<X509ChainElement>().Select(e => e.Certificate.RawData).ToList()
                    : new List<byte[]> { certificate.GetRawCertData() };
                return settings.ValidateServerCertificate(der);
            });
            try
            {
                using (cancellationToken.Register(() => ssl.Dispose()))
                    await ssl.AuthenticateAsClientAsync(settings.ServerName ?? "").ConfigureAwait(false);
                return ssl;
            }
            catch (Exception ex) when (ex is AuthenticationException || ex is ObjectDisposedException)
            {
                ssl.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
                throw new IOException("The TLS handshake failed: " + ex.Message, ex);
            }
        }

        public ITlsServer CreateServer(X509Certificate2 certificate) => new Server(certificate ?? throw new ArgumentNullException(nameof(certificate)));

        private sealed class Server : ITlsServer
        {
            private readonly X509Certificate2 _certificate;

            public Server(X509Certificate2 certificate) => _certificate = certificate;

            public async Task<Stream> AcceptAsync(Stream inner, CancellationToken cancellationToken = default)
            {
                var ssl = new SslStream(inner, false);
                try
                {
                    using (cancellationToken.Register(() => ssl.Dispose()))
                        await ssl.AuthenticateAsServerAsync(_certificate, false, SslProtocols.None, false).ConfigureAwait(false);
                    return ssl;
                }
                catch (Exception ex) when (ex is AuthenticationException || ex is ObjectDisposedException)
                {
                    ssl.Dispose();
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new IOException("The TLS handshake failed: " + ex.Message, ex);
                }
            }

            public void Dispose()
            {
            }
        }
    }
}
