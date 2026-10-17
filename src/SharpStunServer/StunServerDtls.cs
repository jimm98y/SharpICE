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

namespace SharpStunServer
{
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
