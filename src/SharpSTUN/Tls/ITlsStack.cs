// SharpSTUN
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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SharpSTUN
{
    /// <summary>
    /// A TLS implementation STUN and TURN over TCP (RFC 8489 6.2.3), and ICE-TCP over TLS, run over, of no type of its
    /// library's own in what it takes and gives: <see cref="SharpDtlsTlsStack"/>, the default - TLS 1.3 and 1.2 - or
    /// <see cref="BcTlsStack"/>, of BouncyCastle - TLS 1.2 - or <see cref="SystemTlsStack"/>, of .NET's SslStream.
    /// </summary>
    public interface ITlsStack
    {
        /// <summary>The name of the implementation, as traces tell of it.</summary>
        string Name { get; }

        /// <summary>
        /// A client's connection of TLS over the stream given - of TCP, connected to the server - of its handshake done: the
        /// stream of its data, which closes the one given with it.
        /// </summary>
        /// <exception cref="IOException">Of a handshake that failed, or of a certificate refused.</exception>
        Task<Stream> ConnectAsync(Stream inner, TlsClientSettings settings, CancellationToken cancellationToken = default);

        /// <summary>A server of TLS of the certificate given - its private key exportable - of each connection's handshake.</summary>
        ITlsServer CreateServer(X509Certificate2 certificate);
    }

    /// <summary>What a client's connection of TLS is of.</summary>
    public sealed class TlsClientSettings
    {
        /// <summary>The server's name, of SNI (RFC 6066 3); none, of null or of an address.</summary>
        public string ServerName { get; set; }

        /// <summary>
        /// Whether the server's certificate chain - the DER of each, the server's own first - is to be taken; of none, any is.
        /// </summary>
        public Func<IReadOnlyList<byte[]>, bool> ValidateServerCertificate { get; set; }
    }

    /// <summary>A server of TLS of one certificate.</summary>
    public interface ITlsServer : IDisposable
    {
        /// <summary>
        /// The server's side of a connection of TLS over the stream given - of TCP, accepted - of its handshake done: the
        /// stream of its data, which closes the one given with it.
        /// </summary>
        /// <exception cref="IOException">Of a handshake that failed.</exception>
        Task<Stream> AcceptAsync(Stream inner, CancellationToken cancellationToken = default);
    }

    /// <summary>The TLS implementations there are.</summary>
    public static class TlsStacks
    {
        /// <summary>Of SharpDTLS: TLS 1.3 and 1.2. The default.</summary>
        public static ITlsStack SharpDtls { get; } = new SharpDtlsTlsStack();

        /// <summary>Of BouncyCastle: TLS 1.2 alone, as its DTLS is.</summary>
        public static ITlsStack BouncyCastle { get; } = new BcTlsStack();

        /// <summary>Of .NET's SslStream: the versions and cipher suites of the system's.</summary>
        public static ITlsStack System { get; } = new SystemTlsStack();

        /// <summary>What a client or server of no other given runs over: <see cref="SharpDtls"/>.</summary>
        public static ITlsStack Default => SharpDtls;
    }
}
