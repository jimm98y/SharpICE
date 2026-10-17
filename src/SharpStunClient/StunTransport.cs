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

using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>A STUN message received, and where from.</summary>
    public sealed class StunMessageEventArgs : EventArgs
    {
        public StunMessageEventArgs(StunMessage message, IPEndPoint remoteEndPoint)
        {
            Message = message;
            RemoteEndPoint = remoteEndPoint;
        }

        public StunMessage Message { get; }
        public IPEndPoint RemoteEndPoint { get; }
    }

    /// <summary>
    /// What a <see cref="StunClient"/> sends its messages over to a server, and receives them of: UDP, whose requests are
    /// retransmitted (RFC 8489 6.2.1), or TCP and TLS over it, which are reliable (RFC 8489 6.2.2).
    /// </summary>
    public abstract class StunTransport : IDisposable
    {
        /// <summary>Of TCP: no retransmissions, a transaction ended once the connection is.</summary>
        public abstract bool IsReliable { get; }

        /// <summary>The server's address.</summary>
        public IPEndPoint RemoteEndPoint { get; protected set; }

        public abstract IPEndPoint LocalEndPoint { get; }

        public abstract Task SendAsync(byte[] message, CancellationToken cancellationToken = default);

        public event EventHandler<StunMessageEventArgs> MessageReceived;

        /// <summary>The connection of a reliable transport ended: of the error, or of null, closed by the server.</summary>
        public event EventHandler<Exception> Closed;

        protected void OnMessageReceived(StunMessage message, IPEndPoint from) => MessageReceived?.Invoke(this, new StunMessageEventArgs(message, from));

        protected void OnClosed(Exception error) => Closed?.Invoke(this, error);

        /// <summary>
        /// A transport of the same protocol to another server, of an ALTERNATE-SERVER (RFC 8489 10): of TLS, its certificate of
        /// the domain given, or else of the one this one's was. This one, of UDP, only sent elsewhere.
        /// </summary>
        public abstract Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default);

        public abstract void Dispose();
    }

    /// <summary>
    /// STUN over UDP: of a socket of its own, which it reads, or of one it shares - an ICE agent's - read elsewhere and its
    /// datagrams handed to <see cref="Receive"/>.
    /// </summary>
    public sealed class StunUdpTransport : StunTransport
    {
        private readonly bool _ownsSocket;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>Of a socket of its own, bound to any address, which it reads.</summary>
        public StunUdpTransport(IPEndPoint server)
        {
            RemoteEndPoint = server ?? throw new ArgumentNullException(nameof(server));
            Socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            Socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            _ownsSocket = true;
            _ = ReceiveLoopAsync();
        }

        /// <summary>Of a bound socket: read by it, if it is to receive, else by what hands it the datagrams.</summary>
        public StunUdpTransport(Socket socket, IPEndPoint server, bool receive)
        {
            Socket = socket ?? throw new ArgumentNullException(nameof(socket));
            RemoteEndPoint = server ?? throw new ArgumentNullException(nameof(server));
            if (receive)
                _ = ReceiveLoopAsync();
        }

        public Socket Socket { get; }

        public override bool IsReliable => false;

        public override IPEndPoint LocalEndPoint => (IPEndPoint)Socket.LocalEndPoint;

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default)
        {
            Socket.SendTo(message, RemoteEndPoint);
            return Task.CompletedTask;
        }

        /// <summary>A datagram read off the socket elsewhere: true of a STUN message, which is told of.</summary>
        public bool Receive(byte[] buffer, int offset, int count, IPEndPoint from)
        {
            var message = StunMessage.Parse(buffer, offset, count);
            if (message == null)
                return false;
            OnMessageReceived(message, from);
            return true;
        }

        public override Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
        {
            if (server.AddressFamily != RemoteEndPoint.AddressFamily)
                return Task.FromResult<StunTransport>(null);
            RemoteEndPoint = server;
            return Task.FromResult<StunTransport>(this);
        }

        private async Task ReceiveLoopAsync()
        {
            byte[] buffer = new byte[1500];
            var any = new IPEndPoint(Socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            while (!_cts.IsCancellationRequested)
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await Socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    // an ICMP port unreachable of a request before, reported by Windows as a reset
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                Receive(buffer, 0, result.ReceivedBytes, (IPEndPoint)result.RemoteEndPoint);
            }
        }

        public override void Dispose()
        {
            _cts.Cancel();
            if (_ownsSocket)
                Socket.Dispose();
        }
    }

    /// <summary>
    /// STUN over TCP, or TLS over TCP (RFC 8489 6.2.2, 6.2.3), with no framing but the messages' own lengths, as a server of
    /// STUN alone has it. Its certificate is checked of the host name given, of the system's checks or of a callback's.
    /// </summary>
    public sealed class StunStreamTransport : StunTransport
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly string _tlsHost;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly SemaphoreSlim _writing = new SemaphoreSlim(1, 1);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly IPEndPoint _localEndPoint;

        private StunStreamTransport(TcpClient client, Stream stream, IPEndPoint server, string tlsHost, RemoteCertificateValidationCallback validation)
        {
            _client = client;
            _stream = stream;
            _tlsHost = tlsHost;
            _validation = validation;
            _localEndPoint = (IPEndPoint)client.Client.LocalEndPoint;
            RemoteEndPoint = server;
            _ = ReceiveLoopAsync();
        }

        /// <summary>
        /// A connection to the server: of TLS, of a host name given, the name its certificate is checked of; of the callback
        /// given, checked by it rather than by the system.
        /// </summary>
        public static async Task<StunStreamTransport> ConnectAsync(IPEndPoint server, string tlsHost = null, RemoteCertificateValidationCallback validation = null, CancellationToken cancellationToken = default)
        {
            var client = new TcpClient(server.AddressFamily);
            try
            {
                var connect = client.ConnectAsync(server.Address, server.Port);
                var completed = await Task.WhenAny(connect, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
                if (completed != connect)
                    throw new OperationCanceledException(cancellationToken);
                await connect.ConfigureAwait(false);
                client.NoDelay = true;

                Stream stream = client.GetStream();
                if (tlsHost != null)
                {
                    var ssl = new SslStream(stream, false, validation);
                    await ssl.AuthenticateAsClientAsync(tlsHost).ConfigureAwait(false);
                    stream = ssl;
                }
                return new StunStreamTransport(client, stream, server, tlsHost, validation);
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        public override bool IsReliable => true;

        public bool IsSecure => _tlsHost != null;

        public override IPEndPoint LocalEndPoint => _localEndPoint;

        public override async Task SendAsync(byte[] message, CancellationToken cancellationToken = default)
        {
            await _writing.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await _stream.WriteAsync(message, 0, message.Length, cancellationToken).ConfigureAwait(false);
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writing.Release();
            }
        }

        public override async Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
            => await ConnectAsync(server, IsSecure ? domain ?? _tlsHost : null, _validation, cancellationToken).ConfigureAwait(false);

        private async Task ReceiveLoopAsync()
        {
            byte[] header = new byte[StunMessage.HeaderLength];
            Exception error = null;
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    if (!await ReadExactlyAsync(header, 0, header.Length).ConfigureAwait(false))
                        break;
                    // a stream of STUN alone: each message's header says how long it is
                    if ((header[0] & 0xC0) != 0 || BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4)) != StunMessage.MagicCookie)
                        throw new InvalidDataException("What the server sent is not STUN.");
                    int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                    byte[] message = new byte[StunMessage.HeaderLength + length];
                    Buffer.BlockCopy(header, 0, message, 0, header.Length);
                    if (!await ReadExactlyAsync(message, header.Length, length).ConfigureAwait(false))
                        break;

                    var parsed = StunMessage.Parse(message, 0, message.Length);
                    if (parsed == null)
                        throw new InvalidDataException("The server sent a STUN message that is not well formed.");
                    OnMessageReceived(parsed, RemoteEndPoint);
                }
            }
            catch (Exception e) when (e is IOException || e is SocketException || e is InvalidDataException || e is ObjectDisposedException || e is OperationCanceledException)
            {
                error = e;
            }
            if (!_cts.IsCancellationRequested)
                OnClosed(error);
        }

        private async Task<bool> ReadExactlyAsync(byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
                int read = await _stream.ReadAsync(buffer, offset, count, _cts.Token).ConfigureAwait(false);
                if (read == 0)
                    return false;
                offset += read;
                count -= read;
            }
            return true;
        }

        public override void Dispose()
        {
            _cts.Cancel();
            _stream.Dispose();
            _client.Dispose();
        }
    }
}
