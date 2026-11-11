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

#if NET8_0_OR_GREATER
using ReadTask = System.Threading.Tasks.ValueTask<bool>;
#else
using ReadTask = System.Threading.Tasks.Task<bool>;
#endif
using SharpStun;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStun
{
    /// <summary>
    /// A STUN message received, and where from. The arguments are the transport's own again once the event returns, told of
    /// the next message: what is kept of them is to be copied.
    /// </summary>
    public sealed class StunMessageEventArgs : EventArgs
    {
        public StunMessageEventArgs(StunMessage message, IPEndPoint remoteEndPoint) => Set(message, remoteEndPoint);

        internal StunMessageEventArgs()
        {
        }

        public StunMessage Message { get; private set; }
        public IPEndPoint RemoteEndPoint { get; private set; }

        internal StunMessageEventArgs Set(StunMessage message, IPEndPoint remoteEndPoint)
        {
            Message = message;
            RemoteEndPoint = remoteEndPoint;
            return this;
        }
    }

    /// <summary>
    /// What the server sent that is not STUN: of TURN, a ChannelData message (RFC 8656 12.4), its padding over TCP left out. Its
    /// buffer, and these arguments, are the transport's own again once the event returns: what is kept of them is to be copied.
    /// </summary>
    public sealed class StunDataEventArgs : EventArgs
    {
        public StunDataEventArgs(byte[] buffer, int offset, int count) => Set(buffer, offset, count);

        internal StunDataEventArgs()
        {
        }

        public byte[] Buffer { get; private set; }
        public int Offset { get; private set; }
        public int Count { get; private set; }

        internal StunDataEventArgs Set(byte[] buffer, int offset, int count)
        {
            Buffer = buffer;
            Offset = offset;
            Count = count;
            return this;
        }
    }

    /// <summary>
    /// What a <see cref="StunClient"/> sends its messages over to a server, and receives them of: UDP, whose requests are
    /// retransmitted (RFC 8489 6.2.1), or TCP and TLS over it, which are reliable (RFC 8489 6.2.2). Of TURN, its ChannelData
    /// too, told of as <see cref="DataReceived"/>.
    /// </summary>
    public abstract class StunTransport : IDisposable
    {
        /// <summary>Of TCP: no retransmissions, a transaction ended once the connection is.</summary>
        public abstract bool IsReliable { get; }

        /// <summary>Of a stream - TCP, TLS - whose ChannelData messages are padded to 4 bytes (RFC 8656 12.5).</summary>
        public virtual bool IsStream => false;

        /// <summary>The server's address.</summary>
        public IPEndPoint RemoteEndPoint { get; protected set; }

        public abstract IPEndPoint LocalEndPoint { get; }

        public abstract Task SendAsync(byte[] message, CancellationToken cancellationToken = default);

        /// <summary>Bytes of a buffer the caller's again once the task completes: of TURN, ChannelData of a buffer of a pool.</summary>
        public abstract Task SendAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default);

        public event EventHandler<StunMessageEventArgs> MessageReceived;

        /// <summary>What the server sent that is not STUN: ChannelData (RFC 8656 12.4), of its first byte of 0x40 to 0x4F.</summary>
        public event EventHandler<StunDataEventArgs> DataReceived;

        /// <summary>The connection of a reliable transport ended: of the error, or of null, closed by the server.</summary>
        public event EventHandler<Exception> Closed;

        // of each transport, its one receiving loop's: told of again of each message
        private readonly StunMessageEventArgs _messageArgs = new StunMessageEventArgs();
        private readonly StunDataEventArgs _dataArgs = new StunDataEventArgs();

        // of the transport's one receiving loop: whatever a handler of an event throws - an application's, of what a peer or
        // the server sent - is the handler's alone, never the loop's, which would end of it, the client's every transaction
        // and its allocation with it, of no Closed told of
        protected void OnMessageReceived(StunMessage message, IPEndPoint from)
        {
            try
            {
                MessageReceived?.Invoke(this, _messageArgs.Set(message, from));
            }
            catch (Exception)
            {
            }
        }

        protected void OnClosed(Exception error)
        {
            try
            {
                Closed?.Invoke(this, error);
            }
            catch (Exception)
            {
            }
        }

        /// <summary>ChannelData, of the buffer it was read into: the transport's own again once the event returns.</summary>
        protected void OnDataReceived(byte[] buffer, int offset, int count)
        {
            try
            {
                DataReceived?.Invoke(this, _dataArgs.Set(buffer, offset, count));
            }
            catch (Exception)
            {
            }
        }

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
        private readonly UdpSender _sender;

        /// <summary>Of a socket of its own, bound to any address, which it reads.</summary>
        public StunUdpTransport(IPEndPoint server)
        {
            RemoteEndPoint = server ?? throw new ArgumentNullException(nameof(server));
            Socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            Socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            _sender = new UdpSender(Socket);
            _ownsSocket = true;
            _ = ReceiveLoopAsync();
        }

        /// <summary>Of a bound socket: read by it, if it is to receive, else by what hands it the datagrams.</summary>
        public StunUdpTransport(Socket socket, IPEndPoint server, bool receive)
        {
            Socket = socket ?? throw new ArgumentNullException(nameof(socket));
            RemoteEndPoint = server ?? throw new ArgumentNullException(nameof(server));
            _sender = new UdpSender(socket);
            if (receive)
                _ = ReceiveLoopAsync();
        }

        public Socket Socket { get; }

        public override bool IsReliable => false;

        public override IPEndPoint LocalEndPoint => (IPEndPoint)Socket.LocalEndPoint;

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default) => SendAsync(message, 0, message.Length, cancellationToken);

        public override Task SendAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            _sender.SendTo(buffer, offset, count, RemoteEndPoint);
            return Task.CompletedTask;
        }

        /// <summary>
        /// A datagram read off the socket elsewhere: true of a STUN message, or of ChannelData of the server's, which are told of.
        /// </summary>
        public bool Receive(byte[] buffer, int offset, int count, IPEndPoint from)
        {
            var message = StunMessage.Parse(buffer, offset, count);
            if (message != null)
            {
                // an indication - of TURN, a Data indication - of the server alone: of anyone else, one forged to the client's
                // socket (RFC 8656 11.4), as ChannelData is of the server alone below
                if (message.Class == StunMessageClass.Indication && !from.Equals(RemoteEndPoint))
                    return false;
                OnMessageReceived(message, from);
                return true;
            }
            if (count >= 4 && StunFraming.IsChannelData(buffer[offset]) && from.Equals(RemoteEndPoint))
            {
                OnDataReceived(buffer, offset, count);
                return true;
            }
            return false;
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
            var receiver = new UdpReceiver(Socket);
            while (!_cts.IsCancellationRequested)
            {
                int count;
                try
                {
                    count = await receiver.ReceiveAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
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
                Receive(buffer, 0, count, receiver.RemoteEndPoint);
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
    /// STUN alone has it. Of TLS, of a TLS stack - SharpDTLS's, the default, BouncyCastle's or .NET's SslStream - its
    /// certificate checked of the host name given, of the system's checks or of a callback's.
    /// </summary>
    public sealed class StunStreamTransport : StunTransport
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly string _tlsHost;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly ITlsStack _tlsStack;
        private readonly SemaphoreSlim _writing = new SemaphoreSlim(1, 1);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly IPEndPoint _localEndPoint;

        // how long a client's TLS handshake is given
        private static readonly TimeSpan TlsHandshakeTimeout = TimeSpan.FromSeconds(10);

        private StunStreamTransport(TcpClient client, Stream stream, IPEndPoint server, string tlsHost, RemoteCertificateValidationCallback validation, ITlsStack tlsStack)
        {
            _client = client;
            _stream = stream;
            _tlsHost = tlsHost;
            _validation = validation;
            _tlsStack = tlsStack;
            _localEndPoint = (IPEndPoint)client.Client.LocalEndPoint;
            RemoteEndPoint = server;
            _ = ReceiveLoopAsync();
        }

        /// <summary>
        /// A connection to the server: of TLS, of a host name given, the name its certificate is checked of; of the callback
        /// given, checked by it rather than by the system. Of TLS, of the default TLS stack.
        /// </summary>
        public static Task<StunStreamTransport> ConnectAsync(IPEndPoint server, string tlsHost = null, RemoteCertificateValidationCallback validation = null, CancellationToken cancellationToken = default)
            => ConnectAsync(server, tlsHost, validation, null, cancellationToken);

        /// <summary>A connection to the server, of TLS of the TLS stack given: of null, <see cref="TlsStacks.Default"/>.</summary>
        public static async Task<StunStreamTransport> ConnectAsync(IPEndPoint server, string tlsHost, RemoteCertificateValidationCallback validation, ITlsStack tlsStack, CancellationToken cancellationToken = default)
        {
            tlsStack ??= TlsStacks.Default;
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
                    // of a handshake of its own deadline: a server that takes the connection and answers nothing holds it not
                    // for ever, as the URI's other servers are to be tried
                    using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                    {
                        handshake.CancelAfter(TlsHandshakeTimeout);
                        try
                        {
                            stream = await tlsStack.ConnectAsync(stream, new TlsClientSettings
                            {
                                ServerName = tlsHost,
                                ValidateServerCertificate = chain => DtlsCertificates.Validate(chain, tlsHost, validation, client),
                            }, handshake.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
                        {
                            throw new IOException("The TLS handshake timed out.", ex);
                        }
                    }
                }
                return new StunStreamTransport(client, stream, server, tlsHost, validation, tlsStack);
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        public override bool IsReliable => true;

        public override bool IsStream => true;

        public bool IsSecure => _tlsHost != null;

        /// <summary>The TLS stack of a connection of TLS.</summary>
        public ITlsStack TlsStack => _tlsStack;

        public override IPEndPoint LocalEndPoint => _localEndPoint;

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default) => SendAsync(message, 0, message.Length, cancellationToken);

        public override async Task SendAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            await _writing.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
#if NET8_0_OR_GREATER
                await _stream.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
#else
                await _stream.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
#endif
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writing.Release();
            }
        }

        public override async Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
            => await ConnectAsync(server, IsSecure ? domain ?? _tlsHost : null, _validation, _tlsStack, cancellationToken).ConfigureAwait(false);

        private async Task ReceiveLoopAsync()
        {
            // the connection's one buffer, of a pool, of the longest message there is: a STUN message's header and 65535 bytes
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StunMessage.HeaderLength + ushort.MaxValue);
            Exception error = null;
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    if (!await ReadExactlyAsync(buffer, 0, 4).ConfigureAwait(false))
                        break;
                    // ChannelData of TURN: its length, then its data, padded to 4 bytes over a stream (RFC 8656 12.5)
                    if (StunFraming.IsChannelData(buffer[0]))
                    {
                        int dataLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2));
                        if (!await ReadExactlyAsync(buffer, 4, (dataLength + 3) & ~3).ConfigureAwait(false))
                            break;
                        OnDataReceived(buffer, 0, 4 + dataLength);
                        continue;
                    }
                    if (!await ReadExactlyAsync(buffer, 4, StunMessage.HeaderLength - 4).ConfigureAwait(false))
                        break;
                    // else STUN: each message's header says how long it is
                    if ((buffer[0] & 0xC0) != 0 || BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(4)) != StunMessage.MagicCookie)
                        throw new InvalidDataException("What the server sent is neither STUN nor ChannelData.");
                    int length = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2));
                    if (!await ReadExactlyAsync(buffer, StunMessage.HeaderLength, length).ConfigureAwait(false))
                        break;

                    var parsed = StunMessage.Parse(buffer, 0, StunMessage.HeaderLength + length);
                    if (parsed == null)
                        throw new InvalidDataException("The server sent a STUN message that is not well formed.");
                    OnMessageReceived(parsed, RemoteEndPoint);

                    // the last message of STUN of the connection: nothing after it read, the stream its taker's
                    var detach = DetachAfter;
                    if (detach != null && detach(parsed))
                    {
                        _detached.TrySetResult(_stream);
                        return;
                    }
                }
            }
            catch (Exception e) when (e is IOException || e is SocketException || e is InvalidDataException || e is ObjectDisposedException || e is OperationCanceledException)
            {
                error = e;
            }
            finally
            {
                // of what TLS decrypted: cleared, before the pool hands it to anything else
                ArrayPool<byte>.Shared.Return(buffer, true);
            }
            _detached.TrySetException(new IOException("The connection ended before it was taken over.", error));
            if (!_cts.IsCancellationRequested)
                OnClosed(error);
        }

        private readonly TaskCompletionSource<Stream> _detached = new TaskCompletionSource<Stream>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Of TURN, a data connection's (RFC 6062 4.3): the message after which the connection is no longer of STUN - its
        /// ConnectionBind's success response - set before the request is sent. Nothing past it is read of the transport.
        /// </summary>
        internal Func<StunMessage, bool> DetachAfter { get; set; }

        /// <summary>The stream, once the message of <see cref="DetachAfter"/> came: its bytes, from then on, its taker's to read.</summary>
        internal Task<Stream> DetachedAsync() => _detached.Task;

#if NET8_0_OR_GREATER
        [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
#endif
        private async ReadTask ReadExactlyAsync(byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
#if NET8_0_OR_GREATER
                int read = await _stream.ReadAsync(buffer.AsMemory(offset, count), _cts.Token).ConfigureAwait(false);
#else
                int read = await _stream.ReadAsync(buffer, offset, count, _cts.Token).ConfigureAwait(false);
#endif
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
