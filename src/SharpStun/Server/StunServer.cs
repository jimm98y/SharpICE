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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStun
{
    /// <summary>The transport between a client and the server: of a 5-tuple's protocol.</summary>
    public enum StunServerProtocol
    {
        Udp,
        Tcp,
        Tls,
        Dtls
    }

    /// <summary>
    /// A 5-tuple of the server's: a client's address and the server's, over a transport - a datagram's of UDP, a connection of
    /// TCP or TLS, an association of DTLS. What the server sends the client goes over it, at any time: of TURN, the data of
    /// its peers. Of UDP, one of each datagram, alike of one client: <see cref="Key"/> tells them as one.
    /// </summary>
    public sealed class StunServerConnection
    {
        private readonly Action<byte[], int, int> _send;

        public StunServerConnection(StunServerProtocol protocol, IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, Action<byte[]> send)
            : this(protocol, localEndPoint, remoteEndPoint, (buffer, offset, count) => send(Whole(buffer, offset, count)))
        {
        }

        /// <summary>A 5-tuple of what sends the bytes of a buffer's part, the caller's again once it returns.</summary>
        public StunServerConnection(StunServerProtocol protocol, IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, Action<byte[], int, int> send)
        {
            Protocol = protocol;
            LocalEndPoint = localEndPoint;
            RemoteEndPoint = remoteEndPoint;
            _send = send;
            Key = protocol + " " + localEndPoint + " " + remoteEndPoint;
        }

        private static byte[] Whole(byte[] buffer, int offset, int count)
        {
            if (offset == 0 && count == buffer.Length)
                return buffer;
            byte[] copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            return copy;
        }

        public StunServerProtocol Protocol { get; }
        public IPEndPoint LocalEndPoint { get; }
        public IPEndPoint RemoteEndPoint { get; }

        /// <summary>The 5-tuple, as a string: alike of every datagram of one client of UDP.</summary>
        public string Key { get; }

        /// <summary>Of TLS or DTLS.</summary>
        public bool IsSecure => Protocol == StunServerProtocol.Tls || Protocol == StunServerProtocol.Dtls;

        /// <summary>Of TCP or TLS, whose ChannelData is padded to 4 bytes (RFC 8656 12.5).</summary>
        public bool IsStream => Protocol == StunServerProtocol.Tcp || Protocol == StunServerProtocol.Tls;

        /// <summary>Sends the bytes to the client; false of a connection that ended.</summary>
        public bool Send(byte[] data) => Send(data, 0, data.Length);

        /// <summary>Sends the bytes of a buffer's part to the client, the caller's again once it returns; false of a connection that ended.</summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            try
            {
                _send(buffer, offset, count);
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                return false;
            }
        }

        public override string ToString() => Key;

        /// <summary>
        /// Of a connection of TCP or TLS: what takes it over once the response of the request now handled is sent - of TURN,
        /// a client's data connection of a ConnectionBind (RFC 6062 5.4) - its bytes no longer read as STUN of the server, the
        /// stream its own until the task ends, and closed then.
        /// </summary>
        internal Func<Stream, Task> Handoff { get; set; }
    }

    /// <summary>
    /// A request of a method other than Binding, for the server's <see cref="StunServer.RequestHandler"/>: its message, its
    /// 5-tuple, and the user it was authenticated of - null of a server of no realm.
    /// </summary>
    public sealed class StunServerRequest
    {
        internal StunServerRequest(StunMessage message, StunServerConnection connection, string username)
        {
            Message = message;
            Connection = connection;
            Username = username;
        }

        public StunMessage Message { get; }
        public StunServerConnection Connection { get; }
        public string Username { get; }

        /// <summary>
        /// The response of a request answered later - of TURN, a Connect, of its connection to the peer (RFC 6062 5.2) - sent as
        /// one returned of the handler is, of its integrity and FINGERPRINT: of a handler that returns null and calls it after.
        /// </summary>
        internal Action<StunMessage> Respond { get; set; }

        /// <summary>An error response to it, of the code and reason given.</summary>
        public StunMessage Error(int code, string reason)
            => new StunMessage(Message.Method, StunMessageClass.ErrorResponse, Message.TransactionId).AddError(code, reason);

        /// <summary>A success response to it.</summary>
        public StunMessage Success() => new StunMessage(Message.Method, StunMessageClass.SuccessResponse, Message.TransactionId);
    }

    public sealed class StunServerOptions
    {
        /// <summary>
        /// The realm of long-term credentials (RFC 8489 9.2): of one, a request is answered only of a user's credentials, its
        /// first challenged with a 401; of none, every request is answered as it is.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Whether a Binding request is to be of the credentials too, of a realm; of TURN, not, as a server of TURN answers
        /// one as a server of STUN does.
        /// </summary>
        public bool AuthenticateBinding { get; set; } = true;

        /// <summary>
        /// Which attributes the server knows: a request of a comprehension-required one it does not is answered 420 (RFC 8489
        /// 6.3.1). Of STUN and ICE, of none given; a TURN server's, of TURN's too.
        /// </summary>
        public Func<ushort, bool> IsKnownAttribute { get; set; } = StunAttributeType.IsKnown;

        /// <summary>The methods of the requests <see cref="AlternateServer"/> redirects: Binding; a TURN server's, Allocate too.</summary>
        public ICollection<ushort> RedirectedMethods { get; set; } = new HashSet<ushort> { StunMethod.Binding };

        /// <summary>The users of the long-term credentials, and their passwords.</summary>
        public IDictionary<string, string> Users { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// The password algorithms to offer (RFC 8489 9.2.4), in the order of preference, of the nonce cookie's "Password
        /// algorithms" feature: of any, a request signed of MESSAGE-INTEGRITY-SHA256; of none, of MD5 and MESSAGE-INTEGRITY alone,
        /// as a server of RFC 5389.
        /// </summary>
        public IList<StunPasswordAlgorithm> PasswordAlgorithms { get; set; } = new List<StunPasswordAlgorithm> { StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5 };

        /// <summary>Whether a USERHASH is taken in place of a USERNAME: the nonce cookie's "Username anonymity" feature.</summary>
        public bool UsernameAnonymity { get; set; }

        /// <summary>How long a nonce is good for: after it, a request of it is answered 438 (Stale Nonce), of a new one.</summary>
        public TimeSpan NonceLifetime { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// The server a request is redirected to of a 300 (Try Alternate) (RFC 8489 10), of the request's source: null, of none
        /// to redirect to, which answers it here.
        /// </summary>
        public Func<IPEndPoint, IPEndPoint> AlternateServer { get; set; }

        /// <summary>The name of the certificate of the alternate server, of a redirection over TLS (RFC 8489 14.16).</summary>
        public string AlternateDomain { get; set; }

        /// <summary>The certificate of TLS and DTLS, its private key with it: of DTLS, an exportable one.</summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>How long an association of DTLS is kept of no datagram of its peer.</summary>
        public TimeSpan DtlsIdleTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// The DTLS implementation of the listeners of DTLS: of <see cref="DtlsStacks.SharpDtls"/>, the default, DTLS 1.3 and
        /// 1.2; of <see cref="DtlsStacks.BouncyCastle"/>, DTLS 1.2, a thread of each association.
        /// </summary>
        public IDtlsStack DtlsStack { get; set; } = DtlsStacks.Default;

        /// <summary>
        /// The TLS implementation of the listeners of TLS: of <see cref="TlsStacks.SharpDtls"/>, the default, TLS 1.3 and 1.2;
        /// of <see cref="TlsStacks.BouncyCastle"/>, TLS 1.2 - each of a certificate of an exportable private key, as of DTLS;
        /// of <see cref="TlsStacks.System"/>, .NET's SslStream, of any the system can use.
        /// </summary>
        public ITlsStack TlsStack { get; set; } = TlsStacks.Default;

        /// <summary>
        /// The connections of TCP and TLS at most at once, of all listeners: past them, a new one is closed as it is accepted.
        /// </summary>
        public int MaxConnections { get; set; } = 1000;

        /// <summary>The associations of DTLS at most at once of each listener: past them, a new peer is ignored.</summary>
        public int MaxDtlsPeers { get; set; } = 1000;

        /// <summary>
        /// How long a connection of TCP or TLS has for its TLS handshake and its first message: past it, it is closed, as one
        /// that sends nothing would hold its socket for ever.
        /// </summary>
        public TimeSpan FirstMessageTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// How long a connection of TCP or TLS may send nothing once it has: past it, it is closed. Longer than a TURN
        /// client's refreshes, of 9 minutes at most.
        /// </summary>
        public TimeSpan ConnectionIdleTimeout { get; set; } = TimeSpan.FromMinutes(15);

        /// <summary>The SOFTWARE of its responses; none, of null.</summary>
        public string Software { get; set; } = "SharpStunServer";

        /// <summary>What it does, a line at a time, of anything given.</summary>
        public Action<string> Trace { get; set; }
    }

    /// <summary>
    /// A STUN server (RFC 8489) of the Binding method: over UDP, TCP, TLS over TCP, and DTLS over UDP, each listener of its own. It answers a
    /// request with the address it came from, of long-term credentials if a realm is given - its nonces of the nonce cookie,
    /// and of the source address - or redirects it to an alternate server; a request of an attribute it is not to be understood
    /// without is answered 420. <see cref="Process"/> answers a message of a transport of the caller's.
    /// </summary>
    /// <remarks>
    /// Its nonces are stateless: the time each was made and an HMAC of it and the request's source, of a key of the server's
    /// own, which no other server and no other source has (RFC 8489 9.2.4). Classic STUN of RFC 3489, of no magic cookie, is not
    /// answered.
    /// </remarks>
    public sealed class StunServer : IDisposable
    {
        private readonly StunServerOptions _options;
        private readonly byte[] _nonceKey = new byte[32];
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly List<Socket> _udp = new List<Socket>();
        private readonly List<TcpListener> _tcp = new List<TcpListener>();
        private readonly object _sync = new object();

        public StunServer(StunServerOptions options = null)
        {
            _options = options ?? new StunServerOptions();
            using (var random = RandomNumberGenerator.Create())
                random.GetBytes(_nonceKey);
        }

        public StunServerOptions Options => _options;

        /// <summary>
        /// Answers a request of a method other than Binding, authenticated as the options say: its response - signed then as
        /// the request was - or null of none. Of none given, such a request is discarded (RFC 8489 6.3).
        /// </summary>
        public Func<StunServerRequest, StunMessage> RequestHandler { get; set; }

        /// <summary>An indication of a client's - never authenticated (RFC 8656 5) - of no unknown comprehension-required attribute.</summary>
        public Action<StunMessage, StunServerConnection> IndicationHandler { get; set; }

        /// <summary>What a client sent that is not STUN: ChannelData (RFC 8656 12.4), its padding over a stream left out.</summary>
        public Action<StunServerConnection, byte[], int, int> DataHandler { get; set; }

        /// <summary>A connection of TCP or TLS, or an association of DTLS, that ended.</summary>
        public event EventHandler<StunServerConnection> ConnectionClosed;

        private void Trace(string message) => _options.Trace?.Invoke(message);

        #region Listeners

        /// <summary>Answers the requests of UDP of the address, of port 3478 if none is given (0, any port); the address bound.</summary>
        public IPEndPoint ListenUdp(IPEndPoint endPoint)
        {
            var socket = new Socket(endPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(endPoint);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
            lock (_sync)
                _udp.Add(socket);
            _ = ServeUdpAsync(socket);
            var bound = (IPEndPoint)socket.LocalEndPoint;
            Trace($"UDP on {bound}");
            return bound;
        }

        /// <summary>Answers the requests of TCP of the address; the address bound.</summary>
        public IPEndPoint ListenTcp(IPEndPoint endPoint) => Listen(endPoint, false);

        /// <summary>Answers the requests of TLS over TCP of the address, of the certificate of the options; the address bound.</summary>
        public IPEndPoint ListenTls(IPEndPoint endPoint)
        {
            if (_options.Certificate == null)
                throw new InvalidOperationException("TLS takes a certificate: see StunServerOptions.Certificate.");
            lock (_sync)
                _tls ??= (_options.TlsStack ?? TlsStacks.Default).CreateServer(_options.Certificate);
            return Listen(endPoint, true);
        }

        // of the listeners of TLS: the server of the certificate, of the TLS stack of the options
        private ITlsServer _tls;

        /// <summary>
        /// Answers the requests of DTLS over UDP of the address (RFC 8489 6.2.3), of the DTLS stack and the certificate of the
        /// options - its private key exportable - an association of each peer, of a cookie exchange first (RFC 6347 4.2.1, RFC
        /// 9147 5.1), so that a source forged makes none; the address bound.
        /// </summary>
        public IPEndPoint ListenDtls(IPEndPoint endPoint)
        {
            if (_options.Certificate == null)
                throw new InvalidOperationException("DTLS takes a certificate: see StunServerOptions.Certificate.");
            var socket = new Socket(endPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            IDtlsServer dtls;
            var peers = new ConcurrentDictionary<IPEndPoint, DtlsPeer>();
            try
            {
                socket.Bind(endPoint);
                dtls = CreateDtlsServer(socket, peers);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
            lock (_sync)
                _udp.Add(socket);
            _ = ServeDtlsAsync(socket, dtls, peers);
            var bound = (IPEndPoint)socket.LocalEndPoint;
            Trace($"DTLS of {(_options.DtlsStack ?? DtlsStacks.Default).Name} on {bound}");
            return bound;
        }

        /// <summary>An association of DTLS of a peer of a listener: its connection of STUN, once its handshake is done.</summary>
        private sealed class DtlsPeer
        {
            public StunServerConnection Connection;
            public DateTime LastReceived = DateTime.UtcNow;
        }

        private IDtlsServer CreateDtlsServer(Socket socket, ConcurrentDictionary<IPEndPoint, DtlsPeer> peers)
        {
            var sender = new UdpSender(socket);
            var local = (IPEndPoint)socket.LocalEndPoint;
            IDtlsServer dtls = null;
            dtls = (_options.DtlsStack ?? DtlsStacks.Default).CreateServer(new DtlsServerSettings
            {
                Certificate = _options.Certificate,
                SendDatagram = (to, buffer, offset, count) => sender.SendTo(buffer, offset, count, to),
                Established = from =>
                {
                    var peer = peers.GetOrAdd(from, _ => new DtlsPeer());
                    peer.Connection = new StunServerConnection(StunServerProtocol.Dtls, local, from, (data, offset, length) => dtls.Send(from, data, offset, length));
                    Trace($"DTLS of {from}");
                },
                RecordReceived = (from, buffer, offset, count) =>
                {
                    if (peers.TryGetValue(from, out var peer) && peer.Connection != null)
                        ReceiveSafely(peer.Connection, buffer, offset, count);
                },
                Closed = from =>
                {
                    if (!peers.TryRemove(from, out var peer))
                        return;
                    Trace($"DTLS of {from} ended");
                    if (peer.Connection != null)
                        ConnectionClosed?.Invoke(this, peer.Connection);
                },
            });
            return dtls;
        }

        private async Task ServeDtlsAsync(Socket socket, IDtlsServer dtls, ConcurrentDictionary<IPEndPoint, DtlsPeer> peers)
        {
            // the associations of no datagram of their peer's for too long - a handshake left, or a peer gone - closed
            using (dtls)
            using (var idle = new Timer(_ => CloseIdle(dtls, peers), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1)))
            {
                byte[] buffer = new byte[65536];
                var receiver = new UdpReceiver(socket);
                while (!_cts.IsCancellationRequested)
                {
                    int received;
                    try
                    {
                        received = await receiver.ReceiveAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    if (received == 0)
                        continue;

                    var from = receiver.RemoteEndPoint;
                    if (dtls.HasAssociation(from))
                    {
                        peers.GetOrAdd(from, _ => new DtlsPeer()).LastReceived = DateTime.UtcNow;
                    }
                    else if (dtls.Peers.Count >= _options.MaxDtlsPeers)
                    {
                        // a peer of no association: past the limit, its ClientHello left unanswered
                        Trace($"DTLS of {from} refused: {_options.MaxDtlsPeers} associations already");
                        continue;
                    }
                    try
                    {
                        dtls.Receive(from, buffer, 0, received);
                    }
                    catch (Exception ex)
                    {
                        // of the listener's one loop: whatever a datagram ends is its association's alone, never the listener's
                        Trace($"DTLS of {from} failed: {ex.Message}");
                    }
                }
            }
        }

        private void CloseIdle(IDtlsServer dtls, ConcurrentDictionary<IPEndPoint, DtlsPeer> peers)
        {
            var now = DateTime.UtcNow;
            foreach (var from in dtls.Peers)
            {
                var peer = peers.GetOrAdd(from, _ => new DtlsPeer());
                if (now - peer.LastReceived > _options.DtlsIdleTimeout)
                {
                    Trace($"DTLS of {from} idle");
                    dtls.Close(from);
                }
            }
        }

        private IPEndPoint Listen(IPEndPoint endPoint, bool tls)
        {
            var listener = new TcpListener(endPoint);
            listener.Start();
            lock (_sync)
                _tcp.Add(listener);
            _ = AcceptAsync(listener, tls);
            var bound = (IPEndPoint)listener.LocalEndpoint;
            Trace($"{(tls ? "TLS" : "TCP")} on {bound}");
            return bound;
        }

        private const int MaxUdpConnections = 4096;

        // of a method of its own, as a lambda in the loop over the datagrams would make the compiler allocate its closure at each
        private static StunServerConnection UdpConnection(IPEndPoint local, IPEndPoint remote, UdpSender sender)
            => new StunServerConnection(StunServerProtocol.Udp, local, remote, (data, offset, count) => sender.SendTo(data, offset, count, remote));

        private async Task ServeUdpAsync(Socket socket)
        {
            var local = (IPEndPoint)socket.LocalEndPoint;
            byte[] buffer = new byte[65536];
            var receiver = new UdpReceiver(socket);
            var sender = new UdpSender(socket);
            // a connection of each client's 5-tuple, made once: past these, made again, as of a server of many clients
            var connections = new Dictionary<IPEndPoint, StunServerConnection>();
            while (!_cts.IsCancellationRequested)
            {
                int received;
                try
                {
                    received = await receiver.ReceiveAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    // an ICMP port unreachable of a response before, reported by Windows as a reset
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                var remote = receiver.RemoteEndPoint;
                if (!connections.TryGetValue(remote, out var connection))
                {
                    if (connections.Count >= MaxUdpConnections)
                        connections.Clear();
                    connection = UdpConnection(local, remote, sender);
                    connections[remote] = connection;
                }
                ReceiveSafely(connection, buffer, 0, received);
            }
        }

        private async Task AcceptAsync(TcpListener listener, bool tls)
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is ObjectDisposedException || ex is InvalidOperationException)
                {
                    return;
                }
                catch (SocketException)
                {
                    continue;
                }
                if (Interlocked.Increment(ref _connections) > _options.MaxConnections)
                {
                    Interlocked.Decrement(ref _connections);
                    Trace($"Connection of {client.Client.RemoteEndPoint} refused: {_options.MaxConnections} already");
                    client.Dispose();
                    continue;
                }
                _ = ServeStreamCountedAsync(client, tls);
            }
        }

        private int _connections;

        private async Task ServeStreamCountedAsync(TcpClient client, bool tls)
        {
            try
            {
                await ServeStreamAsync(client, tls).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Trace($"Connection failed: {ex.Message}");
            }
            finally
            {
                Interlocked.Decrement(ref _connections);
            }
        }

        // the connection's buffer of a message of the length given, of the pool: the one it has, or a larger one of what it holds
        private static byte[] Grow(byte[] buffer, int length, int kept)
        {
            if (buffer.Length >= length)
                return buffer;
            byte[] larger = ArrayPool<byte>.Shared.Rent(length);
            Buffer.BlockCopy(buffer, 0, larger, 0, kept);
            ArrayPool<byte>.Shared.Return(buffer, true);
            return larger;
        }

        // a connection of STUN, each message of its own length (RFC 8489 6.2.2), and of ChannelData, each padded to 4 bytes
        // (RFC 8656 12.5); answered over it
        private async Task ServeStreamAsync(TcpClient client, bool tls)
        {
            using (client)
            using (var deadline = new CancellationTokenSource())
            // past its deadline - its first message, or its silence after - the connection closed under its reads
            using (deadline.Token.Register(() => client.Dispose()))
            {
                var from = Normalize((IPEndPoint)client.Client.RemoteEndPoint);
                var local = (IPEndPoint)client.Client.LocalEndPoint;
                StunServerConnection connection = null;
                deadline.CancelAfter(_options.FirstMessageTimeout);
                try
                {
                    Stream stream = client.GetStream();
                    if (tls)
                    {
                        stream = await _tls.AcceptAsync(stream, deadline.Token).ConfigureAwait(false);
                    }
                    using (stream)
                    {
                        var writing = new object();
                        connection = new StunServerConnection(tls ? StunServerProtocol.Tls : StunServerProtocol.Tcp, local, from, (data, offset, count) =>
                        {
                            lock (writing)
                                stream.Write(data, offset, count);
                        });
                        // the connection's one buffer, of a pool: of a datagram's size, larger only as a message takes it, so that
                        // a connection that sends nothing holds little
                        byte[] buffer = ArrayPool<byte>.Shared.Rent(1500);
                        try
                        {
                            while (!_cts.IsCancellationRequested)
                            {
                                if (!await ReadAsync(stream, buffer, 0, 4).ConfigureAwait(false))
                                    return;
                                if (StunFraming.IsChannelData(buffer[0]))
                                {
                                    int dataLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2));
                                    int padded = (dataLength + 3) & ~3;
                                    buffer = Grow(buffer, 4 + padded, 4);
                                    if (!await ReadAsync(stream, buffer, 4, padded).ConfigureAwait(false))
                                        return;
                                    deadline.CancelAfter(_options.ConnectionIdleTimeout);
                                    ReceiveSafely(connection, buffer, 0, 4 + dataLength);
                                    continue;
                                }
                                if (!await ReadAsync(stream, buffer, 4, StunMessage.HeaderLength - 4).ConfigureAwait(false))
                                    return;
                                if ((buffer[0] & 0xC0) != 0 || BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(4)) != StunMessage.MagicCookie)
                                    return;
                                int length = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2));
                                buffer = Grow(buffer, StunMessage.HeaderLength + length, StunMessage.HeaderLength);
                                if (!await ReadAsync(stream, buffer, StunMessage.HeaderLength, length).ConfigureAwait(false))
                                    return;
                                deadline.CancelAfter(_options.ConnectionIdleTimeout);
                                ReceiveSafely(connection, buffer, 0, StunMessage.HeaderLength + length);

                                // taken over of the response just sent: of no deadline from now on, the stream its taker's
                                var handoff = connection.Handoff;
                                if (handoff != null)
                                {
                                    deadline.CancelAfter(System.Threading.Timeout.Infinite);
                                    await handoff(stream).ConfigureAwait(false);
                                    return;
                                }
                            }
                        }
                        finally
                        {
                            // of what TLS decrypted: cleared, before the pool hands it to anything else
                            ArrayPool<byte>.Shared.Return(buffer, true);
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is AuthenticationException || ex is ObjectDisposedException)
                {
                    Trace($"Connection of {from} ended: {ex.Message}");
                }
                finally
                {
                    if (connection != null)
                        ConnectionClosed?.Invoke(this, connection);
                }
            }
        }

#if NET8_0_OR_GREATER
        [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
#endif
        private static async ReadTask ReadAsync(Stream stream, byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
#if NET8_0_OR_GREATER
                int read = await stream.ReadAsync(buffer.AsMemory(offset, count)).ConfigureAwait(false);
#else
                int read = await stream.ReadAsync(buffer, offset, count).ConfigureAwait(false);
#endif
                if (read == 0)
                    return false;
                offset += read;
                count -= read;
            }
            return true;
        }

        #endregion // Listeners

        #region Processing

        /// <summary>
        /// The answer to a message from the address given, over a transport of TLS (or DTLS) or not: the response's bytes, or
        /// null of none - of what is not a STUN request it answers, which is discarded (RFC 8489 6.3). Of a transport of the
        /// caller's: a request whose handler sends the client more than its response is to be of <see cref="Receive"/>.
        /// </summary>
        public byte[] Process(byte[] buffer, int offset, int count, IPEndPoint from, bool secure)
        {
            byte[] answer = null;
            var connection = new StunServerConnection(secure ? StunServerProtocol.Dtls : StunServerProtocol.Udp, new IPEndPoint(IPAddress.Any, 0),
                Normalize(from), data => answer ??= data);
            Receive(connection, buffer, offset, count);
            return answer;
        }

        /// <summary>
        /// A message - or ChannelData - of a client's over a 5-tuple: a request answered over it, an indication or ChannelData
        /// handed to the handler of it, anything else discarded (RFC 8489 6.3).
        /// </summary>
        public void Receive(StunServerConnection connection, byte[] buffer, int offset, int count)
        {
            if (connection == null)
                throw new ArgumentNullException(nameof(connection));
            ReceiveCore(connection, buffer, offset, count);
        }

        // of the server's own loops: an exception of a message - of what it is, or of a handler - ends that message alone, not
        // the loop of the others
        private void ReceiveSafely(StunServerConnection connection, byte[] buffer, int offset, int count)
        {
            try
            {
                ReceiveCore(connection, buffer, offset, count);
            }
            catch (Exception ex)
            {
                Trace($"A message of {connection.RemoteEndPoint} failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void ReceiveCore(StunServerConnection connection, byte[] buffer, int offset, int count)
        {
            if (count >= 4 && StunFraming.IsChannelData(buffer[offset]))
            {
                DataHandler?.Invoke(connection, buffer, offset, count);
                return;
            }
            var request = StunMessage.Parse(buffer, offset, count);
            if (request == null || request.HasFingerprint && !request.VerifyFingerprint())
                return;
            if (request.Class == StunMessageClass.Indication)
            {
                // of an attribute it is not to be understood without, dropped (RFC 8489 6.3.2)
                if (request.GetUnknownComprehensionRequired(_options.IsKnownAttribute).Count == 0)
                    IndicationHandler?.Invoke(request, connection);
                return;
            }
            // a response is of no transaction of a server's; a method it supports neither itself nor of a handler is not one
            if (request.Class != StunMessageClass.Request || request.Method != StunMethod.Binding && RequestHandler == null)
                return;
            var from = connection.RemoteEndPoint;

            byte[] key = null;
            string username = null;
            var integrity = StunIntegrity.None;
            if (_options.Realm != null && (request.Method != StunMethod.Binding || _options.AuthenticateBinding))
            {
                var error = Authenticate(request, from, out key, out integrity, out username);
                if (error != null)
                {
                    connection.Send(Finish(error, request, null, StunIntegrity.None));
                    return;
                }
            }

            // of an attribute it is not to be understood without, a 420 that lists them (RFC 8489 6.3.1)
            var unknown = request.GetUnknownComprehensionRequired(_options.IsKnownAttribute);
            if (unknown.Count > 0)
            {
                var error = Error(request, StunErrorCode.UnknownAttribute, "Unknown Attribute").AddUnknownAttributes(unknown);
                connection.Send(Finish(error, request, key, integrity));
                return;
            }

            // a request of a method redirected - a Binding, of a server of TURN an Allocate (RFC 8656 7.2) - to another server: of
            // the request's address family (RFC 8489 10); its certificate's name, of a request of TLS of SHA-256
            var alternate = _options.RedirectedMethods.Contains(request.Method) ? _options.AlternateServer?.Invoke(from) : null;
            if (alternate != null && alternate.AddressFamily == from.AddressFamily)
            {
                var redirect = Error(request, StunErrorCode.TryAlternate, "Try Alternate").AddAddress(alternate, StunAttributeType.AlternateServer);
                if (connection.IsSecure && integrity == StunIntegrity.Sha256 && _options.AlternateDomain != null)
                    redirect.AddString(StunAttributeType.AlternateDomain, _options.AlternateDomain);
                Trace($"Redirected {from} to {alternate}");
                connection.Send(Finish(redirect, request, key, integrity));
                return;
            }

            StunMessage response;
            if (request.Method == StunMethod.Binding)
            {
                response = new StunMessage(request.Method, StunMessageClass.SuccessResponse, request.TransactionId).AddXorAddress(from);
            }
            else
            {
                var serverRequest = new StunServerRequest(request, connection, username);
                serverRequest.Respond = later => connection.Send(Finish(later, request, key, integrity));
                response = RequestHandler(serverRequest);
                if (response == null)
                    return;
            }
            connection.Send(Finish(response, request, key, integrity));
        }

        private static StunMessage Error(StunMessage request, int code, string reason)
            => new StunMessage(request.Method, StunMessageClass.ErrorResponse, request.TransactionId).AddError(code, reason);

        // its SOFTWARE, its integrity of the request's, and a FINGERPRINT, of a request of one
        private byte[] Finish(StunMessage response, StunMessage request, byte[] key, StunIntegrity integrity)
        {
            if (_options.Software != null)
                response.AddString(StunAttributeType.Software, _options.Software);
            return response.ToBytes(key, integrity, request.HasFingerprint);
        }

        private static IPEndPoint Normalize(IPEndPoint endPoint)
            => endPoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port) : endPoint;

        #endregion // Processing

        #region Credentials

        private StunSecurityFeatures Features
            => (_options.PasswordAlgorithms.Count > 0 ? StunSecurityFeatures.PasswordAlgorithms : StunSecurityFeatures.None)
               | (_options.UsernameAnonymity ? StunSecurityFeatures.UsernameAnonymity : StunSecurityFeatures.None);

        // the server's checks of long-term credentials (RFC 8489 9.2.4), in their order: the error response, or null of a request
        // authenticated, of the key and the integrity its response is signed of
        private StunMessage Authenticate(StunMessage request, IPEndPoint from, out byte[] key, out StunIntegrity integrity, out string authenticated)
        {
            key = null;
            integrity = StunIntegrity.None;
            authenticated = null;
            if (!request.HasIntegrity && !request.HasIntegritySha256)
                return Challenge(request, from, StunErrorCode.Unauthorized, "Unauthenticated");

            string nonce = request.Nonce;
            string realm = request.Realm;
            var userhash = request.GetAttribute(StunAttributeType.Userhash);
            string username = request.Username;
            if (username == null && userhash == null || realm == null || nonce == null)
                return Error(request, StunErrorCode.BadRequest, "Bad Request");

            // of the nonce cookie of "Password algorithms": both attributes, the list as it was sent, and one of it; else MD5,
            // of neither
            var algorithm = StunPasswordAlgorithm.Md5;
            bool listed = false;
            var features = StunCredentials.GetSecurityFeatures(nonce);
            if (features.HasValue && (features.Value & StunSecurityFeatures.PasswordAlgorithms) != 0)
            {
                var list = request.GetAttribute(StunAttributeType.PasswordAlgorithms);
                ushort? chosen = request.PasswordAlgorithm;
                if (list != null || chosen.HasValue)
                {
                    if (list == null || !chosen.HasValue || !list.Value.SequenceEqual(PasswordAlgorithmsValue())
                        || !_options.PasswordAlgorithms.Any(a => (ushort)a == chosen.Value))
                        return Error(request, StunErrorCode.BadRequest, "Bad Request");
                    algorithm = (StunPasswordAlgorithm)chosen.Value;
                    listed = true;
                }
            }

            // the user, of its name, or of its hash
            string password = null;
            if (realm == _options.Realm)
            {
                if (username != null && _options.Users.TryGetValue(username, out string found))
                {
                    password = found;
                }
                else if (userhash != null && _options.UsernameAnonymity)
                {
                    foreach (var user in _options.Users)
                    {
                        if (StunCredentials.UserHash(user.Key, realm).SequenceEqual(userhash.Value))
                        {
                            username = user.Key;
                            password = user.Value;
                            break;
                        }
                    }
                }
            }
            if (password == null)
                return Challenge(request, from, StunErrorCode.Unauthorized, "Unauthenticated");

            byte[] candidate = StunCredentials.LongTermKey(username, realm, password, algorithm);
            bool valid = request.HasIntegritySha256 ? request.VerifyIntegritySha256(candidate) : request.VerifyIntegrity(candidate);
            if (!valid)
                return Challenge(request, from, StunErrorCode.Unauthorized, "Unauthenticated");
            if (!IsNonceValid(nonce, from))
                return Challenge(request, from, StunErrorCode.StaleNonce, "Stale Nonce");

            // MESSAGE-INTEGRITY-SHA256, unless the request was of MD5 as of no algorithm listed, of MESSAGE-INTEGRITY then
            key = candidate;
            integrity = listed || request.HasIntegritySha256 ? StunIntegrity.Sha256 : StunIntegrity.Sha1;
            authenticated = username;
            return null;
        }

        private StunMessage Challenge(StunMessage request, IPEndPoint from, int code, string reason)
        {
            var error = Error(request, code, reason)
                .AddString(StunAttributeType.Realm, _options.Realm)
                .AddString(StunAttributeType.Nonce, CreateNonce(from));
            if (_options.PasswordAlgorithms.Count > 0)
                error.AddAttribute(StunAttributeType.PasswordAlgorithms, PasswordAlgorithmsValue());
            return error;
        }

        private byte[] PasswordAlgorithmsValue()
        {
            byte[] value = new byte[4 * _options.PasswordAlgorithms.Count];
            for (int i = 0; i < _options.PasswordAlgorithms.Count; i++)
                BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4 * i), (ushort)_options.PasswordAlgorithms[i]);
            return value;
        }

        // the nonce cookie, then the time the nonce was made and its HMAC of the source (RFC 8489 9.2.4: no two sources of one)
        private string CreateNonce(IPEndPoint from)
        {
            long now = DateTime.UtcNow.Ticks;
            byte[] time = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(time, now);
            return StunCredentials.CreateNonce(Features, ToBase64Url(time) + "." + ToBase64Url(Sign(time, from)));
        }

        private bool IsNonceValid(string nonce, IPEndPoint from)
        {
            if (!nonce.StartsWith(StunCredentials.NonceCookie, StringComparison.Ordinal) || nonce.Length < StunCredentials.NonceCookie.Length + 4)
                return false;
            // of the features of now: a nonce of others is of another configuration, and stale
            if (StunCredentials.GetSecurityFeatures(nonce) != Features)
                return false;
            string[] parts = nonce.Substring(StunCredentials.NonceCookie.Length + 4).Split('.');
            if (parts.Length != 2)
                return false;
            byte[] time = FromBase64Url(parts[0]);
            byte[] signature = FromBase64Url(parts[1]);
            if (time == null || signature == null || time.Length != 8)
                return false;
            byte[] expected = Sign(time, from);
            int difference = expected.Length ^ signature.Length;
            for (int i = 0; i < Math.Min(expected.Length, signature.Length); i++)
                difference |= expected[i] ^ signature[i];
            if (difference != 0)
                return false;
            var made = new DateTime(BinaryPrimitives.ReadInt64BigEndian(time), DateTimeKind.Utc);
            return DateTime.UtcNow - made <= _options.NonceLifetime;
        }

        private byte[] Sign(byte[] time, IPEndPoint from)
        {
            byte[] source = Encoding.UTF8.GetBytes(from.ToString());
            using (var hmac = new HMACSHA256(_nonceKey))
                return hmac.ComputeHash(time.Concat(source).ToArray()).Take(16).ToArray();
        }

        private static string ToBase64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static byte[] FromBase64Url(string text)
        {
            string base64 = text.Replace('-', '+').Replace('_', '/');
            base64 += new string('=', (4 - base64.Length % 4) % 4);
            try
            {
                return Convert.FromBase64String(base64);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        #endregion // Credentials

        public void Dispose()
        {
            _cts.Cancel();
            lock (_sync)
            {
                _tls?.Dispose();
                foreach (var socket in _udp)
                    socket.Dispose();
                foreach (var listener in _tcp)
                    listener.Stop();
                _udp.Clear();
                _tcp.Clear();
            }
        }
    }
}
