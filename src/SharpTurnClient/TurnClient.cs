// SharpTurnClient
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

using SharpStunClient;
using SharpStunCommon;
using SharpTurnCommon;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTurnClient
{
    /// <summary>What an Allocate request asks for (RFC 8656 7.1).</summary>
    public sealed class TurnAllocateOptions
    {
        /// <summary>The family of the relayed address: REQUESTED-ADDRESS-FAMILY; of none, the server's default, IPv4.</summary>
        public AddressFamily? AddressFamily { get; set; }

        /// <summary>An IPv6 relayed address too, of a dual allocation: ADDITIONAL-ADDRESS-FAMILY.</summary>
        public bool Dual { get; set; }

        /// <summary>The lifetime asked for; of none, the server's default.</summary>
        public TimeSpan? Lifetime { get; set; }

        /// <summary>Whether the server is to set the DF bit of what it relays, as Send indications of it ask: DONT-FRAGMENT.</summary>
        public bool DontFragment { get; set; }

        /// <summary>An even port: EVEN-PORT; and of <see cref="ReserveNextPort"/>, the one after it reserved for another allocation.</summary>
        public bool EvenPort { get; set; }
        public bool ReserveNextPort { get; set; }

        /// <summary>The token of a port reserved before, to allocate.</summary>
        public byte[] ReservationToken { get; set; }

        /// <summary>
        /// A TCP allocation (RFC 6062): a relayed address of TCP, of connections to and of peers - of
        /// <see cref="TurnClient.ConnectPeerAsync"/> and <see cref="TurnClient.AcceptPeerAsync"/> - rather than of datagrams.
        /// Of a client of TCP or TLS to the server alone, of none of <see cref="Dual"/>, <see cref="DontFragment"/>,
        /// <see cref="EvenPort"/>, <see cref="ReserveNextPort"/> or <see cref="ReservationToken"/>.
        /// </summary>
        public bool Tcp { get; set; }
    }

    /// <summary>A peer that connected to the relayed address of a TCP allocation (RFC 6062 4.4): to accept, or leave.</summary>
    public sealed class TurnConnectionAttemptEventArgs : EventArgs
    {
        public TurnConnectionAttemptEventArgs(IPEndPoint peer, uint connectionId)
        {
            Peer = peer;
            ConnectionId = connectionId;
        }

        public IPEndPoint Peer { get; }

        /// <summary>The server's number of the peer's connection: of <see cref="TurnClient.AcceptPeerAsync"/>, in 30 seconds.</summary>
        public uint ConnectionId { get; }
    }

    /// <summary>
    /// A connection to a peer through a TCP allocation (RFC 6062): a data connection of the client's to the server, bound to the
    /// peer's connection to the relay, whose bytes go to the peer as they are, and the peer's to it. It ends as the peer's does.
    /// </summary>
    public sealed class TurnTcpConnection : IDisposable
    {
        private readonly StunStreamTransport _transport;

        internal TurnTcpConnection(IPEndPoint peer, uint connectionId, Stream stream, StunStreamTransport transport)
        {
            Peer = peer;
            ConnectionId = connectionId;
            Stream = stream;
            _transport = transport;
        }

        public IPEndPoint Peer { get; }
        public uint ConnectionId { get; }

        /// <summary>The bytes to and of the peer: of TLS of a client of TLS to the server.</summary>
        public Stream Stream { get; }

        /// <summary>The address of the data connection, of the client's.</summary>
        public IPEndPoint LocalEndPoint => _transport.LocalEndPoint;

        /// <summary>Closes the data connection, and the server the peer's of it (RFC 6062 4.6).</summary>
        public void Dispose() => _transport.Dispose();
    }

    /// <summary>A TURN request the server refused: its error code and reason (RFC 8656 19).</summary>
    public sealed class TurnException : Exception
    {
        public TurnException(int code, string reason, StunMessage response = null) : base($"{code} {reason}")
        {
            Code = code;
            Reason = reason;
            Response = response;
        }

        public int Code { get; }
        public string Reason { get; }
        public StunMessage Response { get; }
    }

    /// <summary>Data a peer sent the relayed address, and which peer.</summary>
    public sealed class TurnDataEventArgs : EventArgs
    {
        internal TurnDataEventArgs()
        {
        }

        public TurnDataEventArgs(IPEndPoint peer, byte[] buffer, int offset, int count) => Set(peer, buffer, offset, count);

        internal TurnDataEventArgs Set(IPEndPoint peer, byte[] buffer, int offset, int count)
        {
            Peer = peer;
            Buffer = buffer;
            Offset = offset;
            Count = count;
            return this;
        }

        public IPEndPoint Peer { get; private set; }

        /// <summary>The buffer the data is in: the client's own again once the event returns, as are these arguments.</summary>
        public byte[] Buffer { get; private set; }
        public int Offset { get; private set; }
        public int Count { get; private set; }

        /// <summary>A copy of the data, to keep.</summary>
        public byte[] ToArray()
        {
            byte[] data = new byte[Count];
            System.Buffer.BlockCopy(Buffer, Offset, data, 0, Count);
            return data;
        }
    }

    /// <summary>An ICMP error of a datagram the server relayed to a peer (RFC 8656 11.6): its type and code.</summary>
    public sealed class TurnIcmpEventArgs : EventArgs
    {
        public TurnIcmpEventArgs(IPEndPoint peer, byte type, byte code)
        {
            Peer = peer;
            Type = type;
            Code = code;
        }

        public IPEndPoint Peer { get; }
        public byte Type { get; }
        public byte Code { get; }
    }

    /// <summary>
    /// A TURN client (RFC 8656): an allocation of a relayed address of UDP - or two, of IPv4 and IPv6 - over a
    /// <see cref="StunClient"/> of any of its transports, of its long-term credentials, SHA-256 preferred (RFC 8656 6). Data goes
    /// to a peer of a Send indication, or of ChannelData once a channel is bound to it, and comes of Data indications and
    /// ChannelData. The allocation is refreshed a minute before it expires, permissions every 4 minutes and channels every 9,
    /// as long as the client is.
    /// </summary>
    public sealed class TurnClient : IDisposable
    {
        private static readonly TimeSpan PermissionRefresh = TimeSpan.FromMinutes(4);
        private static readonly TimeSpan ChannelRefresh = TimeSpan.FromMinutes(9);

        private sealed class ChannelState
        {
            public ushort Number;
            public IPEndPoint Peer;
            public bool Bound;
            public DateTime BoundAt;
        }

        private readonly StunClient _client;
        private readonly bool _ownsClient;
        private readonly object _sync = new object();
        private readonly Dictionary<IPAddress, DateTime> _permissions = new Dictionary<IPAddress, DateTime>();
        private readonly Dictionary<IPAddress, Task> _creating = new Dictionary<IPAddress, Task>();
        private readonly Dictionary<ushort, ChannelState> _channels = new Dictionary<ushort, ChannelState>();
        private readonly List<IPEndPoint> _relayed = new List<IPEndPoint>();
        private ushort _nextChannel = TurnConstants.MinChannel;
        // of the transport's one receiving loop: told of again of each datagram
        private readonly TurnDataEventArgs _dataArgs = new TurnDataEventArgs();
        private DateTime _expires;
        private Timer _timer;
        private int _maintaining;
        private bool _allocated;
        private bool _disposed;

        /// <summary>A client over a STUN client connected to the server; disposed with it, of one it owns.</summary>
        public TurnClient(StunClient client, bool ownsClient = false)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _ownsClient = ownsClient;
            // of TURN's attributes, of the responses of a TURN server
            _client.Options.IsKnownAttribute = TurnAttributeType.IsKnownOfTurn;
            _client.IndicationReceived += OnIndication;
            _client.DataReceived += OnChannelData;
            _client.Closed += OnClosed;
        }

        /// <summary>
        /// A client not yet connected, of a STUN client of its own: of <see cref="ConnectAsync"/>, to a server of a TURN URI; its
        /// credentials of the options given, SHA-256 preferred of them.
        /// </summary>
        public TurnClient(StunClientOptions options) : this(new StunClient(Prefer(options)), true)
        {
        }

        private static StunClientOptions Prefer(StunClientOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            options.PreferSha256 = true;
            return options;
        }

        /// <summary>
        /// Connects to a server of a TURN URI (RFC 7065): "turn:host[:port][?transport=udp|tcp]" or "turns:..." of TLS - or DTLS,
        /// of "?transport=udp" - as <see cref="StunClient.ConnectAsync"/> connects.
        /// </summary>
        public Task ConnectAsync(string uri, CancellationToken cancellationToken = default)
        {
            if (!StunUri.Parse(uri).IsTurn)
                throw new ArgumentException($"{uri} is no TURN URI.", nameof(uri));
            return _client.ConnectAsync(uri, cancellationToken);
        }

        public StunClient Client => _client;

        /// <summary>The relayed transport addresses: one, or of a dual allocation, one of each family.</summary>
        public IReadOnlyList<IPEndPoint> RelayedEndPoints
        {
            get { lock (_sync) return _relayed.ToList(); }
        }

        /// <summary>The first relayed transport address; null of no allocation.</summary>
        public IPEndPoint RelayedEndPoint
        {
            get { lock (_sync) return _relayed.FirstOrDefault(); }
        }

        /// <summary>The client's address as the server sees it: of the Allocate response's XOR-MAPPED-ADDRESS.</summary>
        public IPEndPoint MappedEndPoint { get; private set; }

        /// <summary>The lifetime the server gave the allocation, of its last Allocate or Refresh.</summary>
        public TimeSpan Lifetime { get; private set; }

        /// <summary>The token of the port the server reserved of an EVEN-PORT, for another allocation.</summary>
        public byte[] ReservationToken { get; private set; }

        /// <summary>Of a dual allocation the server met in part, why it allocated no IPv6 address: ADDRESS-ERROR-CODE.</summary>
        public (int Code, string Reason)? AddressError { get; private set; }

        public bool IsAllocated
        {
            get { lock (_sync) return _allocated; }
        }

        /// <summary>Of a TCP allocation (RFC 6062): its peers of connections, not of datagrams.</summary>
        public bool IsTcp { get; private set; }

        /// <summary>
        /// Of a TCP allocation: a peer of a permission connected to the relayed address (RFC 6062 4.4) - of
        /// <see cref="AcceptPeerAsync"/>, its connection the client's; else closed of the server in 30 seconds.
        /// </summary>
        public event EventHandler<TurnConnectionAttemptEventArgs> ConnectionAttempt;

        /// <summary>Data a peer sent: of a Data indication, or of ChannelData, of a peer of a permission.</summary>
        public event EventHandler<TurnDataEventArgs> DataReceived;

        /// <summary>An ICMP error of what the server relayed to a peer.</summary>
        public event EventHandler<TurnIcmpEventArgs> IcmpReceived;

        /// <summary>The allocation is gone: refused of a refresh (437), or its connection ended.</summary>
        public event EventHandler<Exception> AllocationLost;

        #region Allocation

        /// <summary>Allocates a relayed address (RFC 8656 7).</summary>
        /// <exception cref="TurnException">Of an error response; of no response, of 408.</exception>
        public async Task AllocateAsync(TurnAllocateOptions options = null, CancellationToken cancellationToken = default)
        {
            options ??= new TurnAllocateOptions();
            if (options.Tcp)
            {
                // of a control connection of TCP or TLS, of none of what a relay of UDP is of (RFC 6062 4.1)
                if (!(_client.Transport is StunStreamTransport))
                    throw new InvalidOperationException("A TCP allocation is of a client of TCP or TLS to the server (RFC 6062 4.1).");
                if (options.Dual || options.DontFragment || options.EvenPort || options.ReserveNextPort || options.ReservationToken != null)
                    throw new ArgumentException("A TCP allocation is of none of Dual, DontFragment, EvenPort, ReserveNextPort or ReservationToken (RFC 6062 4.1).", nameof(options));
            }
            var request = new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddRequestedTransport(options.Tcp ? TurnConstants.Tcp : TurnConstants.Udp);
            if (options.AddressFamily.HasValue)
                request.AddAddressFamily(TurnAttributeType.RequestedAddressFamily, options.AddressFamily.Value);
            if (options.Dual)
                request.AddAddressFamily(TurnAttributeType.AdditionalAddressFamily, AddressFamily.InterNetworkV6);
            if (options.Lifetime.HasValue)
                request.AddLifetime(options.Lifetime.Value);
            if (options.DontFragment)
                request.AddAttribute(TurnAttributeType.DontFragment, new byte[0]);
            if (options.EvenPort || options.ReserveNextPort)
                request.AddEvenPort(options.ReserveNextPort);
            if (options.ReservationToken != null)
                request.AddAttribute(TurnAttributeType.ReservationToken, options.ReservationToken);
            AddSoftware(request);

            var response = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            var relayed = response.GetXorAddresses(TurnAttributeType.XorRelayedAddress).Where(a => a != null).ToList();
            if (relayed.Count == 0)
                throw new TurnException(StunErrorCode.BadRequest, "The Allocate response has no XOR-RELAYED-ADDRESS.", response);

            lock (_sync)
            {
                _relayed.Clear();
                _relayed.AddRange(relayed);
                _allocated = true;
            }
            IsTcp = options.Tcp;
            MappedEndPoint = response.GetXorAddress();
            ReservationToken = response.GetAttribute(TurnAttributeType.ReservationToken)?.Value;
            var addressError = response.GetAddressError();
            AddressError = addressError.HasValue ? (addressError.Value.Code, addressError.Value.Reason) : ((int, string)?)null;
            SetLifetime(response);
            _timer ??= new Timer(_ => Maintain(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        /// <summary>Refreshes the allocation (RFC 8656 8): of the lifetime given, or the server's default; of a family, its relay alone.</summary>
        /// <exception cref="TurnException">Of an error response: of 437, the allocation is gone.</exception>
        public async Task RefreshAsync(TimeSpan? lifetime = null, AddressFamily? family = null, CancellationToken cancellationToken = default)
        {
            var request = new StunMessage(TurnMethod.Refresh, StunMessageClass.Request);
            if (lifetime.HasValue)
                request.AddLifetime(lifetime.Value);
            if (family.HasValue)
                request.AddAddressFamily(TurnAttributeType.RequestedAddressFamily, family.Value);
            AddSoftware(request);
            try
            {
                var response = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
                SetLifetime(response);
            }
            catch (TurnException ex) when (ex.Code == TurnErrorCode.AllocationMismatch)
            {
                Lost(ex);
                throw;
            }
        }

        /// <summary>Deletes the allocation: a Refresh of a lifetime of 0, a 437 of one already gone as good as a success (RFC 8656 8.3).</summary>
        public async Task DeallocateAsync(CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (!_allocated)
                    return;
                _allocated = false;
            }
            var request = new StunMessage(TurnMethod.Refresh, StunMessageClass.Request).AddLifetime(TimeSpan.Zero);
            AddSoftware(request);
            try
            {
                await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (TurnException ex) when (ex.Code == TurnErrorCode.AllocationMismatch)
            {
            }
            finally
            {
                Forget();
            }
        }

        private void SetLifetime(StunMessage response)
        {
            Lifetime = response.GetLifetime() ?? TurnConstants.DefaultLifetime;
            lock (_sync)
                _expires = DateTime.UtcNow + Lifetime;
        }

        #endregion // Allocation

        #region Permissions and channels

        /// <summary>Installs or refreshes permissions of the peers' addresses (RFC 8656 10), kept refreshed from then on.</summary>
        public async Task CreatePermissionAsync(IEnumerable<IPAddress> peers, CancellationToken cancellationToken = default)
        {
            var addresses = peers.Distinct().ToList();
            if (addresses.Count == 0)
                return;
            var request = new StunMessage(TurnMethod.CreatePermission, StunMessageClass.Request);
            foreach (var address in addresses)
                request.AddXorAddress(new IPEndPoint(address, 0), TurnAttributeType.XorPeerAddress);
            await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                foreach (var address in addresses)
                    _permissions[address] = DateTime.UtcNow;
            }
        }

        public Task CreatePermissionAsync(params IPAddress[] peers) => CreatePermissionAsync((IEnumerable<IPAddress>)peers);

        /// <summary>Whether there is a permission of the address.</summary>
        public bool HasPermission(IPAddress peer)
        {
            lock (_sync)
                return _permissions.ContainsKey(Normalize(peer));
        }

        // a permission of the address, once: of a send to a peer of none yet
        private Task EnsurePermissionAsync(IPAddress address, CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                if (_permissions.ContainsKey(address))
                    return Task.CompletedTask;
                if (_creating.TryGetValue(address, out var creating))
                    return creating;
                var task = CreateOnceAsync(address, cancellationToken);
                _creating[address] = task;
                return task;
            }
        }

        private async Task CreateOnceAsync(IPAddress address, CancellationToken cancellationToken)
        {
            try
            {
                await CreatePermissionAsync(new[] { address }, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                lock (_sync)
                    _creating.Remove(address);
            }
        }

        /// <summary>
        /// Binds a channel to the peer (RFC 8656 12.1) - its permission with it - and the data to it goes as ChannelData from then
        /// on; kept rebound. The channel's number; of one bound to the peer already, it, rebound.
        /// </summary>
        public async Task<ushort> BindChannelAsync(IPEndPoint peer, CancellationToken cancellationToken = default)
        {
            if (IsTcp)
                throw new InvalidOperationException("A TCP allocation binds no channels: of ConnectPeerAsync, a connection to the peer (RFC 6062).");
            peer = Normalize(peer);
            ChannelState channel;
            lock (_sync)
            {
                channel = _channels.Values.FirstOrDefault(c => c.Peer.Equals(peer));
                if (channel == null)
                {
                    if (_nextChannel > TurnConstants.MaxChannel)
                        throw new InvalidOperationException("Every channel number is bound.");
                    channel = new ChannelState { Number = _nextChannel++, Peer = peer };
                    _channels[channel.Number] = channel;
                }
            }
            await BindAsync(channel, cancellationToken).ConfigureAwait(false);
            return channel.Number;
        }

        private async Task BindAsync(ChannelState channel, CancellationToken cancellationToken)
        {
            var request = new StunMessage(TurnMethod.ChannelBind, StunMessageClass.Request)
                .AddChannelNumber(channel.Number)
                .AddXorAddress(channel.Peer, TurnAttributeType.XorPeerAddress);
            await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                channel.Bound = true;
                channel.BoundAt = DateTime.UtcNow;
                _permissions[channel.Peer.Address] = DateTime.UtcNow;
            }
        }

        /// <summary>The channel bound to the peer; null of none.</summary>
        public ushort? ChannelOf(IPEndPoint peer)
        {
            peer = Normalize(peer);
            lock (_sync)
                return BoundChannelOf(peer)?.Number;
        }

        private ChannelState BoundChannelOf(IPEndPoint peer)
        {
            foreach (var channel in _channels.Values)
            {
                if (channel.Bound && channel.Peer.Equals(peer))
                    return channel;
            }
            return null;
        }

        /// <summary>
        /// Sends data to the peer at once, of ChannelData of a channel bound to it and of a permission of its address, in a
        /// buffer of a pool: false of none bound, as <see cref="SendAsync(IPEndPoint, byte[], int, int, bool, CancellationToken)"/>
        /// binds none but sends a Send indication. The buffer is the caller's again once it returns.
        /// </summary>
        public bool TrySend(IPEndPoint peer, byte[] buffer, int offset, int count)
        {
            peer = Normalize(peer);
            ushort number;
            lock (_sync)
            {
                var channel = BoundChannelOf(peer);
                if (channel == null || !_permissions.ContainsKey(peer.Address))
                    return false;
                number = channel.Number;
            }
            var transport = _client.Transport;
            if (transport == null)
                return false;
            // over a stream, padded to 4 bytes (RFC 8656 12.5)
            byte[] message = ArrayPool<byte>.Shared.Rent(StunFraming.ChannelDataSize(count, true));
            int length = TurnChannelData.Write(message, number, new ReadOnlySpan<byte>(buffer, offset, count), transport.IsStream);
            Task sent;
            try
            {
                sent = transport.SendAsync(message, 0, length);
            }
            catch
            {
                ArrayPool<byte>.Shared.Return(message);
                throw;
            }
            if (sent.IsCompleted)
            {
                ArrayPool<byte>.Shared.Return(message);
                sent.GetAwaiter().GetResult();
            }
            else
            {
                // of a stream whose write waits: the buffer back to the pool once it is written
                sent.ContinueWith((t, state) =>
                {
                    ArrayPool<byte>.Shared.Return((byte[])state);
                    _ = t.Exception;
                }, message, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
            return true;
        }

        #endregion // Permissions and channels

        #region Data

        /// <summary>
        /// Sends data to the peer through the relay: of ChannelData of a channel bound to it, else of a Send indication (RFC 8656
        /// 11.1, 12.5), a permission of its address installed first, of none yet.
        /// </summary>
        public async Task SendAsync(IPEndPoint peer, byte[] buffer, int offset, int count, bool dontFragment = false, CancellationToken cancellationToken = default)
        {
            if (IsTcp)
                throw new InvalidOperationException("A TCP allocation sends no datagrams: of ConnectPeerAsync, a connection to the peer (RFC 6062).");
            peer = Normalize(peer);
            if (TrySend(peer, buffer, offset, count))
                return;
            await EnsurePermissionAsync(peer.Address, cancellationToken).ConfigureAwait(false);
            ushort? channel = ChannelOf(peer);
            bool stream = _client.Transport.IsStream;
            byte[] message = ArrayPool<byte>.Shared.Rent(Math.Max(StunFraming.ChannelDataSize(count, true), TurnIndication.Size(peer, count, dontFragment)));
            try
            {
                // ChannelData, over a stream padded to 4 bytes (RFC 8656 12.5); else a Send indication
                int length = channel.HasValue
                    ? TurnChannelData.Write(message, channel.Value, new ReadOnlySpan<byte>(buffer, offset, count), stream)
                    : TurnIndication.Write(message, TurnMethod.Send, peer, new ReadOnlySpan<byte>(buffer, offset, count), dontFragment);
                await _client.SendRawAsync(message, 0, length, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(message);
            }
        }

        public Task SendAsync(IPEndPoint peer, byte[] data, CancellationToken cancellationToken = default) => SendAsync(peer, data, 0, data.Length, false, cancellationToken);

        // a Data indication: of a peer of a permission, its data or its ICMP error (RFC 8656 11.4, 11.6)
        private void OnIndication(object sender, StunMessageEventArgs e)
        {
            var message = e.Message;
            if (message.Method == TurnMethod.ConnectionAttempt)
            {
                OnConnectionAttempt(message);
                return;
            }
            if (message.Method != TurnMethod.Data)
                return;
            var peer = message.GetXorAddress(TurnAttributeType.XorPeerAddress);
            if (peer == null || !HasPermission(peer.Address))
                return;
            var icmp = message.GetIcmp();
            if (icmp != null)
            {
                IcmpReceived?.Invoke(this, new TurnIcmpEventArgs(peer, icmp.Value.Type, icmp.Value.Code));
                return;
            }
            var data = message.GetAttribute(TurnAttributeType.Data);
            if (data != null)
                DataReceived?.Invoke(this, _dataArgs.Set(peer, data.Value, 0, data.Value.Length));
        }

        // ChannelData: of a channel bound, of its peer (RFC 8656 12.6)
        private void OnChannelData(object sender, StunDataEventArgs e)
        {
            if (!TurnChannelData.TryRead(e.Buffer, e.Offset, e.Count, out ushort number, out int dataOffset, out int length))
                return;
            IPEndPoint peer;
            lock (_sync)
            {
                if (!_channels.TryGetValue(number, out var channel))
                    return;
                peer = channel.Peer;
            }
            DataReceived?.Invoke(this, _dataArgs.Set(peer, e.Buffer, dataOffset, length));
        }

        #endregion // Data

        #region TCP allocations

        /// <summary>
        /// Of a TCP allocation: a connection to the peer of the relayed address (RFC 6062 4.3) - a Connect, then a data connection
        /// of the client's own to the server, of a ConnectionBind of the same credentials - whose stream is the peer's bytes.
        /// </summary>
        /// <exception cref="TurnException">Of an error response: of 446, a connection of the peer's there is already; of 447, it failed.</exception>
        public async Task<TurnTcpConnection> ConnectPeerAsync(IPEndPoint peer, CancellationToken cancellationToken = default)
        {
            if (peer == null)
                throw new ArgumentNullException(nameof(peer));
            if (!IsTcp || !IsAllocated)
                throw new InvalidOperationException("A connection to a peer is of a TCP allocation (RFC 6062): AllocateAsync of TurnAllocateOptions.Tcp first.");
            peer = Normalize(peer);
            var request = new StunMessage(TurnMethod.Connect, StunMessageClass.Request).AddXorAddress(peer, TurnAttributeType.XorPeerAddress);
            AddSoftware(request);
            var response = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            uint? id = response.GetConnectionId();
            if (id == null)
                throw new TurnException(StunErrorCode.BadRequest, "The Connect response has no CONNECTION-ID.", response);
            return await BindConnectionAsync(peer, id.Value, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Of a TCP allocation: the connection of a peer that connected to the relayed address, of its
        /// <see cref="ConnectionAttempt"/> (RFC 6062 4.4) - a data connection of the client's own, of a ConnectionBind.
        /// </summary>
        /// <exception cref="TurnException">Of an error response: of 400, the server no longer has the peer's connection.</exception>
        public Task<TurnTcpConnection> AcceptPeerAsync(TurnConnectionAttemptEventArgs attempt, CancellationToken cancellationToken = default)
        {
            if (attempt == null)
                throw new ArgumentNullException(nameof(attempt));
            if (!IsTcp || !IsAllocated)
                throw new InvalidOperationException("A connection of a peer is of a TCP allocation (RFC 6062).");
            return BindConnectionAsync(attempt.Peer, attempt.ConnectionId, cancellationToken);
        }

        // a new connection to the server of the control connection's - of its TLS, and its certificate's name - bound to the
        // peer's of a ConnectionBind of the client's credentials; past its success response, the peer's bytes (RFC 6062 4.3)
        private async Task<TurnTcpConnection> BindConnectionAsync(IPEndPoint peer, uint connectionId, CancellationToken cancellationToken)
        {
            var control = _client.Transport ?? throw new InvalidOperationException("The client is not connected.");
            var transport = await StunStreamTransport.ConnectAsync(control.RemoteEndPoint, _client.TlsHost, _client.Options.CertificateValidation, cancellationToken).ConfigureAwait(false);
            try
            {
                // nothing of the connection read as STUN past its ConnectionBind's success
                transport.DetachAfter = message => message.Method == TurnMethod.ConnectionBind && message.Class == StunMessageClass.SuccessResponse;
                using (var bind = new StunClient(transport, _client.Options))
                {
                    var request = new StunMessage(TurnMethod.ConnectionBind, StunMessageClass.Request).AddConnectionId(connectionId);
                    AddSoftware(request);
                    var response = await bind.RequestAsync(request, cancellationToken).ConfigureAwait(false);
                    if (response == null)
                        throw new TurnException(408, "Request Timeout");
                    if (response.Class == StunMessageClass.ErrorResponse)
                    {
                        var error = response.Error;
                        throw new TurnException(error?.Code ?? 0, error?.Reason ?? "", response);
                    }
                }
                var stream = await transport.DetachedAsync().ConfigureAwait(false);
                return new TurnTcpConnection(peer, connectionId, stream, transport);
            }
            catch
            {
                transport.Dispose();
                throw;
            }
        }

        // a ConnectionAttempt (RFC 6062 4.4): of the server alone, as of the control connection of TCP or TLS
        private void OnConnectionAttempt(StunMessage message)
        {
            if (!IsTcp)
                return;
            var peer = message.GetXorAddress(TurnAttributeType.XorPeerAddress);
            uint? id = message.GetConnectionId();
            if (peer == null || id == null)
                return;
            ConnectionAttempt?.Invoke(this, new TurnConnectionAttemptEventArgs(Normalize(peer), id.Value));
        }

        #endregion // TCP allocations

        #region Maintenance

        // the allocation refreshed a minute before it expires - or at half its lifetime, of a short one - permissions every 4
        // minutes, channels every 9 (RFC 8656 8, 9, 12)
        private void Maintain()
        {
            if (Interlocked.Exchange(ref _maintaining, 1) == 1)
                return;
            _ = MaintainAsync();
        }

        private async Task MaintainAsync()
        {
            try
            {
                DateTime now = DateTime.UtcNow;
                bool refresh;
                List<IPAddress> permissions;
                List<ChannelState> channels;
                lock (_sync)
                {
                    if (!_allocated || _disposed)
                        return;
                    TimeSpan margin = Lifetime > TimeSpan.FromMinutes(2) ? TimeSpan.FromMinutes(1) : TimeSpan.FromTicks(Lifetime.Ticks / 2);
                    refresh = now >= _expires - margin;
                    permissions = _permissions.Where(p => now - p.Value >= PermissionRefresh).Select(p => p.Key).ToList();
                    channels = _channels.Values.Where(c => c.Bound && now - c.BoundAt >= ChannelRefresh).ToList();
                }
                if (refresh)
                    await RefreshAsync().ConfigureAwait(false);
                foreach (var channel in channels)
                    await BindAsync(channel, CancellationToken.None).ConfigureAwait(false);
                if (permissions.Count > 0)
                    await CreatePermissionAsync(permissions).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TurnException || ex is StunException || ex is ObjectDisposedException || ex is SocketException)
            {
            }
            finally
            {
                Interlocked.Exchange(ref _maintaining, 0);
            }
        }

        private void OnClosed(object sender, Exception error) => Lost(new TurnException(TurnErrorCode.AllocationMismatch, "The connection to the server ended."));

        private void Lost(Exception error)
        {
            lock (_sync)
            {
                if (!_allocated)
                    return;
                _allocated = false;
            }
            Forget();
            AllocationLost?.Invoke(this, error);
        }

        private void Forget()
        {
            lock (_sync)
            {
                _relayed.Clear();
                _permissions.Clear();
                _channels.Clear();
            }
        }

        #endregion // Maintenance

        // the response of a success; else an exception of the error, or of no answer, 408
        private async Task<StunMessage> RequestAsync(StunMessage request, CancellationToken cancellationToken)
        {
            var response = await _client.RequestAsync(request, cancellationToken).ConfigureAwait(false);
            if (response == null)
                throw new TurnException(408, "Request Timeout");
            if (response.Class == StunMessageClass.ErrorResponse)
            {
                var error = response.Error;
                throw new TurnException(error?.Code ?? 0, error?.Reason ?? "", response);
            }
            return response;
        }

        private void AddSoftware(StunMessage request)
        {
            if (_client.Options.Software != null)
                request.AddString(StunAttributeType.Software, _client.Options.Software);
        }

        private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        private static IPEndPoint Normalize(IPEndPoint endPoint) => endPoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port) : endPoint;

        /// <summary>Stops refreshing; of a client it owns, deletes the allocation - waiting a second for it - and disposes the client.</summary>
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            _timer?.Dispose();
            _client.IndicationReceived -= OnIndication;
            _client.DataReceived -= OnChannelData;
            _client.Closed -= OnClosed;
            if (_ownsClient)
            {
                try
                {
                    DeallocateAsync().Wait(TimeSpan.FromSeconds(1));
                }
                catch (AggregateException)
                {
                }
                _client.Dispose();
            }
        }
    }
}
