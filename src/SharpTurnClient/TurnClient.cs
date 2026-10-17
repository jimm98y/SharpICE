// SharpTurnClient
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

using SharpStunClient;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
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
        public TurnDataEventArgs(IPEndPoint peer, byte[] data)
        {
            Peer = peer;
            Data = data;
        }

        public IPEndPoint Peer { get; }
        public byte[] Data { get; }
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
        private const byte Udp = 17;
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
        private ushort _nextChannel = 0x4000;
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
            _client.IndicationReceived += OnIndication;
            _client.DataReceived += OnChannelData;
            _client.Closed += OnClosed;
        }

        /// <summary>
        /// A client of a server of a TURN URI (RFC 7065): "turn:host[:port][?transport=udp|tcp]" or "turns:..." of TLS - or DTLS,
        /// of "?transport=udp" - as <see cref="StunClient.ConnectAsync"/> connects; its credentials of the options given, SHA-256
        /// preferred of them.
        /// </summary>
        public static async Task<TurnClient> ConnectAsync(string uri, StunClientOptions options, CancellationToken cancellationToken = default)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            if (!StunUri.Parse(uri).IsTurn)
                throw new ArgumentException($"{uri} is no TURN URI.", nameof(uri));
            options.PreferSha256 = true;
            var client = await StunClient.ConnectAsync(uri, options, cancellationToken).ConfigureAwait(false);
            return new TurnClient(client, true);
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
            var request = new StunMessage(StunMethod.Allocate, StunMessageClass.Request)
                .AddAttribute(StunAttributeType.RequestedTransport, new byte[] { Udp, 0, 0, 0 });
            if (options.AddressFamily.HasValue)
                request.AddAttribute(StunAttributeType.RequestedAddressFamily, new byte[] { Family(options.AddressFamily.Value), 0, 0, 0 });
            if (options.Dual)
                request.AddAttribute(StunAttributeType.AdditionalAddressFamily, new byte[] { 2, 0, 0, 0 });
            if (options.Lifetime.HasValue)
                request.AddUInt32(StunAttributeType.Lifetime, (uint)options.Lifetime.Value.TotalSeconds);
            if (options.DontFragment)
                request.AddAttribute(StunAttributeType.DontFragment, new byte[0]);
            if (options.EvenPort || options.ReserveNextPort)
                request.AddAttribute(StunAttributeType.EvenPort, new byte[] { (byte)(options.ReserveNextPort ? 0x80 : 0) });
            if (options.ReservationToken != null)
                request.AddAttribute(StunAttributeType.ReservationToken, options.ReservationToken);
            AddSoftware(request);

            var response = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            var relayed = response.GetXorAddresses(StunAttributeType.XorRelayedAddress).Where(a => a != null).ToList();
            if (relayed.Count == 0)
                throw new TurnException(StunErrorCode.BadRequest, "The Allocate response has no XOR-RELAYED-ADDRESS.", response);

            lock (_sync)
            {
                _relayed.Clear();
                _relayed.AddRange(relayed);
                _allocated = true;
            }
            MappedEndPoint = response.GetXorAddress();
            ReservationToken = response.GetAttribute(StunAttributeType.ReservationToken)?.Value;
            var addressError = response.GetAttribute(StunAttributeType.AddressErrorCode);
            AddressError = addressError != null && addressError.Value.Length >= 4
                ? ((addressError.Value[2] & 0x7) * 100 + addressError.Value[3], System.Text.Encoding.UTF8.GetString(addressError.Value, 4, addressError.Value.Length - 4))
                : ((int, string)?)null;
            SetLifetime(response);
            _timer ??= new Timer(_ => Maintain(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        /// <summary>Refreshes the allocation (RFC 8656 8): of the lifetime given, or the server's default; of a family, its relay alone.</summary>
        /// <exception cref="TurnException">Of an error response: of 437, the allocation is gone.</exception>
        public async Task RefreshAsync(TimeSpan? lifetime = null, AddressFamily? family = null, CancellationToken cancellationToken = default)
        {
            var request = new StunMessage(StunMethod.Refresh, StunMessageClass.Request);
            if (lifetime.HasValue)
                request.AddUInt32(StunAttributeType.Lifetime, (uint)lifetime.Value.TotalSeconds);
            if (family.HasValue)
                request.AddAttribute(StunAttributeType.RequestedAddressFamily, new byte[] { Family(family.Value), 0, 0, 0 });
            AddSoftware(request);
            try
            {
                var response = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
                SetLifetime(response);
            }
            catch (TurnException ex) when (ex.Code == StunErrorCode.AllocationMismatch)
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
            var request = new StunMessage(StunMethod.Refresh, StunMessageClass.Request).AddUInt32(StunAttributeType.Lifetime, 0);
            AddSoftware(request);
            try
            {
                await RequestAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (TurnException ex) when (ex.Code == StunErrorCode.AllocationMismatch)
            {
            }
            finally
            {
                Forget();
            }
        }

        private void SetLifetime(StunMessage response)
        {
            uint seconds = response.GetUInt32(StunAttributeType.Lifetime) ?? 600;
            Lifetime = TimeSpan.FromSeconds(seconds);
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
            var request = new StunMessage(StunMethod.CreatePermission, StunMessageClass.Request);
            foreach (var address in addresses)
                request.AddXorAddress(new IPEndPoint(address, 0), StunAttributeType.XorPeerAddress);
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
            peer = Normalize(peer);
            ChannelState channel;
            lock (_sync)
            {
                channel = _channels.Values.FirstOrDefault(c => c.Peer.Equals(peer));
                if (channel == null)
                {
                    if (_nextChannel > 0x4FFF)
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
            byte[] number = new byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(number, channel.Number);
            var request = new StunMessage(StunMethod.ChannelBind, StunMessageClass.Request)
                .AddAttribute(StunAttributeType.ChannelNumber, number)
                .AddXorAddress(channel.Peer, StunAttributeType.XorPeerAddress);
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
                return _channels.Values.FirstOrDefault(c => c.Bound && c.Peer.Equals(peer))?.Number;
        }

        #endregion // Permissions and channels

        #region Data

        /// <summary>
        /// Sends data to the peer through the relay: of ChannelData of a channel bound to it, else of a Send indication (RFC 8656
        /// 11.1, 12.5), a permission of its address installed first, of none yet.
        /// </summary>
        public async Task SendAsync(IPEndPoint peer, byte[] buffer, int offset, int count, bool dontFragment = false, CancellationToken cancellationToken = default)
        {
            peer = Normalize(peer);
            await EnsurePermissionAsync(peer.Address, cancellationToken).ConfigureAwait(false);
            ushort? channel = ChannelOf(peer);
            if (channel.HasValue)
            {
                // over a stream, padded to 4 bytes (RFC 8656 12.5)
                int length = 4 + count;
                byte[] message = new byte[_client.Transport.IsStream ? (length + 3) & ~3 : length];
                BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0), channel.Value);
                BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)count);
                Buffer.BlockCopy(buffer, offset, message, 4, count);
                await _client.SendRawAsync(message, cancellationToken).ConfigureAwait(false);
                return;
            }

            byte[] data = new byte[count];
            Buffer.BlockCopy(buffer, offset, data, 0, count);
            var indication = new StunMessage(StunMethod.Send, StunMessageClass.Indication)
                .AddXorAddress(peer, StunAttributeType.XorPeerAddress)
                .AddAttribute(StunAttributeType.Data, data);
            if (dontFragment)
                indication.AddAttribute(StunAttributeType.DontFragment, new byte[0]);
            await _client.SendIndicationAsync(indication, cancellationToken).ConfigureAwait(false);
        }

        public Task SendAsync(IPEndPoint peer, byte[] data, CancellationToken cancellationToken = default) => SendAsync(peer, data, 0, data.Length, false, cancellationToken);

        // a Data indication: of a peer of a permission, its data or its ICMP error (RFC 8656 11.4, 11.6)
        private void OnIndication(object sender, StunMessageEventArgs e)
        {
            var message = e.Message;
            if (message.Method != StunMethod.Data)
                return;
            var peer = message.GetXorAddress(StunAttributeType.XorPeerAddress);
            if (peer == null || !HasPermission(peer.Address))
                return;
            var icmp = message.GetAttribute(StunAttributeType.Icmp);
            if (icmp != null && icmp.Value.Length >= 4)
            {
                IcmpReceived?.Invoke(this, new TurnIcmpEventArgs(peer, icmp.Value[2], icmp.Value[3]));
                return;
            }
            var data = message.GetAttribute(StunAttributeType.Data);
            if (data != null)
                DataReceived?.Invoke(this, new TurnDataEventArgs(peer, data.Value));
        }

        // ChannelData: of a channel bound, of its peer (RFC 8656 12.6)
        private void OnChannelData(object sender, StunDataEventArgs e)
        {
            if (e.Count < 4)
                return;
            ushort number = BinaryPrimitives.ReadUInt16BigEndian(e.Buffer.AsSpan(e.Offset));
            int length = BinaryPrimitives.ReadUInt16BigEndian(e.Buffer.AsSpan(e.Offset + 2));
            if (4 + length > e.Count)
                return;
            IPEndPoint peer;
            lock (_sync)
            {
                if (!_channels.TryGetValue(number, out var channel))
                    return;
                peer = channel.Peer;
            }
            byte[] data = new byte[length];
            Buffer.BlockCopy(e.Buffer, e.Offset + 4, data, 0, length);
            DataReceived?.Invoke(this, new TurnDataEventArgs(peer, data));
        }

        #endregion // Data

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

        private void OnClosed(object sender, Exception error) => Lost(new TurnException(StunErrorCode.AllocationMismatch, "The connection to the server ended."));

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

        private static byte Family(AddressFamily family) => family == AddressFamily.InterNetworkV6 ? (byte)2 : (byte)1;

        private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        private static IPEndPoint Normalize(IPEndPoint endPoint) => new IPEndPoint(Normalize(endPoint.Address), endPoint.Port);

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
