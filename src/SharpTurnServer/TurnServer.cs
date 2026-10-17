// SharpTurnServer
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
using SharpStunServer;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTurnServer
{
    public sealed class TurnServerOptions
    {
        /// <summary>
        /// The options of the STUN server underneath: its realm and users - of the long-term credentials TURN is to require
        /// (RFC 8656 5) - its certificate, its alternate servers. A Binding request is answered of no credentials, as of a
        /// server of STUN.
        /// </summary>
        public StunServerOptions Stun { get; set; } = new StunServerOptions { AuthenticateBinding = false, Software = "SharpTurnServer" };

        /// <summary>
        /// The address of the IPv4 relayed transport addresses; of none, the address a client's 5-tuple is of, or - of a listener
        /// of any address - the first IPv4 one of an interface that is up.
        /// </summary>
        public IPAddress RelayAddress { get; set; }

        /// <summary>The address of the IPv6 relayed transport addresses; of none, IPv6 relays are not allocated (440).</summary>
        public IPAddress RelayAddressV6 { get; set; }

        /// <summary>
        /// The address a relayed transport address is told of to the client, of a server behind a NAT that maps its relays'
        /// ports alike; of none, the relay's own.
        /// </summary>
        public IPAddress AdvertisedRelayAddress { get; set; }

        /// <summary>The ports of the relays: of the dynamic range, as RFC 8656 7.2 recommends.</summary>
        public int PortMin { get; set; } = 49152;
        public int PortMax { get; set; } = 65535;

        /// <summary>The lifetime of an allocation, and the longest a client may ask for (RFC 8656 7.2: an hour at most).</summary>
        public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromSeconds(600);
        public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromSeconds(3600);

        /// <summary>How many allocations a user may have at once; more are answered 486.</summary>
        public int MaxAllocationsPerUser { get; set; } = 10;

        /// <summary>
        /// Whether data may be relayed to and of a peer: of none given, of any; of one refused, its permission or channel is
        /// answered 403 and a Send indication to it dropped (RFC 8656 10.2, 11.2, 12.2) - of a server that is not to reach its
        /// own network, of its private addresses.
        /// </summary>
        public Func<IPEndPoint, bool> AllowPeer { get; set; }

        /// <summary>What it does, a line at a time, of anything given.</summary>
        public Action<string> Trace { get; set; }
    }

    /// <summary>
    /// A TURN server (RFC 8656) of UDP allocations, over UDP, TCP, TLS and DTLS between the client and it - the transports of
    /// <see cref="StunServer"/>, which it answers Binding requests of too. Of each allocation, a relay of UDP of its own - or
    /// two, of IPv4 and IPv6 - its permissions and channels; the peers' data relayed to the client as Data indications, or as
    /// ChannelData of a channel bound to the peer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Of Allocate: REQUESTED-TRANSPORT of UDP alone (442), REQUESTED-ADDRESS-FAMILY (440), ADDITIONAL-ADDRESS-FAMILY of a dual
    /// allocation, its partial failure of ADDRESS-ERROR-CODE, EVEN-PORT and its reservation of the next port of a
    /// RESERVATION-TOKEN held 30 seconds, DONT-FRAGMENT, LIFETIME, and a quota of each user (486). A retransmitted Allocate is
    /// answered again, as one of another transaction of the 5-tuple is answered 437. A request of an allocation of other
    /// credentials than the ones it was made of is answered 441; one of no allocation, 437.
    /// </para>
    /// <para>
    /// An allocation of TCP or TLS ends with its connection; one of UDP or DTLS, with its lifetime. ICMP errors the relays get
    /// are not told of: the system does not say of which peer they are. TCP allocations (RFC 6062) are not done.
    /// </para>
    /// </remarks>
    public sealed class TurnServer : IDisposable
    {
        public static readonly TimeSpan PermissionLifetime = TimeSpan.FromSeconds(300);
        public static readonly TimeSpan ChannelLifetime = TimeSpan.FromSeconds(600);
        private static readonly TimeSpan ReservationLifetime = TimeSpan.FromSeconds(30);
        private const byte Udp = 17;

        private sealed class Relay
        {
            public Socket Socket;
            public IPEndPoint EndPoint;
            public IPEndPoint Advertised;
            public DateTime Expires;
            public AddressFamily Family => EndPoint.AddressFamily;
        }

        private sealed class Channel
        {
            public ushort Number;
            public IPEndPoint Peer;
            public DateTime Expires;
        }

        private sealed class Allocation
        {
            public string Key;
            public StunServerConnection Connection;
            public string Username;
            public byte[] TransactionId;
            public byte[] ReservationToken;
            public StunMessage AddressError;
            public readonly List<Relay> Relays = new List<Relay>();
            public readonly Dictionary<IPAddress, DateTime> Permissions = new Dictionary<IPAddress, DateTime>();
            public readonly Dictionary<ushort, Channel> Channels = new Dictionary<ushort, Channel>();
            public bool Closed;

            public Relay RelayOf(AddressFamily family) => Relays.FirstOrDefault(r => r.Family == family);

            public Channel ChannelOf(IPEndPoint peer) => Channels.Values.FirstOrDefault(c => c.Peer.Equals(peer));
        }

        private sealed class Reservation
        {
            public Socket Socket;
            public DateTime Expires;
        }

        private readonly TurnServerOptions _options;
        private readonly StunServer _stun;
        private readonly object _sync = new object();
        private readonly Dictionary<string, Allocation> _allocations = new Dictionary<string, Allocation>();
        private readonly Dictionary<string, Reservation> _reservations = new Dictionary<string, Reservation>();
        private readonly Random _random = new Random();
        private readonly Timer _timer;

        public TurnServer(TurnServerOptions options = null)
        {
            _options = options ?? new TurnServerOptions();
            _stun = new StunServer(_options.Stun)
            {
                RequestHandler = OnRequest,
                IndicationHandler = OnIndication,
                DataHandler = OnChannelData,
            };
            _stun.ConnectionClosed += (s, connection) => Remove(connection.Key, "its connection ended");
            _timer = new Timer(_ => Sweep(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        }

        /// <summary>The STUN server underneath, of its listeners.</summary>
        public StunServer Stun => _stun;

        public IPEndPoint ListenUdp(IPEndPoint endPoint) => _stun.ListenUdp(endPoint);
        public IPEndPoint ListenTcp(IPEndPoint endPoint) => _stun.ListenTcp(endPoint);
        public IPEndPoint ListenTls(IPEndPoint endPoint) => _stun.ListenTls(endPoint);
        public IPEndPoint ListenDtls(IPEndPoint endPoint) => _stun.ListenDtls(endPoint);

        /// <summary>The allocations there are.</summary>
        public int AllocationCount
        {
            get { lock (_sync) return _allocations.Count; }
        }

        private void Trace(string message) => _options.Trace?.Invoke(message);

        #region Requests

        private StunMessage OnRequest(StunServerRequest request)
        {
            switch (request.Message.Method)
            {
                case StunMethod.Allocate:
                    return Allocate(request);
                case StunMethod.Refresh:
                    return OfAllocation(request, Refresh);
                case StunMethod.CreatePermission:
                    return OfAllocation(request, CreatePermission);
                case StunMethod.ChannelBind:
                    return OfAllocation(request, ChannelBind);
                default:
                    return null;
            }
        }

        // a request of the 5-tuple's allocation, of the credentials it was made of (RFC 8656 5)
        private StunMessage OfAllocation(StunServerRequest request, Func<StunServerRequest, Allocation, StunMessage> handler)
        {
            Allocation allocation;
            lock (_sync)
                _allocations.TryGetValue(request.Connection.Key, out allocation);
            if (allocation == null || allocation.Closed)
                return request.Error(StunErrorCode.AllocationMismatch, "Allocation Mismatch");
            if (_options.Stun.Realm != null && allocation.Username != request.Username)
                return request.Error(StunErrorCode.WrongCredentials, "Wrong Credentials");
            return handler(request, allocation);
        }

        private StunMessage Allocate(StunServerRequest request)
        {
            var message = request.Message;
            string key = request.Connection.Key;
            lock (_sync)
            {
                // a retransmission of the transaction that made it answered again; another of the 5-tuple, 437 (RFC 8656 7.2)
                if (_allocations.TryGetValue(key, out var existing) && !existing.Closed)
                {
                    return existing.TransactionId.SequenceEqual(message.TransactionId)
                        ? Allocated(request, existing)
                        : request.Error(StunErrorCode.AllocationMismatch, "Allocation Mismatch");
                }
            }

            var transport = message.GetAttribute(StunAttributeType.RequestedTransport);
            if (transport == null || transport.Value.Length != 4)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (transport.Value[0] != Udp)
                return request.Error(StunErrorCode.UnsupportedTransportProtocol, "Unsupported Transport Protocol");

            var token = message.GetAttribute(StunAttributeType.ReservationToken);
            var evenPort = message.GetAttribute(StunAttributeType.EvenPort);
            var requestedFamily = message.GetAttribute(StunAttributeType.RequestedAddressFamily);
            var additionalFamily = message.GetAttribute(StunAttributeType.AdditionalAddressFamily);
            bool reserveNext = evenPort != null && evenPort.Value.Length >= 1 && (evenPort.Value[0] & 0x80) != 0;
            if (token != null && (evenPort != null || requestedFamily != null || additionalFamily != null))
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (requestedFamily != null && additionalFamily != null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (reserveNext && additionalFamily != null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (additionalFamily != null && (additionalFamily.Value.Length < 1 || additionalFamily.Value[0] != 2))
                return request.Error(StunErrorCode.BadRequest, "Bad Request");

            // the family asked for, IPv4 of none (RFC 8656 7.2)
            var family = AddressFamily.InterNetwork;
            if (requestedFamily != null)
            {
                if (requestedFamily.Value.Length < 1 || requestedFamily.Value[0] != 1 && requestedFamily.Value[0] != 2)
                    return request.Error(StunErrorCode.AddressFamilyNotSupported, "Address Family not Supported");
                family = requestedFamily.Value[0] == 2 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            }
            if (token == null && RelayAddressOf(family, request.Connection) == null)
                return request.Error(StunErrorCode.AddressFamilyNotSupported, "Address Family not Supported");

            lock (_sync)
            {
                if (request.Username != null && _allocations.Values.Count(a => a.Username == request.Username) >= _options.MaxAllocationsPerUser)
                    return request.Error(StunErrorCode.AllocationQuotaReached, "Allocation Quota Reached");
            }

            DateTime expires = DateTime.UtcNow + Lifetime(message, false);
            var allocation = new Allocation
            {
                Key = key,
                Connection = request.Connection,
                Username = request.Username,
                TransactionId = message.TransactionId,
            };

            if (token != null)
            {
                // of a port reserved of an EVEN-PORT before
                Reservation reservation;
                lock (_sync)
                {
                    string tokenKey = Convert.ToBase64String(token.Value);
                    if (_reservations.TryGetValue(tokenKey, out reservation))
                        _reservations.Remove(tokenKey);
                }
                if (reservation == null || reservation.Expires < DateTime.UtcNow)
                {
                    reservation?.Socket.Dispose();
                    return request.Error(StunErrorCode.InsufficientCapacity, "Insufficient Capacity");
                }
                allocation.Relays.Add(MakeRelay(reservation.Socket, expires));
            }
            else
            {
                var address = RelayAddressOf(family, request.Connection);
                Socket reserved = null;
                var socket = evenPort != null ? BindEven(address, reserveNext, out reserved) : Bind(address);
                if (socket == null)
                    return request.Error(StunErrorCode.InsufficientCapacity, "Insufficient Capacity");
                allocation.Relays.Add(MakeRelay(socket, expires));
                if (reserved != null)
                {
                    byte[] value = new byte[8];
                    using (var random = RandomNumberGenerator.Create())
                        random.GetBytes(value);
                    allocation.ReservationToken = value;
                    lock (_sync)
                        _reservations[Convert.ToBase64String(value)] = new Reservation { Socket = reserved, Expires = DateTime.UtcNow + ReservationLifetime };
                }

                // the IPv6 relay of a dual allocation, or the reason there is none (RFC 8656 7.2 step 9)
                if (additionalFamily != null)
                {
                    var v6 = RelayAddressOf(AddressFamily.InterNetworkV6, request.Connection);
                    var second = v6 != null ? Bind(v6) : null;
                    if (second != null)
                        allocation.Relays.Add(MakeRelay(second, expires));
                    else
                        allocation.AddressError = new StunMessage(StunMethod.Allocate, StunMessageClass.SuccessResponse)
                            .AddError(v6 == null ? StunErrorCode.AddressFamilyNotSupported : StunErrorCode.InsufficientCapacity, v6 == null ? "Address Family not Supported" : "Insufficient Capacity");
                }
            }

            lock (_sync)
                _allocations[key] = allocation;
            foreach (var relay in allocation.Relays)
                _ = RelayAsync(allocation, relay);
            Trace($"Allocated {string.Join(", ", allocation.Relays.Select(r => r.EndPoint))} for {request.Connection.RemoteEndPoint} of {allocation.Username}");
            return Allocated(request, allocation);
        }

        private StunMessage Allocated(StunServerRequest request, Allocation allocation)
        {
            var response = request.Success();
            foreach (var relay in allocation.Relays)
                response.AddXorAddress(relay.Advertised, StunAttributeType.XorRelayedAddress);
            response.AddUInt32(StunAttributeType.Lifetime, Seconds(allocation.Relays.Max(r => r.Expires) - DateTime.UtcNow));
            if (allocation.ReservationToken != null)
                response.AddAttribute(StunAttributeType.ReservationToken, allocation.ReservationToken);
            response.AddXorAddress(request.Connection.RemoteEndPoint);
            if (allocation.AddressError != null)
            {
                // ADDRESS-ERROR-CODE: of IPv6, the family not allocated, then as an ERROR-CODE is (RFC 8656 18.12)
                byte[] error = allocation.AddressError.GetAttribute(StunAttributeType.ErrorCode).Value.ToArray();
                error[0] = 2;
                response.AddAttribute(StunAttributeType.AddressErrorCode, error);
            }
            return response;
        }

        private StunMessage Refresh(StunServerRequest request, Allocation allocation)
        {
            var message = request.Message;
            List<Relay> relays;
            var requestedFamily = message.GetAttribute(StunAttributeType.RequestedAddressFamily);
            lock (_sync)
            {
                relays = allocation.Relays.ToList();
                if (requestedFamily != null)
                {
                    var family = requestedFamily.Value.Length >= 1 && requestedFamily.Value[0] == 2 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                    relays = relays.Where(r => r.Family == family).ToList();
                    if (relays.Count == 0)
                        return request.Error(StunErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
                }
            }

            var lifetime = Lifetime(message, true);
            var response = request.Success();
            if (lifetime == TimeSpan.Zero)
            {
                foreach (var relay in relays)
                    RemoveRelay(allocation, relay, "deleted by its client");
                response.AddUInt32(StunAttributeType.Lifetime, 0);
                return response;
            }
            lock (_sync)
            {
                foreach (var relay in relays)
                    relay.Expires = DateTime.UtcNow + lifetime;
            }
            response.AddUInt32(StunAttributeType.Lifetime, Seconds(lifetime));
            return response;
        }

        private StunMessage CreatePermission(StunServerRequest request, Allocation allocation)
        {
            var peers = request.Message.GetXorAddresses(StunAttributeType.XorPeerAddress);
            if (peers.Count == 0 || peers.Any(p => p == null))
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            lock (_sync)
            {
                if (peers.Any(p => allocation.RelayOf(p.AddressFamily) == null))
                    return request.Error(StunErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
            }
            if (_options.AllowPeer != null && peers.Any(p => !_options.AllowPeer(p)))
                return request.Error(StunErrorCode.Forbidden, "Forbidden");
            lock (_sync)
            {
                foreach (var peer in peers)
                    allocation.Permissions[peer.Address] = DateTime.UtcNow + PermissionLifetime;
            }
            return request.Success();
        }

        private StunMessage ChannelBind(StunServerRequest request, Allocation allocation)
        {
            var message = request.Message;
            var number = message.GetAttribute(StunAttributeType.ChannelNumber);
            var peer = message.GetXorAddress(StunAttributeType.XorPeerAddress);
            if (number == null || number.Value.Length != 4 || peer == null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            ushort channel = BinaryPrimitives.ReadUInt16BigEndian(number.Value);
            if (channel < 0x4000 || channel > 0x4FFF)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            lock (_sync)
            {
                if (allocation.RelayOf(peer.AddressFamily) == null)
                    return request.Error(StunErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
            }
            if (_options.AllowPeer != null && !_options.AllowPeer(peer))
                return request.Error(StunErrorCode.Forbidden, "Forbidden");

            lock (_sync)
            {
                // the channel bound to another peer, or the peer to another channel (RFC 8656 12.2)
                if (allocation.Channels.TryGetValue(channel, out var bound) && !bound.Peer.Equals(peer))
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
                var other = allocation.ChannelOf(peer);
                if (other != null && other.Number != channel)
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");

                allocation.Channels[channel] = new Channel { Number = channel, Peer = peer, Expires = DateTime.UtcNow + ChannelLifetime };
                allocation.Permissions[peer.Address] = DateTime.UtcNow + PermissionLifetime;
            }
            return request.Success();
        }

        // the lifetime asked for, of the default and the maximum (RFC 8656 7.2, 8.2): of a Refresh of 0, 0
        private TimeSpan Lifetime(StunMessage message, bool refresh)
        {
            uint? asked = message.GetUInt32(StunAttributeType.Lifetime);
            if (refresh && asked == 0)
                return TimeSpan.Zero;
            if (asked == null)
                return _options.DefaultLifetime;
            var lifetime = TimeSpan.FromSeconds(Math.Min(asked.Value, _options.MaxLifetime.TotalSeconds));
            return lifetime > _options.DefaultLifetime ? lifetime : _options.DefaultLifetime;
        }

        private static uint Seconds(TimeSpan time) => (uint)Math.Max(0, Math.Round(time.TotalSeconds));

        #endregion // Requests

        #region Relays

        private IPAddress RelayAddressOf(AddressFamily family, StunServerConnection connection)
        {
            if (family == AddressFamily.InterNetworkV6)
                return _options.RelayAddressV6;
            if (_options.RelayAddress != null)
                return _options.RelayAddress;
            var local = connection.LocalEndPoint.Address;
            if (local.AddressFamily == AddressFamily.InterNetwork && !local.Equals(IPAddress.Any))
                return local;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;
                var address = nic.GetIPProperties().UnicastAddresses.Select(u => u.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (address != null)
                    return address;
            }
            return null;
        }

        private Relay MakeRelay(Socket socket, DateTime expires)
        {
            var endPoint = (IPEndPoint)socket.LocalEndPoint;
            var advertised = _options.AdvertisedRelayAddress != null && endPoint.AddressFamily == _options.AdvertisedRelayAddress.AddressFamily
                ? new IPEndPoint(_options.AdvertisedRelayAddress, endPoint.Port)
                : endPoint;
            return new Relay { Socket = socket, EndPoint = endPoint, Advertised = advertised, Expires = expires };
        }

        // a port of the range at random (RFC 6056), as RFC 8656 7.2 recommends
        private Socket Bind(IPAddress address)
        {
            for (int attempt = 0; attempt < 64; attempt++)
            {
                int port;
                lock (_random)
                    port = _random.Next(_options.PortMin, _options.PortMax + 1);
                var socket = TryBind(address, port);
                if (socket != null)
                    return socket;
            }
            return null;
        }

        // an even port, and of a reservation, the odd one after it too
        private Socket BindEven(IPAddress address, bool reserveNext, out Socket next)
        {
            next = null;
            for (int attempt = 0; attempt < 64; attempt++)
            {
                int port;
                lock (_random)
                    port = _random.Next(_options.PortMin, _options.PortMax) & ~1;
                if (port < _options.PortMin || port + (reserveNext ? 1 : 0) > _options.PortMax)
                    continue;
                var socket = TryBind(address, port);
                if (socket == null)
                    continue;
                if (!reserveNext)
                    return socket;
                next = TryBind(address, port + 1);
                if (next != null)
                    return socket;
                socket.Dispose();
            }
            return null;
        }

        private static Socket TryBind(IPAddress address, int port)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.ExclusiveAddressUse = true;
                socket.Bind(new IPEndPoint(address, port));
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    // Windows reports an ICMP port unreachable of a datagram sent before as a reset of the next receive
                    const int SIO_UDP_CONNRESET = -1744830452;
                    socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                }
                return socket;
            }
            catch (SocketException)
            {
                socket.Dispose();
                return null;
            }
        }

        // the peers' datagrams: of a permission of their address, to the client - of ChannelData of a channel bound to the peer,
        // else of a Data indication (RFC 8656 11.3, 12.7)
        private async Task RelayAsync(Allocation allocation, Relay relay)
        {
            byte[] buffer = new byte[65536];
            var any = new IPEndPoint(relay.Family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            while (true)
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await relay.Socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                var peer = (IPEndPoint)result.RemoteEndPoint;
                if (peer.Address.IsIPv4MappedToIPv6)
                    peer = new IPEndPoint(peer.Address.MapToIPv4(), peer.Port);
                Channel channel;
                lock (_sync)
                {
                    if (allocation.Closed || !allocation.Permissions.TryGetValue(peer.Address, out DateTime until) || until < DateTime.UtcNow)
                        continue;
                    channel = allocation.ChannelOf(peer);
                    if (channel != null && channel.Expires < DateTime.UtcNow)
                        channel = null;
                }

                int count = result.ReceivedBytes;
                byte[] message;
                if (channel != null)
                {
                    int length = 4 + count;
                    message = new byte[allocation.Connection.IsStream ? (length + 3) & ~3 : length];
                    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(0), channel.Number);
                    BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)count);
                    Buffer.BlockCopy(buffer, 0, message, 4, count);
                }
                else
                {
                    byte[] data = new byte[count];
                    Buffer.BlockCopy(buffer, 0, data, 0, count);
                    message = new StunMessage(StunMethod.Data, StunMessageClass.Indication)
                        .AddXorAddress(peer, StunAttributeType.XorPeerAddress)
                        .AddAttribute(StunAttributeType.Data, data)
                        .ToBytes(null, false);
                }
                allocation.Connection.Send(message);
            }
        }

        // a Send indication: to a peer of a permission, of the DF bit of a DONT-FRAGMENT (RFC 8656 11.2)
        private void OnIndication(StunMessage indication, StunServerConnection connection)
        {
            if (indication.Method != StunMethod.Send)
                return;
            var peer = indication.GetXorAddress(StunAttributeType.XorPeerAddress);
            var data = indication.GetAttribute(StunAttributeType.Data);
            if (peer == null || data == null)
                return;
            if (_options.AllowPeer != null && !_options.AllowPeer(peer))
                return;
            SendToPeer(connection.Key, peer, data.Value, 0, data.Value.Length, indication.HasAttribute(StunAttributeType.DontFragment), true);
        }

        // ChannelData of the client's: of a channel bound, to its peer (RFC 8656 12.6)
        private void OnChannelData(StunServerConnection connection, byte[] buffer, int offset, int count)
        {
            ushort number = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset));
            int length = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset + 2));
            if (number > 0x4FFF || 4 + length > count)
                return;
            IPEndPoint peer;
            lock (_sync)
            {
                if (!_allocations.TryGetValue(connection.Key, out var allocation) || !allocation.Channels.TryGetValue(number, out var channel) || channel.Expires < DateTime.UtcNow)
                    return;
                peer = channel.Peer;
            }
            SendToPeer(connection.Key, peer, buffer, offset + 4, length, false, false);
        }

        private void SendToPeer(string key, IPEndPoint peer, byte[] buffer, int offset, int count, bool dontFragment, bool checkPermission)
        {
            Relay relay;
            lock (_sync)
            {
                if (!_allocations.TryGetValue(key, out var allocation) || allocation.Closed)
                    return;
                relay = allocation.RelayOf(peer.AddressFamily);
                if (relay == null)
                    return;
                if (checkPermission && (!allocation.Permissions.TryGetValue(peer.Address, out DateTime until) || until < DateTime.UtcNow))
                    return;
            }
            try
            {
                lock (relay)
                {
                    if (relay.Family == AddressFamily.InterNetwork)
                        relay.Socket.DontFragment = dontFragment;
                    relay.Socket.SendTo(buffer, offset, count, SocketFlags.None, peer);
                }
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
            {
            }
        }

        #endregion // Relays

        #region Lifetimes

        // what expired: relays and the allocations of none left, permissions, channels, reservations
        private void Sweep()
        {
            var expired = new List<(Allocation, Relay)>();
            var released = new List<Socket>();
            lock (_sync)
            {
                DateTime now = DateTime.UtcNow;
                foreach (var allocation in _allocations.Values)
                {
                    expired.AddRange(allocation.Relays.Where(r => r.Expires <= now).Select(r => (allocation, r)));
                    foreach (var address in allocation.Permissions.Where(p => p.Value <= now).Select(p => p.Key).ToList())
                        allocation.Permissions.Remove(address);
                    foreach (var number in allocation.Channels.Where(c => c.Value.Expires <= now).Select(c => c.Key).ToList())
                        allocation.Channels.Remove(number);
                }
                foreach (var token in _reservations.Where(r => r.Value.Expires <= now).Select(r => r.Key).ToList())
                {
                    released.Add(_reservations[token].Socket);
                    _reservations.Remove(token);
                }
            }
            foreach (var (allocation, relay) in expired)
                RemoveRelay(allocation, relay, "expired");
            foreach (var socket in released)
                socket.Dispose();
        }

        private void RemoveRelay(Allocation allocation, Relay relay, string why)
        {
            bool last;
            lock (_sync)
            {
                if (!allocation.Relays.Remove(relay))
                    return;
                last = allocation.Relays.Count == 0;
                // its permissions and channels with it (RFC 8656 8.1)
                foreach (var address in allocation.Permissions.Keys.Where(a => a.AddressFamily == relay.Family).ToList())
                    allocation.Permissions.Remove(address);
                foreach (var channel in allocation.Channels.Values.Where(c => c.Peer.AddressFamily == relay.Family).ToList())
                    allocation.Channels.Remove(channel.Number);
                if (last)
                {
                    allocation.Closed = true;
                    if (_allocations.TryGetValue(allocation.Key, out var current) && current == allocation)
                        _allocations.Remove(allocation.Key);
                }
            }
            relay.Socket.Dispose();
            Trace($"Relay {relay.EndPoint} of {allocation.Connection.RemoteEndPoint} {why}");
        }

        private void Remove(string key, string why)
        {
            Allocation allocation;
            lock (_sync)
            {
                if (!_allocations.TryGetValue(key, out allocation))
                    return;
            }
            foreach (var relay in allocation.Relays.ToList())
                RemoveRelay(allocation, relay, why);
        }

        #endregion // Lifetimes

        public void Dispose()
        {
            _timer.Dispose();
            _stun.Dispose();
            List<Allocation> allocations;
            List<Reservation> reservations;
            lock (_sync)
            {
                allocations = _allocations.Values.ToList();
                reservations = _reservations.Values.ToList();
                _reservations.Clear();
            }
            foreach (var allocation in allocations)
                Remove(allocation.Key, "closed");
            foreach (var reservation in reservations)
                reservation.Socket.Dispose();
        }
    }
}
