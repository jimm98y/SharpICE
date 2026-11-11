// SharpTurn
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

using SharpStun;
using SharpTurn;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SharpTurn
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

        /// <summary>
        /// The address of the IPv6 relayed transport addresses; of none, the address of IPv6 a client's 5-tuple is of, of a
        /// listener of one, else none: IPv6 relays are not allocated then (440).
        /// </summary>
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
        public TimeSpan DefaultLifetime { get; set; } = TurnConstants.DefaultLifetime;
        public TimeSpan MaxLifetime { get; set; } = TurnConstants.MaxLifetime;

        /// <summary>How many allocations a user may have at once - its EVEN-PORT reservations of them; more are answered 486.</summary>
        public int MaxAllocationsPerUser { get; set; } = 10;

        /// <summary>How many allocations - and reservations - the server has at most, of all its users; more are answered 508.</summary>
        public int MaxAllocations { get; set; } = 1000;

        /// <summary>How many peers' addresses an allocation may have permissions of at once; more are answered 508.</summary>
        public int MaxPermissionsPerAllocation { get; set; } = 128;

        /// <summary>
        /// Whether a client of TCP or TLS may have a TCP allocation (RFC 6062): a relay of TCP, of connections to and of its
        /// peers. Of false, one asked for is answered 442.
        /// </summary>
        public bool AllowTcpAllocations { get; set; } = true;

        /// <summary>
        /// How many connections of peers a TCP allocation has at most at once - those being made, and those waiting for their
        /// ConnectionBind, too: a Connect past them is answered 508, a peer that connects past them closed.
        /// </summary>
        public int MaxConnectionsPerAllocation { get; set; } = 32;

        /// <summary>
        /// Whether data may be relayed to and of a peer: of one refused, its permission or channel is answered 403 and a Send
        /// indication to it dropped (RFC 8656 10.2, 11.2, 12.2). Of its default, <see cref="TurnPeers.IsPublic(IPEndPoint)"/>:
        /// public unicast addresses alone, as a server is not to reach its own network; of a server for a private network,
        /// one of the peers it is to reach. Of any, the server's own listeners and relays are refused, of a loop.
        /// </summary>
        public Func<IPEndPoint, bool> AllowPeer { get; set; } = TurnPeers.IsPublic;

        /// <summary>
        /// Whether to relay of no credentials, of a <see cref="StunServerOptions.Realm"/> of none: an open relay, of anyone's -
        /// of a spoofed source over UDP too - which RFC 8656 5 forbids. Of false, the default, a server of no realm is refused.
        /// </summary>
        public bool AllowUnauthenticated { get; set; }

        /// <summary>What it does, a line at a time, of anything given.</summary>
        public Action<string> Trace { get; set; }
    }

    /// <summary>
    /// A TURN server (RFC 8656) of UDP allocations, over UDP, TCP, TLS and DTLS between the client and it - the transports of
    /// <see cref="StunServer"/>, which it answers Binding requests of too. Of each allocation, a relay of UDP of its own - or
    /// two, of IPv4 and IPv6 - its permissions and channels; the peers' data relayed to the client as Data indications, or as
    /// ChannelData of a channel bound to the peer. Of a client of TCP or TLS, a TCP allocation too (RFC 6062): a relay of TCP,
    /// of a connection to a peer of each Connect, and of each peer of a permission that connects to it, each relayed as it is
    /// over a data connection of the client's of its own, of a ConnectionBind.
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
    /// are not told of: the system does not say of which peer they are.
    /// </para>
    /// <para>
    /// Of a TCP allocation (RFC 6062): of a control connection of TCP or TLS alone (400), of no DONT-FRAGMENT, EVEN-PORT,
    /// RESERVATION-TOKEN or ADDITIONAL-ADDRESS-FAMILY (400). A Connect is answered once its connection, of the relayed
    /// address, is made - 30 seconds at most - of a CONNECTION-ID, or 447; one to a peer a connection is of already, 446. A
    /// peer that connects of no permission is closed, else told of a ConnectionAttempt. A peer's connection of no
    /// ConnectionBind in 30 seconds is closed; until it, what the peer sends is left in its socket, of TCP's own window. Each
    /// data connection closes with its peer's, and the other way round, and all of them with the allocation.
    /// </para>
    /// </remarks>
    public sealed class TurnServer : IDisposable
    {
        public static readonly TimeSpan PermissionLifetime = TurnConstants.PermissionLifetime;
        public static readonly TimeSpan ChannelLifetime = TurnConstants.ChannelLifetime;
        private static readonly TimeSpan ReservationLifetime = TimeSpan.FromSeconds(30);

        private sealed class Relay
        {
            // of UDP, its socket; of TCP, the listener of its peers' connections
            public Socket Socket;
            public TcpListener Listener;
            public UdpSender Sender;
            // the DF bit the socket is of now: set again only as a Send indication's DONT-FRAGMENT changes it
            public bool DontFragment;
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
            public (int Code, string Reason)? AddressError;
            public readonly List<Relay> Relays = new List<Relay>();
            public readonly Dictionary<IPAddress, DateTime> Permissions = new Dictionary<IPAddress, DateTime>();
            public readonly Dictionary<ushort, Channel> Channels = new Dictionary<ushort, Channel>();
            public bool Closed;

            // of a TCP allocation (RFC 6062): its relay of TCP, and its peers' connections, of their CONNECTION-IDs
            public bool IsTcp;
            public readonly Dictionary<uint, TcpPeer> Connections = new Dictionary<uint, TcpPeer>();

            public Relay RelayOf(AddressFamily family)
            {
                foreach (var relay in Relays)
                {
                    if (relay.Family == family)
                        return relay;
                }
                return null;
            }

            // the channels of each peer: of the peer of each datagram a relay gets, at once, not of a scan of every channel
            private readonly Dictionary<IPEndPoint, Channel> _channelsOfPeer = new Dictionary<IPEndPoint, Channel>();

            public Channel ChannelOf(IPEndPoint peer) => _channelsOfPeer.TryGetValue(peer, out var channel) ? channel : null;

            public void AddChannel(Channel channel)
            {
                if (Channels.TryGetValue(channel.Number, out var old))
                    _channelsOfPeer.Remove(old.Peer);
                Channels[channel.Number] = channel;
                _channelsOfPeer[channel.Peer] = channel;
            }

            public void RemoveChannel(ushort number)
            {
                if (Channels.TryGetValue(number, out var channel))
                {
                    Channels.Remove(number);
                    _channelsOfPeer.Remove(channel.Peer);
                }
            }
        }

        // a peer's connection of a TCP allocation: being made of a Connect, waiting for its ConnectionBind, or bound - relayed
        // as it is to a data connection of the client's
        private sealed class TcpPeer
        {
            public uint Id;
            public Allocation Allocation;
            public IPEndPoint Peer;
            public TcpClient Client;
            // of a Connect, until its connection is made
            public bool Connecting;
            // since when it waits for its ConnectionBind
            public DateTime Waiting;
            public bool Bound;
            public Stream Data;
            public bool Closed;
        }

        private sealed class Reservation
        {
            public Socket Socket;
            public DateTime Expires;
            public string Username;
        }

        private readonly TurnServerOptions _options;
        private readonly StunServer _stun;
        private readonly object _sync = new object();
        private readonly Dictionary<string, Allocation> _allocations = new Dictionary<string, Allocation>();
        private readonly Dictionary<string, Reservation> _reservations = new Dictionary<string, Reservation>();
        // the peers' connections of every TCP allocation, of their CONNECTION-IDs, of a ConnectionBind to find
        private readonly Dictionary<uint, TcpPeer> _tcpPeers = new Dictionary<uint, TcpPeer>();
        // of the relays' ports, one of every server of the process: of .NET Framework, two made in one tick of the clock would
        // be of one seed, and pick their ports alike
        private static readonly Random _random = new Random();

        // a TCP relay's port taken of one server at a time, of this process: as it is bound of reuse, of a probe of it first
        private static readonly object TcpBinding = new object();
        private readonly Timer _timer;

        public TurnServer(TurnServerOptions options = null)
        {
            _options = options ?? new TurnServerOptions();
            if (_options.Stun.Realm == null && !_options.AllowUnauthenticated)
                throw new ArgumentException("A TURN server takes long-term credentials (RFC 8656 5): a realm and its users, or AllowUnauthenticated of an open relay.", nameof(options));
            // of TURN's attributes, and its Allocate redirected as a Binding is
            _options.Stun.IsKnownAttribute = TurnAttributeType.IsKnownOfTurn;
            _options.Stun.RedirectedMethods.Add(TurnMethod.Allocate);
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

        public IPEndPoint ListenUdp(IPEndPoint endPoint) => Listening(_stun.ListenUdp(endPoint));
        public IPEndPoint ListenTcp(IPEndPoint endPoint) => Listening(_stun.ListenTcp(endPoint));
        public IPEndPoint ListenTls(IPEndPoint endPoint) => Listening(_stun.ListenTls(endPoint));
        public IPEndPoint ListenDtls(IPEndPoint endPoint) => Listening(_stun.ListenDtls(endPoint));

        // the listeners' endpoints: peers no relay is to reach, of a loop of the server's own
        private readonly List<IPEndPoint> _listeners = new List<IPEndPoint>();

        private IPEndPoint Listening(IPEndPoint endPoint)
        {
            lock (_sync)
                _listeners.Add(endPoint);
            return endPoint;
        }

        // the addresses of this host's interfaces: read again each minute, as they change
        private static readonly object HostAddressesSync = new object();
        private static HashSet<IPAddress> _hostAddresses;
        private static DateTime _hostAddressesRead;

        private static HashSet<IPAddress> HostAddresses
        {
            get
            {
                lock (HostAddressesSync)
                {
                    if (_hostAddresses == null || DateTime.UtcNow - _hostAddressesRead > TimeSpan.FromMinutes(1))
                    {
                        var addresses = new HashSet<IPAddress>();
                        try
                        {
                            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                            {
                                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                                    addresses.Add(Normalize(unicast.Address));
                            }
                        }
                        catch (NetworkInformationException)
                        {
                        }
                        _hostAddresses = addresses;
                        _hostAddressesRead = DateTime.UtcNow;
                    }
                    return _hostAddresses;
                }
            }
        }

        private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        // a peer of the server's own: the unspecified addresses - of Linux, the host's own - its listeners, and of the host's
        // addresses other than the loopback's - its interfaces', its relay addresses and the one it advertises - every port but
        // those of its relays, as any service of the host's is of them, hidden as it may be of a firewall of the outside
        // (RFC 8656 21.2.3). Another allocation's relay is a peer as any is: two clients of one server relay to each other of
        // theirs. Of the loopback, the listeners alone: the default policy refuses the rest of it, and one that allows it, as
        // tests do, means it.
        private bool IsOwn(IPEndPoint peer)
        {
            var address = Normalize(peer.Address);
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                return true;
            bool loopback = IPAddress.IsLoopback(address);
            bool host = !loopback && (HostAddresses.Contains(address) || address.Equals(_options.RelayAddress) || address.Equals(_options.RelayAddressV6)
                || address.Equals(_options.AdvertisedRelayAddress));
            lock (_sync)
            {
                foreach (var listener in _listeners)
                {
                    if (listener.Port == peer.Port && ((loopback || host) && (listener.Address.Equals(IPAddress.Any) || listener.Address.Equals(IPAddress.IPv6Any)) || Normalize(listener.Address).Equals(address)))
                        return true;
                }
                return host && !IsRelayPort(peer.Port);
            }
        }

        // under the lock: whether the port is of a relay of the server's, of an allocation of any client's
        private bool IsRelayPort(int port)
        {
            foreach (var allocation in _allocations.Values)
            {
                foreach (var relay in allocation.Relays)
                {
                    if (relay.EndPoint.Port == port || relay.Advertised.Port == port)
                        return true;
                }
            }
            return false;
        }

        // whether the peer may be relayed to: not of the server's own, and of the options' choice
        private bool IsAllowed(IPEndPoint peer)
        {
            if (peer == null || IsOwn(peer))
                return false;
            return _options.AllowPeer == null || _options.AllowPeer(peer);
        }

        // whether a permission of the address may be installed: of its address alone, as a permission is of no port (RFC 8656
        // 9) - of the unspecified addresses never; of the default policy, of a public address, as TurnPeers.IsPublic of an
        // endpoint refuses port 0, which a permission's XOR-PEER-ADDRESS is of
        private bool IsAllowedPermission(IPAddress address)
        {
            address = Normalize(address);
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                return false;
            if (_options.AllowPeer == null)
                return true;
            return _options.AllowPeer.Method == ((Func<IPEndPoint, bool>)TurnPeers.IsPublic).Method
                ? TurnPeers.IsPublic(address)
                : _options.AllowPeer(new IPEndPoint(address, 0));
        }

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
                case TurnMethod.Allocate:
                    return Allocate(request);
                case TurnMethod.Refresh:
                    return OfAllocation(request, Refresh);
                case TurnMethod.CreatePermission:
                    return OfAllocation(request, CreatePermission);
                case TurnMethod.ChannelBind:
                    return OfAllocation(request, ChannelBind);
                case TurnMethod.Connect:
                    return OfAllocation(request, Connect);
                case TurnMethod.ConnectionBind:
                    return ConnectionBind(request);
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
                return request.Error(TurnErrorCode.AllocationMismatch, "Allocation Mismatch");
            if (_options.Stun.Realm != null && allocation.Username != request.Username)
                return request.Error(TurnErrorCode.WrongCredentials, "Wrong Credentials");
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
                        : request.Error(TurnErrorCode.AllocationMismatch, "Allocation Mismatch");
                }
            }

            byte? transport = message.GetRequestedTransport();
            if (transport == null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            bool tcp = transport == TurnConstants.Tcp;
            if (tcp)
            {
                // of a TCP allocation (RFC 6062 5.1): of a control connection of TCP or TLS, of none of what a relay of UDP is of;
                // of one relayed address, its control connection its own
                if (!_options.AllowTcpAllocations)
                    return request.Error(TurnErrorCode.UnsupportedTransportProtocol, "Unsupported Transport Protocol");
                if (!request.Connection.IsStream)
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
                if (message.HasAttribute(TurnAttributeType.DontFragment) || message.HasAttribute(TurnAttributeType.EvenPort)
                    || message.HasAttribute(TurnAttributeType.ReservationToken) || message.HasAttribute(TurnAttributeType.AdditionalAddressFamily))
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
            }
            else if (transport != TurnConstants.Udp)
            {
                return request.Error(TurnErrorCode.UnsupportedTransportProtocol, "Unsupported Transport Protocol");
            }

            var token = message.GetAttribute(TurnAttributeType.ReservationToken);
            bool? evenPort = message.GetEvenPort();
            var requestedFamily = message.GetAddressFamily(TurnAttributeType.RequestedAddressFamily);
            var additionalFamily = message.GetAddressFamily(TurnAttributeType.AdditionalAddressFamily);
            bool reserveNext = evenPort == true;
            if (token != null && (evenPort != null || requestedFamily != null || additionalFamily != null))
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (requestedFamily != null && additionalFamily != null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (reserveNext && additionalFamily != null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            if (additionalFamily != null && additionalFamily != AddressFamily.InterNetworkV6)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");

            // the family asked for, IPv4 of none (RFC 8656 7.2)
            var family = requestedFamily ?? AddressFamily.InterNetwork;
            if (family == AddressFamily.Unknown)
                return request.Error(TurnErrorCode.AddressFamilyNotSupported, "Address Family not Supported");
            if (token == null && RelayAddressOf(family, request.Connection) == null)
                return request.Error(TurnErrorCode.AddressFamilyNotSupported, "Address Family not Supported");

            lock (_sync)
            {
                // the reservations of EVEN-PORT ports too, as each holds a port as an allocation does; and the allocations
                // being made of other connections now, whose sockets are being bound outside the lock, that Allocates at once
                // of many connections take no more than the quotas
                int pendingOfUser = request.Username != null && _pendingOf.TryGetValue(request.Username, out int pending) ? pending : 0;
                if (request.Username != null && _allocations.Values.Count(a => a.Username == request.Username)
                    + _reservations.Values.Count(r => r.Username == request.Username) + pendingOfUser >= _options.MaxAllocationsPerUser)
                    return request.Error(TurnErrorCode.AllocationQuotaReached, "Allocation Quota Reached");
                if (_allocations.Count + _reservations.Count + _pending >= _options.MaxAllocations)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                _pending++;
                if (request.Username != null)
                    _pendingOf[request.Username] = pendingOfUser + 1;
            }
            try
            {
                return AllocateRelays(request, message, key, tcp, token, evenPort, reserveNext, family, additionalFamily);
            }
            finally
            {
                lock (_sync)
                {
                    _pending--;
                    if (request.Username != null && _pendingOf.TryGetValue(request.Username, out int pending))
                    {
                        if (pending <= 1)
                            _pendingOf.Remove(request.Username);
                        else
                            _pendingOf[request.Username] = pending - 1;
                    }
                }
            }
        }

        // the allocations being made now, of their quota's slot taken before their sockets are bound
        private int _pending;
        private readonly Dictionary<string, int> _pendingOf = new Dictionary<string, int>();

        // of the slot of the quotas taken: the relays bound, and the allocation of them
        private StunMessage AllocateRelays(StunServerRequest request, StunMessage message, string key, bool tcp, StunAttribute token, bool? evenPort, bool reserveNext,
            AddressFamily family, AddressFamily? additionalFamily)
        {
            DateTime expires = DateTime.UtcNow + Lifetime(message, false);
            var allocation = new Allocation
            {
                Key = key,
                Connection = request.Connection,
                Username = request.Username,
                TransactionId = message.TransactionId,
                IsTcp = tcp,
            };

            if (tcp)
            {
                var listener = BindTcp(RelayAddressOf(family, request.Connection));
                if (listener == null)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                allocation.Relays.Add(MakeTcpRelay(listener, expires));
            }
            else if (token != null)
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
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                }
                allocation.Relays.Add(MakeRelay(reservation.Socket, expires));
            }
            else
            {
                var address = RelayAddressOf(family, request.Connection);
                Socket reserved = null;
                var socket = evenPort != null ? BindEven(address, reserveNext, out reserved) : Bind(address);
                if (socket == null)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                allocation.Relays.Add(MakeRelay(socket, expires));
                if (reserved != null)
                {
                    byte[] value = new byte[8];
                    using (var random = RandomNumberGenerator.Create())
                        random.GetBytes(value);
                    allocation.ReservationToken = value;
                    lock (_sync)
                        _reservations[Convert.ToBase64String(value)] = new Reservation { Socket = reserved, Expires = DateTime.UtcNow + ReservationLifetime, Username = request.Username };
                }

                // the IPv6 relay of a dual allocation, or the reason there is none (RFC 8656 7.2 step 9)
                if (additionalFamily != null)
                {
                    var v6 = RelayAddressOf(AddressFamily.InterNetworkV6, request.Connection);
                    var second = v6 != null ? Bind(v6) : null;
                    if (second != null)
                        allocation.Relays.Add(MakeRelay(second, expires));
                    else
                        allocation.AddressError = v6 == null ? (TurnErrorCode.AddressFamilyNotSupported, "Address Family not Supported") : (TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                }
            }

            lock (_sync)
                _allocations[key] = allocation;
            foreach (var relay in allocation.Relays)
                _ = relay.Listener != null ? AcceptPeersAsync(allocation, relay) : RelayAsync(allocation, relay);
            Trace($"Allocated {(tcp ? "TCP " : "")}{string.Join(", ", allocation.Relays.Select(r => r.EndPoint))} for {request.Connection.RemoteEndPoint} of {allocation.Username}");
            return Allocated(request, allocation);
        }

        private StunMessage Allocated(StunServerRequest request, Allocation allocation)
        {
            var response = request.Success();
            foreach (var relay in allocation.Relays)
                response.AddXorAddress(relay.Advertised, TurnAttributeType.XorRelayedAddress);
            response.AddLifetime(allocation.Relays.Max(r => r.Expires) - DateTime.UtcNow);
            if (allocation.ReservationToken != null)
                response.AddAttribute(TurnAttributeType.ReservationToken, allocation.ReservationToken);
            response.AddXorAddress(request.Connection.RemoteEndPoint);
            // of IPv6, the family not allocated (RFC 8656 18.12)
            if (allocation.AddressError != null)
                response.AddAddressError(AddressFamily.InterNetworkV6, allocation.AddressError.Value.Code, allocation.AddressError.Value.Reason);
            return response;
        }

        private StunMessage Refresh(StunServerRequest request, Allocation allocation)
        {
            var message = request.Message;
            List<Relay> relays;
            var requestedFamily = message.GetAddressFamily(TurnAttributeType.RequestedAddressFamily);
            lock (_sync)
            {
                relays = allocation.Relays.ToList();
                if (requestedFamily != null)
                {
                    relays = relays.Where(r => r.Family == requestedFamily.Value).ToList();
                    if (relays.Count == 0)
                        return request.Error(TurnErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
                }
            }

            var lifetime = Lifetime(message, true);
            var response = request.Success();
            if (lifetime == TimeSpan.Zero)
            {
                foreach (var relay in relays)
                    RemoveRelay(allocation, relay, "deleted by its client");
                response.AddLifetime(TimeSpan.Zero);
                return response;
            }
            lock (_sync)
            {
                foreach (var relay in relays)
                    relay.Expires = DateTime.UtcNow + lifetime;
            }
            response.AddLifetime(lifetime);
            return response;
        }

        private StunMessage CreatePermission(StunServerRequest request, Allocation allocation)
        {
            var peers = request.Message.GetXorAddresses(TurnAttributeType.XorPeerAddress);
            if (peers.Count == 0 || peers.Any(p => p == null))
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            lock (_sync)
            {
                if (peers.Any(p => allocation.RelayOf(p.AddressFamily) == null))
                    return request.Error(TurnErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
            }
            // of each address alone, as a permission is of no port (RFC 8656 9.1)
            if (peers.Any(p => !IsAllowedPermission(p.Address)))
                return request.Error(TurnErrorCode.Forbidden, "Forbidden");
            lock (_sync)
            {
                // of the addresses the peers' datagrams are of: an IPv4 address mapped to IPv6 as the IPv4 one
                var addresses = peers.Select(p => Normalize(p.Address)).Distinct().ToList();
                int added = addresses.Count(a => !allocation.Permissions.ContainsKey(a));
                if (allocation.Permissions.Count + added > _options.MaxPermissionsPerAllocation)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                foreach (var address in addresses)
                    allocation.Permissions[address] = DateTime.UtcNow + PermissionLifetime;
            }
            return request.Success();
        }

        private StunMessage ChannelBind(StunServerRequest request, Allocation allocation)
        {
            // of a TCP allocation, no channels: its data goes over connections of their own (RFC 6062 3)
            if (allocation.IsTcp)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            var message = request.Message;
            ushort? number = message.GetChannelNumber();
            var peer = message.GetXorAddress(TurnAttributeType.XorPeerAddress);
            if (number == null || peer == null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            // of the endpoint the peer's datagrams are of: an IPv4 address mapped to IPv6 as the IPv4 one
            peer = new IPEndPoint(Normalize(peer.Address), peer.Port);
            ushort channel = number.Value;
            if (channel < TurnConstants.MinChannel || channel > TurnConstants.MaxChannel)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            lock (_sync)
            {
                if (allocation.RelayOf(peer.AddressFamily) == null)
                    return request.Error(TurnErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
            }
            if (!IsAllowed(peer))
                return request.Error(TurnErrorCode.Forbidden, "Forbidden");

            lock (_sync)
            {
                if (!allocation.Permissions.ContainsKey(peer.Address) && allocation.Permissions.Count >= _options.MaxPermissionsPerAllocation)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                // the channel bound to another peer, or the peer to another channel (RFC 8656 12.2)
                if (allocation.Channels.TryGetValue(channel, out var bound) && !bound.Peer.Equals(peer))
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
                var other = allocation.ChannelOf(peer);
                if (other != null && other.Number != channel)
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");

                allocation.AddChannel(new Channel { Number = channel, Peer = peer, Expires = DateTime.UtcNow + ChannelLifetime });
                allocation.Permissions[peer.Address] = DateTime.UtcNow + PermissionLifetime;
            }
            return request.Success();
        }

        // the lifetime asked for, of the default and the maximum (RFC 8656 7.2, 8.2): of a Refresh of 0, 0
        private TimeSpan Lifetime(StunMessage message, bool refresh)
        {
            TimeSpan? asked = message.GetLifetime();
            if (refresh && asked == TimeSpan.Zero)
                return TimeSpan.Zero;
            if (asked == null)
                return _options.DefaultLifetime;
            var lifetime = asked.Value < _options.MaxLifetime ? asked.Value : _options.MaxLifetime;
            return lifetime > _options.DefaultLifetime ? lifetime : _options.DefaultLifetime;
        }

        #endregion // Requests

        #region Relays

        private IPAddress RelayAddressOf(AddressFamily family, StunServerConnection connection)
        {
            if (family == AddressFamily.InterNetworkV6)
            {
                // of none given, of a listener of an address of IPv6 of its own, it
                var own = connection.LocalEndPoint.Address;
                return _options.RelayAddressV6
                    ?? (own.AddressFamily == AddressFamily.InterNetworkV6 && !own.Equals(IPAddress.IPv6Any) && !own.IsIPv6LinkLocal ? own : null);
            }
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
            return new Relay { Socket = socket, Sender = new UdpSender(socket), EndPoint = endPoint, Advertised = advertised, Expires = expires };
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
            // the peer's data read past the room the header of a Data indication of IPv6 takes, the most of any, so that its
            // ChannelData's header, or its Data indication's, is written before it where it is; of a buffer of a pool
            byte[] buffer = ArrayPool<byte>.Shared.Rent(RelayRoom + ushort.MaxValue + RelayRoom);
            var receiver = new UdpReceiver(relay.Socket);
            try
            {
                while (true)
                {
                    int count;
                    try
                    {
                        count = await receiver.ReceiveAsync(buffer, RelayRoom, ushort.MaxValue).ConfigureAwait(false);
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }

                    var peer = receiver.RemoteEndPoint;
                    // of more than a Data indication's 16 bit length takes, framed: dropped, as no client could read it
                    if (TurnIndication.Size(peer, count, false) - StunMessage.HeaderLength > ushort.MaxValue)
                        continue;
                    Channel channel;
                    lock (_sync)
                    {
                        if (allocation.Closed || !allocation.Permissions.TryGetValue(peer.Address, out DateTime until) || until < DateTime.UtcNow)
                            continue;
                        channel = allocation.ChannelOf(peer);
                        if (channel != null && channel.Expires < DateTime.UtcNow)
                            channel = null;
                    }

                    int start, length;
                    if (channel != null)
                    {
                        start = RelayRoom - StunFraming.ChannelDataHeaderLength;
                        length = TurnChannelData.Frame(buffer.AsSpan(start), channel.Number, count, allocation.Connection.IsStream);
                    }
                    else
                    {
                        start = RelayRoom - TurnIndication.HeaderSize(peer);
                        length = TurnIndication.Frame(buffer.AsSpan(start), TurnMethod.Data, peer, count);
                    }
                    allocation.Connection.Send(buffer, start, length);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        // the header of a Data indication of a peer of IPv6: of a message's, an XOR-PEER-ADDRESS's, and DATA's own
        private static readonly int RelayRoom = TurnIndication.HeaderSize(new IPEndPoint(IPAddress.IPv6Any, 0));

        // a Send indication: to a peer of a permission, of the DF bit of a DONT-FRAGMENT (RFC 8656 11.2)
        private void OnIndication(StunMessage indication, StunServerConnection connection)
        {
            if (indication.Method != TurnMethod.Send)
                return;
            var peer = indication.GetXorAddress(TurnAttributeType.XorPeerAddress);
            var data = indication.GetAttribute(TurnAttributeType.Data);
            if (peer == null || data == null)
                return;
            if (!IsAllowed(peer))
                return;
            SendToPeer(connection.Key, peer, data.Value, 0, data.Value.Length, indication.HasAttribute(TurnAttributeType.DontFragment), true);
        }

        // ChannelData of the client's: of a channel bound, to its peer (RFC 8656 12.6)
        private void OnChannelData(StunServerConnection connection, byte[] buffer, int offset, int count)
        {
            if (!TurnChannelData.TryRead(buffer, offset, count, out ushort number, out int dataOffset, out int length))
                return;
            IPEndPoint peer;
            lock (_sync)
            {
                if (!_allocations.TryGetValue(connection.Key, out var allocation) || !allocation.Channels.TryGetValue(number, out var channel) || channel.Expires < DateTime.UtcNow)
                    return;
                peer = channel.Peer;
            }
            SendToPeer(connection.Key, peer, buffer, dataOffset, length, false, false);
        }

        private void SendToPeer(string key, IPEndPoint peer, byte[] buffer, int offset, int count, bool dontFragment, bool checkPermission)
        {
            Relay relay;
            lock (_sync)
            {
                if (!_allocations.TryGetValue(key, out var allocation) || allocation.Closed)
                    return;
                relay = allocation.RelayOf(peer.AddressFamily);
                // of a relay of TCP, nothing of a Send indication: its data goes over connections of their own
                if (relay == null || relay.Socket == null)
                    return;
                if (checkPermission && (!allocation.Permissions.TryGetValue(peer.Address, out DateTime until) || until < DateTime.UtcNow))
                    return;
            }
            try
            {
                lock (relay)
                {
                    if (relay.Family == AddressFamily.InterNetwork && relay.DontFragment != dontFragment)
                    {
                        relay.Socket.DontFragment = dontFragment;
                        relay.DontFragment = dontFragment;
                    }
                    relay.Sender.SendTo(buffer, offset, count, peer);
                }
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
            {
            }
        }

        #endregion // Relays

        #region TCP allocations

        private Relay MakeTcpRelay(TcpListener listener, DateTime expires)
        {
            var endPoint = (IPEndPoint)listener.LocalEndpoint;
            var advertised = _options.AdvertisedRelayAddress != null && endPoint.AddressFamily == _options.AdvertisedRelayAddress.AddressFamily
                ? new IPEndPoint(_options.AdvertisedRelayAddress, endPoint.Port)
                : endPoint;
            return new Relay { Listener = listener, EndPoint = endPoint, Advertised = advertised, Expires = expires };
        }

        // a listener of TCP of a port of the range at random: its port the one the connections of Connect are made of too, the
        // relayed address their peers see (RFC 6062 5.2)
        private TcpListener BindTcp(IPAddress address)
        {
            if (address == null)
                return null;
            for (int attempt = 0; attempt < 64; attempt++)
            {
                int port;
                lock (_random)
                    port = _random.Next(_options.PortMin, _options.PortMax + 1);
                lock (TcpBinding)
                {
                    // of a port no socket has: one of reuse is bound over another's of reuse - another relay's - which would
                    // take its peers' connections
                    if (!IsFreeTcpPort(address, port))
                        continue;
                    var listener = new TcpListener(address, port);
                    try
                    {
                        // a port of a listener bound again - of a connection of Connect - of the address reused of both; of
                        // Windows, of a listener not of its exclusive use, as .NET's is of it there
                        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                            listener.ExclusiveAddressUse = false;
                        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                        listener.Start();
                        return listener;
                    }
                    catch (SocketException)
                    {
                        listener.Stop();
                    }
                }
            }
            return null;
        }

        // whether a socket of no reuse is bound of the port: of none of anyone's - a listener of reuse too - on it
        private static bool IsFreeTcpPort(IPAddress address, int port)
        {
            using (var probe = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    probe.Bind(new IPEndPoint(address, port));
                    return true;
                }
                catch (SocketException)
                {
                    return false;
                }
            }
        }

        // under the lock: a peer's connection of the allocation, of a CONNECTION-ID of none other's
        private TcpPeer AddTcpPeer(Allocation allocation, IPEndPoint peer, TcpClient client, bool connecting)
        {
            byte[] value = new byte[4];
            uint id;
            using (var random = RandomNumberGenerator.Create())
            {
                do
                {
                    random.GetBytes(value);
                    id = BinaryPrimitives.ReadUInt32BigEndian(value);
                }
                while (id == 0 || _tcpPeers.ContainsKey(id));
            }
            var tcpPeer = new TcpPeer { Id = id, Allocation = allocation, Peer = peer, Client = client, Connecting = connecting, Waiting = DateTime.UtcNow };
            allocation.Connections[id] = tcpPeer;
            _tcpPeers[id] = tcpPeer;
            return tcpPeer;
        }

        // the peers' connections to the relayed address: of a permission of their address, told of to the client of a
        // ConnectionAttempt; else closed as they are accepted (RFC 6062 5.3)
        private async Task AcceptPeersAsync(Allocation allocation, Relay relay)
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await relay.Listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is ObjectDisposedException || ex is InvalidOperationException)
                {
                    return;
                }
                catch (SocketException)
                {
                    if (allocation.Closed)
                        return;
                    continue;
                }

                IPEndPoint peer;
                try
                {
                    var remote = (IPEndPoint)client.Client.RemoteEndPoint;
                    peer = new IPEndPoint(Normalize(remote.Address), remote.Port);
                }
                catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                {
                    client.Dispose();
                    continue;
                }

                TcpPeer accepted = null;
                string refused = null;
                lock (_sync)
                {
                    if (allocation.Closed)
                        refused = "its allocation ended";
                    else if (!allocation.Permissions.TryGetValue(peer.Address, out DateTime until) || until < DateTime.UtcNow)
                        refused = "of no permission";
                    else if (allocation.Connections.Count >= _options.MaxConnectionsPerAllocation)
                        refused = $"{_options.MaxConnectionsPerAllocation} connections already";
                    else if (allocation.Connections.Values.Any(c => c.Peer.Equals(peer)))
                        refused = "a connection of the peer's already";
                    else
                        accepted = AddTcpPeer(allocation, peer, client, false);
                }
                if (accepted == null)
                {
                    Trace($"Connection of {peer} to {relay.EndPoint} closed: {refused}");
                    client.Dispose();
                    if (allocation.Closed)
                        return;
                    continue;
                }

                var attempt = new StunMessage(TurnMethod.ConnectionAttempt, StunMessageClass.Indication)
                    .AddXorAddress(peer, TurnAttributeType.XorPeerAddress)
                    .AddConnectionId(accepted.Id);
                if (_options.Stun.Software != null)
                    attempt.AddString(StunAttributeType.Software, _options.Stun.Software);
                if (allocation.Connection.Send(attempt.ToBytes(null, false)))
                    Trace($"Connection {accepted.Id} of {peer} to {relay.EndPoint}: told of to {allocation.Connection.RemoteEndPoint}");
                else
                    CloseTcpPeer(accepted, "its client's control connection ended");
            }
        }

        // a Connect (RFC 6062 5.2): a connection to the peer of the relayed address, answered once it is made, of its
        // CONNECTION-ID, or once it failed, 447; one of a peer the allocation has a connection of already, 446
        private StunMessage Connect(StunServerRequest request, Allocation allocation)
        {
            if (!allocation.IsTcp)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            var peer = request.Message.GetXorAddress(TurnAttributeType.XorPeerAddress);
            if (peer == null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            peer = new IPEndPoint(Normalize(peer.Address), peer.Port);
            Relay relay;
            lock (_sync)
                relay = allocation.RelayOf(peer.AddressFamily);
            if (relay == null)
                return request.Error(TurnErrorCode.PeerAddressFamilyMismatch, "Peer Address Family Mismatch");
            if (!IsAllowed(peer))
                return request.Error(TurnErrorCode.Forbidden, "Forbidden");

            TcpPeer pending;
            lock (_sync)
            {
                if (allocation.Closed)
                    return request.Error(TurnErrorCode.AllocationMismatch, "Allocation Mismatch");
                // one connection of a peer's transport address, being made, waiting or bound (RFC 6062 3, 5.2)
                if (allocation.Connections.Values.Any(c => c.Peer.Equals(peer)))
                    return request.Error(TurnErrorCode.ConnectionAlreadyExists, "Connection Already Exists");
                if (allocation.Connections.Count >= _options.MaxConnectionsPerAllocation)
                    return request.Error(TurnErrorCode.InsufficientCapacity, "Insufficient Capacity");
                pending = AddTcpPeer(allocation, peer, null, true);
            }
            _ = ConnectPeerAsync(request, relay, pending);
            // answered of the connection, once it is made or it failed
            return null;
        }

        private async Task ConnectPeerAsync(StunServerRequest request, Relay relay, TcpPeer pending)
        {
            var socket = new Socket(pending.Peer.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            string failure = null;
            try
            {
                // of the relayed address, its listener's port (RFC 6062 5.2)
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.Bind(relay.EndPoint);
                var connect = socket.ConnectAsync(pending.Peer);
                if (await Task.WhenAny(connect, Task.Delay(TurnConstants.ConnectTimeout)).ConfigureAwait(false) != connect)
                    throw new SocketException((int)SocketError.TimedOut);
                await connect.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
            {
                failure = ex.Message;
            }

            StunMessage response = null;
            lock (_sync)
            {
                if (failure == null && !pending.Closed && !pending.Allocation.Closed)
                {
                    pending.Client = new TcpClient { Client = socket };
                    pending.Connecting = false;
                    pending.Waiting = DateTime.UtcNow;
                    response = request.Success().AddConnectionId(pending.Id);
                }
                else
                {
                    failure ??= "its allocation ended";
                }
            }
            if (response == null)
            {
                socket.Dispose();
                CloseTcpPeer(pending, "its Connect failed: " + failure);
                response = request.Error(TurnErrorCode.ConnectionTimeoutOrFailure, "Connection Timeout or Failure");
            }
            else
            {
                Trace($"Connection {pending.Id} of {relay.EndPoint} to {pending.Peer}");
            }
            request.Respond(response);
        }

        // a ConnectionBind (RFC 6062 5.4): a new connection of the client's - not its control connection - of the credentials
        // of the allocation, of the CONNECTION-ID of a peer's connection waiting; relayed to it as it is once answered
        private StunMessage ConnectionBind(StunServerRequest request)
        {
            var connection = request.Connection;
            if (!connection.IsStream)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            uint? id = request.Message.GetConnectionId();
            if (id == null)
                return request.Error(StunErrorCode.BadRequest, "Bad Request");
            TcpPeer peer;
            lock (_sync)
            {
                if (_allocations.ContainsKey(connection.Key))
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
                // of a CONNECTION-ID of no connection waiting, or of another user's: the connection closed once answered, that
                // no one guesses the IDs of others' connections over it, one after another
                if (!_tcpPeers.TryGetValue(id.Value, out peer) || peer.Bound || peer.Connecting || peer.Closed || peer.Allocation.Closed)
                {
                    connection.Handoff = Closing;
                    return request.Error(StunErrorCode.BadRequest, "Bad Request");
                }
                if (_options.Stun.Realm != null && peer.Allocation.Username != request.Username)
                {
                    connection.Handoff = Closing;
                    return request.Error(TurnErrorCode.WrongCredentials, "Wrong Credentials");
                }
                peer.Bound = true;
            }
            connection.Handoff = stream => RelayTcpAsync(peer, stream);
            Trace($"Connection {peer.Id} of {peer.Peer} bound to {connection.RemoteEndPoint}");
            return request.Success();
        }

        // a connection taken over of nothing: closed once the response before is sent
        private static Task Closing(Stream stream) => Task.CompletedTask;

        // a peer's connection and the client's data connection of it, each relayed to the other as it is - what the peer sent
        // before, left in its socket, first - until either ends, which ends the other (RFC 6062 5.4, 5.5)
        private async Task RelayTcpAsync(TcpPeer peer, Stream data)
        {
            NetworkStream peerStream;
            lock (_sync)
            {
                if (peer.Closed)
                    return;
                peer.Data = data;
                peerStream = peer.Client.GetStream();
            }
            try
            {
                var toPeer = CopyAsync(data, peerStream);
                var toClient = CopyAsync(peerStream, data);
                await Task.WhenAny(toPeer, toClient).ConfigureAwait(false);
            }
            finally
            {
                CloseTcpPeer(peer, "its connection ended");
            }
        }

        // of TCP's own flow control: what is not written is not read either (RFC 6062 3)
        private static async Task CopyAsync(Stream from, Stream to)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(16384);
            try
            {
                while (true)
                {
                    int read = await from.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (read == 0)
                        return;
                    await to.WriteAsync(buffer, 0, read).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException || ex is InvalidOperationException)
            {
            }
            finally
            {
                // of what TLS decrypted: cleared, before the pool hands it to anything else
                ArrayPool<byte>.Shared.Return(buffer, true);
            }
        }

        private void CloseTcpPeer(TcpPeer peer, string why)
        {
            TcpClient client;
            Stream data;
            lock (_sync)
            {
                if (peer.Closed)
                    return;
                peer.Closed = true;
                peer.Allocation.Connections.Remove(peer.Id);
                _tcpPeers.Remove(peer.Id);
                client = peer.Client;
                data = peer.Data;
            }
            client?.Dispose();
            try
            {
                data?.Dispose();
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
            }
            Trace($"Connection {peer.Id} of {peer.Peer} closed: {why}");
        }

        #endregion // TCP allocations

        #region Lifetimes

        // what expired: relays and the allocations of none left, permissions, channels, reservations
        // of a timer's thread: whatever a round of it throws - a handler's, a stream's - ends that round alone, never the process
        private void Sweep()
        {
            try
            {
                SweepOnce();
            }
            catch (Exception ex)
            {
                Trace($"Sweep failed: {ex.Message}");
            }
        }

        private void SweepOnce()
        {
            var expired = new List<(Allocation, Relay)>();
            var released = new List<Socket>();
            List<TcpPeer> unbound;
            lock (_sync)
            {
                DateTime now = DateTime.UtcNow;
                // the peers' connections of no ConnectionBind in time (RFC 6062 5.2, 5.3)
                unbound = _tcpPeers.Values.Where(p => !p.Bound && !p.Connecting && now - p.Waiting > TurnConstants.ConnectionBindTimeout).ToList();
                foreach (var allocation in _allocations.Values)
                {
                    expired.AddRange(allocation.Relays.Where(r => r.Expires <= now).Select(r => (allocation, r)));
                    foreach (var address in allocation.Permissions.Where(p => p.Value <= now).Select(p => p.Key).ToList())
                        allocation.Permissions.Remove(address);
                    foreach (var number in allocation.Channels.Where(c => c.Value.Expires <= now).Select(c => c.Key).ToList())
                        allocation.RemoveChannel(number);
                }
                foreach (var token in _reservations.Where(r => r.Value.Expires <= now).Select(r => r.Key).ToList())
                {
                    released.Add(_reservations[token].Socket);
                    _reservations.Remove(token);
                }
            }
            foreach (var peer in unbound)
                CloseTcpPeer(peer, "no ConnectionBind of it in time");
            foreach (var (allocation, relay) in expired)
                RemoveRelay(allocation, relay, "expired");
            foreach (var socket in released)
                socket.Dispose();
        }

        private void RemoveRelay(Allocation allocation, Relay relay, string why)
        {
            bool last;
            Socket reserved = null;
            List<TcpPeer> connections = null;
            lock (_sync)
            {
                if (!allocation.Relays.Remove(relay))
                    return;
                last = allocation.Relays.Count == 0;
                // of a TCP allocation, its peers' connections, and the client's data connections of them, with it (RFC 6062 5.5)
                if (last)
                    connections = allocation.Connections.Values.ToList();
                // its permissions and channels with it (RFC 8656 8.1)
                foreach (var address in allocation.Permissions.Keys.Where(a => a.AddressFamily == relay.Family).ToList())
                    allocation.Permissions.Remove(address);
                foreach (var channel in allocation.Channels.Values.Where(c => c.Peer.AddressFamily == relay.Family).ToList())
                    allocation.RemoveChannel(channel.Number);
                if (last)
                {
                    allocation.Closed = true;
                    if (_allocations.TryGetValue(allocation.Key, out var current) && current == allocation)
                        _allocations.Remove(allocation.Key);
                    // the port it reserved of EVEN-PORT, of no other allocation taken yet, released with it
                    if (allocation.ReservationToken != null && _reservations.TryGetValue(Convert.ToBase64String(allocation.ReservationToken), out var reservation))
                    {
                        _reservations.Remove(Convert.ToBase64String(allocation.ReservationToken));
                        reserved = reservation.Socket;
                    }
                }
            }
            relay.Socket?.Dispose();
            relay.Listener?.Stop();
            reserved?.Dispose();
            if (connections != null)
            {
                foreach (var connection in connections)
                    CloseTcpPeer(connection, "its allocation ended");
            }
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
