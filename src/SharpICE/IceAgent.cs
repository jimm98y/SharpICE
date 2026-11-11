// SharpICE
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
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE
{
    /// <summary>The state of an agent's connection (RFC 8445; as WebRTC's RTCIceConnectionState names them).</summary>
    public enum IceConnectionState
    {
        New,
        Checking,
        Connected,
        Disconnected,
        Failed,
        Closed
    }

    /// <summary>
    /// A datagram that is not STUN - DTLS, RTP, RTCP (RFC 7983) - received on one of the agent's sockets, of a peer it knows.
    /// Its buffer, and these arguments, are the agent's own again once the event returns: what is kept of them is to be copied.
    /// </summary>
    public sealed class IceDataReceivedEventArgs : EventArgs
    {
        public IceDataReceivedEventArgs(byte[] buffer, int offset, int count, IPEndPoint remoteEndPoint) => Set(buffer, offset, count, remoteEndPoint);

        internal IceDataReceivedEventArgs()
        {
        }

        public byte[] Buffer { get; private set; }
        public int Offset { get; private set; }
        public int Count { get; private set; }
        public IPEndPoint RemoteEndPoint { get; private set; }

        internal IceDataReceivedEventArgs Set(byte[] buffer, int offset, int count, IPEndPoint remoteEndPoint)
        {
            Buffer = buffer;
            Offset = offset;
            Count = count;
            RemoteEndPoint = remoteEndPoint;
            return this;
        }
    }

    /// <summary>
    /// An ICE agent (RFC 8445) of one component - RTP and RTCP multiplexed on it (RFC 5761), all media bundled (RFC 9143), as
    /// WebRTC has it. It gathers host candidates of the local addresses, a socket each, and server reflexive ones of STUN servers,
    /// and of TCP, if asked to, passive and active ones (RFC 6544); checks the pairs of them and the peer's candidates; and once
    /// one is selected, sends and receives the data of the layers above on it - every datagram that is not STUN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Checks are paced one every Ta, triggered ones first, then the waiting pair of the highest priority, then a frozen one of a
    /// foundation none of whose pairs is being checked - a pair's foundation unfrozen once one of its pairs succeeds (RFC 8445
    /// 6.1.4.2). A check is retransmitted over UDP as RFC 8489 6.2.1 says, and its pair fails once it is not answered.
    /// Controlling, it nominates the first pair that succeeds (RFC 8445 8.1.1); controlled, it selects the pair the peer
    /// nominates, and until then the best that succeeded, so that data can flow as soon as a pair does. The consent to send on
    /// the selected pair is checked every few seconds (RFC 7675).
    /// </para>
    /// <para>
    /// The peer's candidates are trickled (RFC 8838): it fails once all its pairs did and the peer said its candidates are
    /// complete - or, of no end-of-candidates, once none came for a while. One of an mDNS name is resolved first. Of a lite peer it
    /// controls (RFC 8445 6.1.1); lite itself, it sends no checks. A restart (RFC 8445 9) begins the checks again of new
    /// credentials, the data going by the pair selected until another is.
    /// </para>
    /// </remarks>
    public sealed partial class IceAgent : IDisposable
    {
        // ICE's ufrag of at least 24 bits of randomness and pwd of 128 (RFC 8445 5.3), of the ice-char of RFC 8839
        private const string IceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private const int MaxDatagram = 65536;

        // how long after the last of the peer's candidates its pairs, all failed, fail the agent, of no end-of-candidates
        private static readonly TimeSpan TrickleWait = TimeSpan.FromSeconds(5);

        internal sealed class LocalBase
        {
            // of UDP, the socket; of a passive candidate of TCP, the listener; of an active one, neither; of a relayed one, its
            // allocation's client
            public Socket Socket;
            public UdpSender Sender;
            public TcpListener Listener;
            public TurnClient Turn;
            // of a relayed candidate of TCP (RFC 6544, RFC 6062): the client of its TCP allocation, of connections, not of the
            // datagrams of Turn
            public TurnClient TcpRelay;

            // of its one receiving loop - the socket's, or the relay's client's - told of again of each datagram
            public readonly IceDataReceivedEventArgs Args = new IceDataReceivedEventArgs();

            // the socket's or the listener's; of an active candidate of TCP, its address and port 9
            public IPEndPoint EndPoint;
            public IceCandidate Candidate;
            public byte[] Buffer;

            // of TCP, or of TLS over it: of connections
            public bool IsStream => Candidate.IsStream;
        }

        // a STUN message to send: over a connection of TCP, or of the base's socket to an address
        private readonly struct Outgoing
        {
            public Outgoing(LocalBase local, IceTcpConnection connection, byte[] bytes, IPEndPoint to)
            {
                Base = local;
                Connection = connection;
                Bytes = bytes;
                To = to;
            }

            public LocalBase Base { get; }
            public IceTcpConnection Connection { get; }
            public byte[] Bytes { get; }
            public IPEndPoint To { get; }
        }

        private readonly object _sync = new object();
        private readonly IceAgentOptions _options;
        private readonly List<LocalBase> _bases = new List<LocalBase>();
        private readonly List<IceCandidate> _localCandidates = new List<IceCandidate>();
        private readonly List<IceCandidate> _remoteCandidates = new List<IceCandidate>();
        private readonly List<IceCandidatePair> _pairs = new List<IceCandidatePair>();
        private readonly LinkedList<IceCandidatePair> _triggered = new LinkedList<IceCandidatePair>();
        private readonly Dictionary<StunTransactionKey, IceCandidatePair> _transactions = new Dictionary<StunTransactionKey, IceCandidatePair>();
        private readonly List<IceTcpConnection> _connections = new List<IceTcpConnection>();
        private readonly List<TurnClient> _turns = new List<TurnClient>();
        private readonly Random _random = new Random();

        // the requests of gathering, each the base it was sent from and what is waiting for its answer
        private readonly Dictionary<StunTransactionKey, TaskCompletionSource<IPEndPoint>> _gatherings = new Dictionary<StunTransactionKey, TaskCompletionSource<IPEndPoint>>();

        private Timer _timer;
        private int _ticking;
        private bool _gathered;
        private bool _started;
        private bool _closed;
        private bool _restarting;
        private DateTime _lastConsentCheck = DateTime.MinValue;
        private TimeSpan _consentInterval;
        private DateTime _lastRemoteCandidate = DateTime.UtcNow;
        private bool _remoteGatheringComplete;
        private DateTime _remoteGatheringCompletedAt;
        private int _resolving;
        private byte[] _remoteKey;

        public IceAgent(IceAgentOptions options = null)
        {
            _options = options ?? new IceAgentOptions();
            // a lite agent is controlled (RFC 8445 6.1.1)
            Role = _options.Lite ? IceRole.Controlled : _options.Role;
            LocalUfrag = RandomIceString(8);
            LocalPassword = RandomIceString(24);
            byte[] tieBreaker = new byte[8];
            using (var random = RandomNumberGenerator.Create())
                random.GetBytes(tieBreaker);
            TieBreaker = BitConverter.ToUInt64(tieBreaker, 0);
            _consentInterval = NextConsentInterval();
        }

        public IceRole Role { get; private set; }

        /// <summary>The tie-breaker a role conflict is resolved by (RFC 8445 7.3.1.1).</summary>
        public ulong TieBreaker { get; }

        /// <summary>The agent's ice-ufrag: a new one of each restart.</summary>
        public string LocalUfrag { get; private set; }

        /// <summary>The agent's ice-pwd: a new one of each restart.</summary>
        public string LocalPassword { get; private set; }

        public string RemoteUfrag { get; private set; }

        public string RemotePassword { get; private set; }

        /// <summary>Whether the agent is a lite one: its session description is to say "a=ice-lite".</summary>
        public bool IsLite => _options.Lite;

        /// <summary>Whether the peer is a lite agent, of its session description's "a=ice-lite".</summary>
        public bool RemoteIsLite { get; private set; }

        /// <summary>Whether the peer said it has no more candidates: its "a=end-of-candidates".</summary>
        public bool RemoteGatheringComplete
        {
            get { lock (_sync) return _remoteGatheringComplete; }
        }

        public IceConnectionState State { get; private set; } = IceConnectionState.New;

        /// <summary>The pair the data goes by: the nominated one, else - controlled, until one is - the best that succeeded.</summary>
        public IceCandidatePair SelectedPair { get; private set; }

        public IReadOnlyList<IceCandidate> LocalCandidates
        {
            get { lock (_sync) return _localCandidates.ToList(); }
        }

        public IReadOnlyList<IceCandidate> RemoteCandidates
        {
            get { lock (_sync) return _remoteCandidates.ToList(); }
        }

        public IReadOnlyList<IceCandidatePair> Pairs
        {
            get { lock (_sync) return _pairs.ToList(); }
        }

        public event EventHandler<IceCandidate> CandidateGathered;
        public event EventHandler<IceConnectionState> StateChanged;
        public event EventHandler<IceCandidatePair> SelectedPairChanged;
        public event EventHandler<IceDataReceivedEventArgs> DataReceived;

        /// <summary>What resolves the peer's candidates of mDNS names: of a test, one of its own responder.</summary>
        internal MdnsResolver Mdns { get; set; } = new MdnsResolver();

        /// <summary>Of a test, the endpoint the responder of the agent's own names is of, rather than port 5353 and the groups.</summary>
        internal IPEndPoint MdnsResponderEndPoint { get; set; }

        /// <summary>The responder of the names of the agent's host candidates, of <see cref="IceAgentOptions.MdnsCandidates"/>.</summary>
        internal MdnsResponder MdnsResponder => _mdns;

        private MdnsResponder _mdns;

        private static string RandomIceString(int length)
        {
            byte[] bytes = new byte[length];
            using (var random = RandomNumberGenerator.Create())
                random.GetBytes(bytes);
            char[] chars = new char[length];
            for (int i = 0; i < length; i++)
                chars[i] = IceChars[bytes[i] % IceChars.Length];
            return new string(chars);
        }

        // RFC 7675 5.1: of 0.8 to 1.2 times the interval, at random, that the checks of many agents do not fall together
        private TimeSpan NextConsentInterval()
        {
            lock (_random)
                return TimeSpan.FromTicks((long)(_options.ConsentInterval.Ticks * (0.8 + 0.4 * _random.NextDouble())));
        }

        private void Trace(string message) => _options.Trace?.Invoke(message);

        #region Gathering

        /// <summary>
        /// The local addresses to gather candidates of: of the interfaces that are up, as the options choose, of no address being
        /// deprecated or not yet sure of (of its duplicate address detection); in the order of RFC 8421 4, of IPv6 first and the
        /// families intermingled.
        /// </summary>
        private List<IPAddress> GetLocalAddresses()
        {
            var addresses = new List<IPAddress>();
            var loopback = new List<IPAddress>();
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus != OperationalStatus.Up)
                    continue;
                bool isLoopback = networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback;
                foreach (var unicast in networkInterface.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;
                    if (address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        if (!_options.IncludeIPv6 || !IsUsableIPv6(address) || !IsPreferred(unicast))
                            continue;
                    }
                    else if (address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                    if (_options.AddressFilter != null && !_options.AddressFilter(address))
                        continue;

                    if (isLoopback || IPAddress.IsLoopback(address))
                        loopback.Add(address);
                    else if (!addresses.Contains(address))
                        addresses.Add(address);
                }
            }
            if (_options.IncludeLoopback || addresses.Count == 0)
                addresses.AddRange(loopback);
            return Intermingle(addresses);
        }

        /// <summary>
        /// Whether an IPv6 address is one a peer may reach (RFC 8421, RFC 6724): not link-local nor site-local, whose zone a peer
        /// has no part in; not multicast; not of IPv4 in IPv6 - mapped or compatible - nor of a tunnel of 6to4 (2002::/16), of
        /// Teredo (2001::/32) or of the 6bone (3ffe::/16), as browsers leave them out.
        /// </summary>
        internal static bool IsUsableIPv6(IPAddress address)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv4MappedToIPv6)
                return false;
            byte[] bytes = address.GetAddressBytes();
            if (bytes[0] == 0x20 && bytes[1] == 0x02)
                return false; // 6to4
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0)
                return false; // Teredo
            if (bytes[0] == 0x3F && bytes[1] == 0xFE)
                return false; // 6bone
            // IPv4-compatible (::a.b.c.d), but not the loopback, ::1
            bool compatible = true;
            for (int i = 0; i < 12; i++)
                compatible &= bytes[i] == 0;
            return !compatible || IPAddress.IsLoopback(address);
        }

        // of an address of the system's that says, not deprecated, nor tentative or a duplicate of another's: Windows alone
        //  says it, and elsewhere asking throws - each address taken, as the system has nothing of the kind to tell
        private static bool IsPreferred(UnicastIPAddressInformation unicast)
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                return true;
            try
            {
                return unicast.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred;
            }
            catch (PlatformNotSupportedException)
            {
                return true;
            }
        }

        /// <summary>
        /// The addresses of each family intermingled, IPv6 first (RFC 8421 4): of N6 of IPv6 and N4 of IPv4, N6 / N4 - rounded
        /// up - of IPv6 before each of IPv4, as the candidates' local preferences are to order them; the order within a family as
        /// it was.
        /// </summary>
        internal static List<IPAddress> Intermingle(IReadOnlyList<IPAddress> addresses)
        {
            var v6 = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).ToList();
            var v4 = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
            if (v6.Count == 0 || v4.Count == 0)
                return v6.Concat(v4).ToList();
            int run = (v6.Count + v4.Count - 1) / v4.Count;
            var ordered = new List<IPAddress>(addresses.Count);
            int i6 = 0, i4 = 0;
            while (i6 < v6.Count || i4 < v4.Count)
            {
                for (int k = 0; k < run && i6 < v6.Count; k++)
                    ordered.Add(v6[i6++]);
                if (i4 < v4.Count)
                    ordered.Add(v4[i4++]);
            }
            return ordered;
        }

        private Socket Bind(IPAddress address)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                // Windows reports an ICMP port unreachable of a datagram sent before as a reset of the next receive
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    const int SIO_UDP_CONNRESET = -1744830452;
                    socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                }

                if (_options.PortMin > 0 && _options.PortMax >= _options.PortMin)
                {
                    for (int port = _options.PortMin; port <= _options.PortMax; port++)
                    {
                        try
                        {
                            socket.Bind(new IPEndPoint(address, port));
                            return socket;
                        }
                        catch (SocketException)
                        {
                        }
                    }
                    throw new SocketException((int)SocketError.AddressAlreadyInUse);
                }

                socket.Bind(new IPEndPoint(address, 0));
                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Gathers the candidates (RFC 8445 5.1.1): a host candidate of each local address, of a socket bound to it; of TCP, a
        /// passive and an active one of each; of each public address of the options, one of each socket's port; then - of a
        /// full agent - a server reflexive one of each STUN server that answers, of each IPv4 socket. Each is told of as it is gathered too, to be trickled. Once only: the candidates of a second call are
        /// those of the first.
        /// </summary>
        public async Task<IReadOnlyList<IceCandidate>> GatherCandidatesAsync(CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (_closed)
                    throw new ObjectDisposedException(nameof(IceAgent));
                if (_gathered)
                    return _localCandidates.ToList();
                _gathered = true;
            }

            var addresses = GetLocalAddresses();
            var gathered = new List<IceCandidate>();
            if (_options.MdnsCandidates)
            {
                var responder = new MdnsResponder(addresses, MdnsResponderEndPoint, Trace);
                lock (_sync)
                {
                    if (_closed)
                    {
                        responder.Dispose();
                        throw new ObjectDisposedException(nameof(IceAgent));
                    }
                    _mdns = responder;
                }
            }
            if (_options.IncludeUdp && !_options.RelayOnly)
            {
                for (int i = 0; i < addresses.Count; i++)
                {
                    Socket socket;
                    try
                    {
                        socket = Bind(addresses[i]);
                    }
                    catch (SocketException ex)
                    {
                        Trace($"Could not bind {addresses[i]}: {ex.Message}");
                        continue;
                    }

                    var endPoint = (IPEndPoint)socket.LocalEndPoint;
                    var candidate = new IceCandidate
                    {
                        Foundation = (i + 1).ToString(CultureInfo.InvariantCulture),
                        Component = IceCandidate.RtpComponent,
                        Transport = "udp",
                        Priority = IceCandidate.ComputePriority(IceCandidateType.Host, 65535 - i, IceCandidate.RtpComponent),
                        Address = HostAddress(endPoint.Address),
                        Port = endPoint.Port,
                        Type = IceCandidateType.Host,
                    };
                    var local = new LocalBase { Socket = socket, Sender = new UdpSender(socket), EndPoint = endPoint, Candidate = candidate, Buffer = new byte[MaxDatagram] };
                    AddBase(local, gathered);
                    StartReceiving(local);
                }
            }

            if (_options.IncludeTcp && !_options.RelayOnly)
                GatherTcp(addresses, gathered);
            if (_options.IncludeTls && !_options.RelayOnly)
                GatherTls(addresses, gathered);
            if (!_options.RelayOnly)
                GatherPublic(gathered);

            // a lite agent is of host candidates alone (RFC 8445 2.5)
            if (_options.IncludeUdp && !IsLite && !_options.RelayOnly)
                await GatherServerReflexiveAsync(gathered, cancellationToken).ConfigureAwait(false);
            if (!IsLite)
                await GatherRelayedAsync(gathered, cancellationToken).ConfigureAwait(false);
            return gathered;
        }

        // the unspecified address of the family, of a related address not to be told
        private static string NoAddress(AddressFamily family) => family == AddressFamily.InterNetworkV6 ? "::" : "0.0.0.0";

        // a host candidate's address: of mDNS candidates, the name it is hidden behind
        private string HostAddress(IPAddress address) => _mdns != null ? _mdns.Register(address) : address.ToString();

        private void AddBase(LocalBase local, List<IceCandidate> gathered)
        {
            lock (_sync)
            {
                _bases.Add(local);
                _localCandidates.Add(local.Candidate);
                foreach (var remote in _remoteCandidates)
                    AddPair(local, remote);
            }
            gathered.Add(local.Candidate);
            Trace($"Gathered {local.Candidate}");
            CandidateGathered?.Invoke(this, local.Candidate);
        }

        // the public addresses of a NAT of one to one: of each socket and passive listener of the family, a candidate of the
        // address and the base's port - of a full agent server reflexive, of a lite one a host candidate (RFC 8445 2.5)
        private void GatherPublic(List<IceCandidate> gathered)
        {
            var addresses = _options.PublicAddresses;
            if (addresses == null || addresses.Count == 0)
                return;
            List<LocalBase> bases;
            lock (_sync)
                bases = _bases.Where(b => (b.Socket != null || b.Listener != null) && !IPAddress.IsLoopback(b.EndPoint.Address)).ToList();

            var type = IsLite ? IceCandidateType.Host : IceCandidateType.ServerReflexive;
            int index = 0;
            foreach (var address in addresses)
            {
                foreach (var local in bases)
                {
                    // of the family's bases; of an address that is the base's own, no NAT: nothing to tell of
                    if (local.EndPoint.AddressFamily != address.AddressFamily || local.EndPoint.Address.Equals(address))
                        continue;
                    bool stream = local.Listener != null;
                    string text = address.ToString();
                    lock (_sync)
                    {
                        if (_localCandidates.Any(c => c.Address == text && c.Port == local.EndPoint.Port && c.Transport == local.Candidate.Transport))
                            continue;
                    }
                    // of a host candidate, one below its base's, that no two are of one priority
                    int preference = type == IceCandidateType.Host ? Math.Max(0, local.Candidate.LocalPreference - 1) : local.Candidate.LocalPreference;
                    var candidate = new IceCandidate
                    {
                        Foundation = "p" + (++index).ToString(CultureInfo.InvariantCulture),
                        Component = IceCandidate.RtpComponent,
                        Transport = local.Candidate.Transport,
                        Priority = IceCandidate.ComputePriority(type, preference, IceCandidate.RtpComponent, local.Candidate.Transport),
                        Address = text,
                        Port = local.EndPoint.Port,
                        Type = type,
                    };
                    if (type == IceCandidateType.ServerReflexive)
                    {
                        // of mDNS candidates, no address of the host's (draft-ietf-mmusic-mdns-ice-candidates 3.1.2.2)
                        candidate.RelatedAddress = _mdns != null ? NoAddress(address.AddressFamily) : local.EndPoint.Address.ToString();
                        candidate.RelatedPort = _mdns != null ? 0 : local.EndPoint.Port;
                    }
                    if (stream)
                        candidate.TcpType = IceCandidate.TcpPassive;
                    lock (_sync)
                        _localCandidates.Add(candidate);
                    gathered.Add(candidate);
                    Trace($"Gathered {candidate}");
                    CandidateGathered?.Invoke(this, candidate);
                }
            }
        }

        private async Task GatherServerReflexiveAsync(List<IceCandidate> gathered, CancellationToken cancellationToken)
        {
            if (_options.StunServers.Count == 0)
                return;

            var requests = new List<Task<(LocalBase Base, IPEndPoint Mapped)>>();
            foreach (string server in _options.StunServers)
            {
                foreach (var local in _bases.Where(b => b.Socket != null && !IPAddress.IsLoopback(b.EndPoint.Address)))
                    requests.Add(RequestMappedAsync(local, server, cancellationToken));
            }

            var results = await Task.WhenAll(requests).ConfigureAwait(false);
            int index = 0;
            foreach (var (local, mapped) in results)
            {
                if (mapped == null)
                    continue;
                // of no NAT, the host candidate again: redundant (RFC 8445 5.1.3)
                if (mapped.Equals(local.EndPoint))
                    continue;
                lock (_sync)
                {
                    // a NAT that maps each socket alike gives one of them only
                    if (_localCandidates.Any(c => c.Type == IceCandidateType.ServerReflexive && c.Address == mapped.Address.ToString() && c.Port == mapped.Port))
                        continue;
                }
                var candidate = new IceCandidate
                {
                    Foundation = "s" + (++index).ToString(CultureInfo.InvariantCulture),
                    Component = IceCandidate.RtpComponent,
                    Transport = "udp",
                    // of its base's local preference: of the order of RFC 8421 too
                    Priority = IceCandidate.ComputePriority(IceCandidateType.ServerReflexive, local.Candidate.LocalPreference, IceCandidate.RtpComponent),
                    Address = mapped.Address.ToString(),
                    Port = mapped.Port,
                    Type = IceCandidateType.ServerReflexive,
                    // of mDNS candidates, no address of the host's (draft-ietf-mmusic-mdns-ice-candidates 3.1.2.2)
                    RelatedAddress = _mdns != null ? NoAddress(mapped.AddressFamily) : local.EndPoint.Address.ToString(),
                    RelatedPort = _mdns != null ? 0 : local.EndPoint.Port,
                };
                lock (_sync)
                    _localCandidates.Add(candidate);
                gathered.Add(candidate);
                Trace($"Gathered {candidate}");
                CandidateGathered?.Invoke(this, candidate);
            }
        }

        // a relayed candidate of each TURN server's allocation (RFC 8445 5.1.1.2), of its mapped address as its related one
        private async Task GatherRelayedAsync(List<IceCandidate> gathered, CancellationToken cancellationToken)
        {
            if (_options.TurnServers.Count == 0)
                return;
            // of ICE-TCP, a TCP allocation too of each server of TCP or TLS (RFC 6062): its relayed candidates of TCP
            var tcpServers = _options.IncludeTcp ? _options.TurnServers.Where(IsOfStream).ToList() : new List<IceTurnServer>();
            var tcpAllocating = Task.WhenAll(tcpServers.Select(server => AllocateAsync(server, cancellationToken, true)));
            var allocations = await Task.WhenAll(_options.TurnServers.Select(server => AllocateAsync(server, cancellationToken))).ConfigureAwait(false);
            var tcpAllocations = await tcpAllocating.ConfigureAwait(false);
            for (int i = 0; i < tcpAllocations.Length; i++)
            {
                if (tcpAllocations[i] != null)
                    GatherTcpRelayed(tcpAllocations[i], i, gathered);
            }
            int index = 0;
            foreach (var turn in allocations)
            {
                if (turn == null)
                    continue;
                foreach (var relayed in turn.RelayedEndPoints.OrderBy(e => e.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1))
                {
                    var candidate = new IceCandidate
                    {
                        Foundation = "r" + (++index).ToString(CultureInfo.InvariantCulture),
                        Component = IceCandidate.RtpComponent,
                        Transport = "udp",
                        Priority = IceCandidate.ComputePriority(IceCandidateType.Relayed, 65535 - index, IceCandidate.RtpComponent),
                        Address = relayed.Address.ToString(),
                        Port = relayed.Port,
                        Type = IceCandidateType.Relayed,
                        // of mDNS candidates, no address of the host's
                        RelatedAddress = _mdns != null || turn.MappedEndPoint == null ? NoAddress(relayed.AddressFamily) : turn.MappedEndPoint.Address.ToString(),
                        RelatedPort = _mdns != null || turn.MappedEndPoint == null ? 0 : turn.MappedEndPoint.Port,
                    };
                    var local = new LocalBase { Turn = turn, EndPoint = relayed, Candidate = candidate };
                    turn.DataReceived += (s, e) =>
                    {
                        try
                        {
                            OnDatagram(local, null, e.Buffer, e.Offset, e.Count, e.Peer);
                        }
                        catch (Exception ex)
                        {
                            Trace($"Relayed data from {e.Peer} failed: {ex}");
                        }
                    };
                    AddBase(local, gathered);
                }
            }
        }

        // a server of TCP, or of TLS: "turn:...?transport=tcp", or "turns:..." of no "?transport=udp"
        private static bool IsOfStream(IceTurnServer server)
        {
            try
            {
                return StunUri.Parse(server.Uri).TransportProtocol == "tcp";
            }
            catch (FormatException)
            {
                return false;
            }
        }

        // of TCP, a TCP allocation (RFC 6062) of a server of TCP or TLS, of the relayed candidates of ICE-TCP
        private async Task<TurnClient> AllocateAsync(IceTurnServer server, CancellationToken cancellationToken, bool tcp = false)
        {
            TurnClient turn = null;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_options.TurnServerTimeout);
                try
                {
                    var options = new StunClientOptions
                    {
                        Username = server.Username,
                        Password = server.Password,
                        Software = _options.Software,
                        CertificateValidation = _options.TurnCertificateValidation,
                        InitialRetransmissionTimeout = _options.InitialRetransmissionTimeout,
                        DtlsStack = _options.DtlsStack,
                        TlsStack = _options.TlsStack,
                    };
                    turn = new TurnClient(options);
                    await turn.ConnectAsync(server.Uri, timeout.Token).ConfigureAwait(false);
                    // of IPv6, a relayed address of each family, of a server that allocates them (RFC 8656 7.1); one of RFC 5766
                    // takes the attribute for one it does not know, and allocates one of IPv4; of TCP, of one family alone
                    await turn.AllocateAsync(tcp ? new TurnAllocateOptions { Tcp = true } : new TurnAllocateOptions { Dual = _options.IncludeIPv6 }, timeout.Token).ConfigureAwait(false);
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            turn.Dispose();
                            return null;
                        }
                        _turns.Add(turn);
                    }
                    Trace($"Allocated {(tcp ? "TCP " : "")}{string.Join(", ", turn.RelayedEndPoints)} of {server.Uri}");
                    return turn;
                }
                catch (Exception ex) when (ex is TurnException || ex is StunException || ex is OperationCanceledException || ex is System.IO.IOException || ex is SocketException || ex is FormatException)
                {
                    Trace($"No allocation of {server.Uri}: {ex.Message}");
                    turn?.Dispose();
                    return null;
                }
            }
        }

        private async Task<(LocalBase, IPEndPoint)> RequestMappedAsync(LocalBase local, string server, CancellationToken cancellationToken)
        {
            var serverEndPoint = await StunClient.ResolveAsync(server, local.EndPoint.AddressFamily).ConfigureAwait(false);
            if (serverEndPoint == null)
                return (local, null);

            var request = StunClient.CreateBindingRequest(_options.Software);
            byte[] bytes = request.ToBytes();
            var answered = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
            var key = Key(request.TransactionId);
            lock (_sync)
                _gatherings[key] = answered;

            try
            {
                DateTime deadline = DateTime.UtcNow + _options.StunServerTimeout;
                TimeSpan rto = _options.InitialRetransmissionTimeout;
                while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
                {
                    local.Socket.SendTo(bytes, serverEndPoint);
                    TimeSpan wait = TimeSpan.FromTicks(Math.Min(rto.Ticks, Math.Max(0, (deadline - DateTime.UtcNow).Ticks)));
                    if (await Task.WhenAny(answered.Task, Task.Delay(wait, cancellationToken)).ConfigureAwait(false) == answered.Task)
                        return (local, answered.Task.Result);
                    rto = TimeSpan.FromTicks(rto.Ticks * 2);
                }
                return (local, null);
            }
            catch (TaskCanceledException)
            {
                return (local, null);
            }
            finally
            {
                lock (_sync)
                    _gatherings.Remove(key);
            }
        }

        #endregion // Gathering

        #region Remote

        /// <summary>
        /// The peer's ice-ufrag and ice-pwd: of its session description. Of others than the peer had, after the checks began, the
        /// peer restarted ICE, and so does the agent (RFC 8445 9): true then, and the agent's own credentials are new, to answer
        /// with, its candidates to be signalled again, as the peer's are.
        /// </summary>
        public bool SetRemoteCredentials(string ufrag, string password)
        {
            if (ufrag == null)
                throw new ArgumentNullException(nameof(ufrag));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            bool restarted = false;
            lock (_sync)
            {
                if (RemoteUfrag != null && !_restarting && (RemoteUfrag != ufrag || RemotePassword != password))
                {
                    RestartUnderLock();
                    restarted = true;
                }
                RemoteUfrag = ufrag;
                RemotePassword = password;
                _remoteKey = StunMessage.ShortTermKey(password);
                _restarting = false;
            }
            if (restarted)
                Trace("Restarted by the peer: new local credentials");
            return restarted;
        }

        /// <summary>
        /// Whether the peer is a lite agent, of its session description's "a=ice-lite": of one, a full agent controls (RFC 8445
        /// 6.1.1), as the peer sends no checks.
        /// </summary>
        public void SetRemoteLite(bool lite)
        {
            bool switched = false;
            lock (_sync)
            {
                RemoteIsLite = lite;
                if (lite && !IsLite && Role != IceRole.Controlling)
                {
                    SwitchRole(IceRole.Controlling);
                    switched = true;
                }
            }
            if (switched)
                Trace("The peer is lite: controlling");
        }

        /// <summary>
        /// A candidate of the peer's - of its session description, or trickled - of component 1, of UDP, or of TCP of an agent
        /// of TCP, active or passive. One of a name is resolved; one of an mDNS name (".local") of multicast DNS, after this
        /// returns. False of one that is not used.
        /// </summary>
        public bool AddRemoteCandidate(IceCandidate candidate)
        {
            if (candidate == null || candidate.Component != IceCandidate.RtpComponent)
                return false;
            if (!candidate.IsUdp && !(candidate.IsTcp && _options.IncludeTcp) && !(candidate.IsTls && _options.IncludeTls))
                return false;
            // of TCP and TLS, active and passive ones; simultaneous-open is not done
            if (candidate.IsStream && candidate.TcpType != IceCandidate.TcpActive && candidate.TcpType != IceCandidate.TcpPassive)
                return false;
            if (candidate.Port < 0 || candidate.Port > IPEndPoint.MaxPort)
                return false;
            lock (_sync)
            {
                // of a peer that signals without end: each candidate pairs, and is checked
                if (_remoteCandidates.Count + _resolving >= _options.MaxRemoteCandidates)
                {
                    Trace($"Candidate left out, of {_options.MaxRemoteCandidates} already: {candidate}");
                    return false;
                }
            }

            var endPoint = candidate.EndPoint;
            if (endPoint == null)
            {
                if (candidate.Address == null)
                    return false;
                if (candidate.Address.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                {
                    if (!_options.ResolveMdns)
                        return false;
                    lock (_sync)
                    {
                        if (_closed)
                            return false;
                        _resolving++;
                    }
                    _ = ResolveMdnsAsync(candidate);
                    return true;
                }
                if (!_options.ResolveHostNames)
                    return false;
                try
                {
                    var address = Dns.GetHostAddresses(candidate.Address).FirstOrDefault();
                    if (address == null)
                        return false;
                    candidate.Address = address.ToString();
                    endPoint = new IPEndPoint(address, candidate.Port);
                }
                catch (Exception ex) when (ex is SocketException || ex is ArgumentException)
                {
                    return false;
                }
            }
            return AddResolved(candidate, endPoint);
        }

        /// <summary>A candidate of its SDP line; of "end-of-candidates", the peer has no more (see <see cref="SetRemoteGatheringComplete"/>).</summary>
        public bool AddRemoteCandidate(string candidate)
        {
            string text = candidate?.Trim();
            if (text == "end-of-candidates" || text == "a=end-of-candidates")
            {
                SetRemoteGatheringComplete();
                return true;
            }
            return AddRemoteCandidate(IceCandidate.Parse(candidate));
        }

        /// <summary>
        /// The peer has no more candidates: its "a=end-of-candidates" (RFC 8838 13). Once all the pairs failed, the agent fails at
        /// once rather than waiting for more.
        /// </summary>
        public void SetRemoteGatheringComplete()
        {
            lock (_sync)
            {
                if (_remoteGatheringComplete)
                    return;
                _remoteGatheringComplete = true;
                _remoteGatheringCompletedAt = DateTime.UtcNow;
            }
            Trace("The peer's candidates are complete");
        }

        private async Task ResolveMdnsAsync(IceCandidate candidate)
        {
            string name = candidate.Address;
            try
            {
                var locals = GetLocalAddresses().Where(a => !IPAddress.IsLoopback(a) || _options.IncludeLoopback).ToList();
                var address = await Mdns.ResolveAsync(name, locals, _options.IncludeIPv6, _options.MdnsTimeout).ConfigureAwait(false);
                if (address == null)
                {
                    Trace($"Could not resolve {name}");
                    return;
                }
                Trace($"Resolved {name}: {address}");
                candidate.Address = address.ToString();
                AddResolved(candidate, new IPEndPoint(address, candidate.Port));
            }
            catch (Exception ex)
            {
                Trace($"Resolving {name} failed: {ex.Message}");
            }
            finally
            {
                lock (_sync)
                    _resolving--;
            }
        }

        private bool AddResolved(IceCandidate candidate, IPEndPoint endPoint)
        {
            lock (_sync)
            {
                if (_closed)
                    return false;
                var existing = _remoteCandidates.FirstOrDefault(c => IceCandidate.SameTransport(c, candidate) && Equals(c.EndPoint, endPoint));
                if (existing != null)
                {
                    // a peer reflexive one learnt of the peer's checks before it was signalled - of an mDNS name resolved after
                    // them, as one of them: of its signalled type, foundation and priority from now on (RFC 8445 7.3.1.3)
                    if (existing.Type == IceCandidateType.PeerReflexive && candidate.Type != IceCandidateType.PeerReflexive)
                    {
                        existing.Type = candidate.Type;
                        existing.Foundation = candidate.Foundation;
                        existing.Priority = candidate.Priority;
                        foreach (var pair in _pairs.Where(p => p.Remote == existing))
                            pair.Priority = PairPriority(pair);
                        Trace($"Signalled {existing}");
                    }
                    return false;
                }
                _remoteCandidates.Add(candidate);
                _lastRemoteCandidate = DateTime.UtcNow;
                foreach (var local in _bases)
                    AddPair(local, candidate);
            }
            Trace($"Remote {candidate}");
            // of the relays of TCP, a permission of its address: the peer's connections to them come of it
            PermitOnTcpRelays(endPoint.Address);
            return true;
        }

        // under the lock
        private IceCandidatePair AddPair(LocalBase local, IceCandidate remote)
        {
            var endPoint = remote.EndPoint;
            if (endPoint == null || endPoint.AddressFamily != local.EndPoint.AddressFamily)
                return null;
            // a loopback address reaches only one of its own, and one of a network only one of a network
            if (IPAddress.IsLoopback(endPoint.Address) != IPAddress.IsLoopback(local.EndPoint.Address))
                return null;
            if (!IceCandidate.SameTransport(local.Candidate, remote))
                return null;
            // of TCP and TLS, an active candidate of the peer's passive ones; a passive one's pairs are of the connections the
            // peer makes to it, as its checks come over them (RFC 6544 6.2)
            if (local.IsStream && (local.Candidate.TcpType != IceCandidate.TcpActive || remote.TcpType != IceCandidate.TcpPassive))
                return null;
            // of a relay of TCP and the peer's of one server's address: its Connect and the peer's to each other are of one
            // 4-tuple of the server's, which two would make at once, and fail of each other - of the lower relayed port alone,
            // alike of both agents, whichever their roles
            if (local.TcpRelay != null && remote.Type == IceCandidateType.Relayed && local.TcpRelay.RelayedEndPoint is IPEndPoint relayed
                && relayed.Address.Equals(endPoint.Address) && relayed.Port >= endPoint.Port)
                return null;

            var existing = _pairs.FirstOrDefault(p => p.Base == local && p.RemoteEndPoint.Equals(endPoint));
            if (existing != null)
                return existing;

            var pair = new IceCandidatePair(local, remote, endPoint);
            pair.Priority = PairPriority(pair);
            // one pair of a foundation is checked at a time, the others frozen until one of them succeeds (RFC 8445 6.1.2.6)
            pair.State = _pairs.Any(p => p.Foundation == pair.Foundation && (p.State == IceCandidatePairState.Waiting || p.State == IceCandidatePairState.InProgress))
                ? IceCandidatePairState.Frozen
                : IceCandidatePairState.Waiting;
            _pairs.Add(pair);
            return pair;
        }

        private ulong PairPriority(IceCandidatePair pair) => Role == IceRole.Controlling
            ? IceCandidatePair.ComputePriority(pair.Local.Priority, pair.Remote.Priority)
            : IceCandidatePair.ComputePriority(pair.Remote.Priority, pair.Local.Priority);

        #endregion // Remote

        #region Checks

        /// <summary>Begins the checks: of the pairs there are, and of those of candidates added after. Of a lite agent, the answers alone.</summary>
        public void Start()
        {
            lock (_sync)
            {
                if (_closed)
                    throw new ObjectDisposedException(nameof(IceAgent));
                if (_started)
                    return;
                if (RemoteUfrag == null && !IsLite)
                    throw new InvalidOperationException("The peer's credentials are not known: see SetRemoteCredentials.");
                _started = true;
                _lastRemoteCandidate = DateTime.UtcNow;
            }
            SetState(IceConnectionState.Checking);
            _timer = new Timer(_ => Tick(), null, TimeSpan.Zero, _options.CheckInterval);
        }

        /// <summary>
        /// Restarts ICE (RFC 8445 9): new local credentials - to be signalled, with the candidates, in a new offer - and the peer's
        /// candidates and credentials forgotten, until it signals them anew. The data goes by the pair selected until another
        /// is; the agent's candidates stay what they are.
        /// </summary>
        public void Restart()
        {
            lock (_sync)
            {
                if (_closed)
                    throw new ObjectDisposedException(nameof(IceAgent));
                RestartUnderLock();
                _restarting = true;
            }
            Trace("Restarted: new local credentials");
        }

        // under the lock
        private void RestartUnderLock()
        {
            LocalUfrag = RandomIceString(8);
            LocalPassword = RandomIceString(24);
            RemoteUfrag = null;
            RemotePassword = null;
            _remoteKey = null;
            _remoteCandidates.Clear();
            _triggered.Clear();
            _transactions.Clear();
            _remoteGatheringComplete = false;
            _lastRemoteCandidate = DateTime.UtcNow;
            _pairs.Clear();

            var selected = SelectedPair;
            if (selected != null)
            {
                // the data goes on by it, its consent not checked until a pair of the new credentials is selected
                selected.Nominated = false;
                selected.Nominating = false;
                selected.LastConsent = DateTime.UtcNow;
                if (selected.State == IceCandidatePairState.InProgress)
                    selected.State = IceCandidatePairState.Succeeded;
            }
            foreach (var connection in _connections.Where(c => c != selected?.Connection).ToList())
            {
                _connections.Remove(connection);
                connection.Dispose();
            }
        }

        private void Tick()
        {
            if (Interlocked.Exchange(ref _ticking, 1) == 1)
                return;
            try
            {
                var sends = new List<Outgoing>();
                var connects = new List<IceCandidatePair>();
                IceConnectionState? newState = null;
                lock (_sync)
                {
                    if (_closed)
                        return;
                    DateTime now = DateTime.UtcNow;

                    // a lite agent sends no checks (RFC 8445 2.5)
                    if (!IsLite)
                    {
                        // the checks in flight, retransmitted, or given up
                        foreach (var pair in _pairs)
                        {
                            if (pair.State != IceCandidatePairState.InProgress || now < pair.NextTransmission)
                                continue;
                            // over TCP and TLS, no retransmissions (RFC 6544 7.1): given up as late as one of UDP is
                            if (pair.IsStream || pair.Transmissions >= _options.MaxTransmissions)
                            {
                                _transactions.Remove(Key(pair.TransactionId));
                                pair.State = pair.LastSucceeded > DateTime.MinValue ? IceCandidatePairState.Succeeded : IceCandidatePairState.Failed;
                                Trace($"Check timed out: {pair}");
                                continue;
                            }
                            pair.Transmissions++;
                            pair.Timeout = TimeSpan.FromTicks(pair.Timeout.Ticks * 2);
                            pair.NextTransmission = now + pair.Timeout;
                            sends.Add(new Outgoing(pair.Base, null, pair.Request, pair.RemoteEndPoint));
                        }

                        // one new check every Ta, of the peer's credentials known: a triggered one first, else an ordinary one
                        if (_remoteKey != null)
                        {
                            IceCandidatePair next = null;
                            while (_triggered.Count > 0 && next == null)
                            {
                                var triggered = _triggered.First.Value;
                                _triggered.RemoveFirst();
                                if (triggered.State != IceCandidatePairState.InProgress && _pairs.Contains(triggered))
                                    next = triggered;
                            }
                            next ??= NextOrdinaryCheck();
                            if (next != null)
                                Check(next, now, sends, connects);
                        }
                    }

                    // the consent of the selected pair: not of one of credentials a restart left behind
                    var selected = SelectedPair;
                    if (selected != null)
                    {
                        if (!IsLite && _remoteKey != null && _pairs.Contains(selected) && now - _lastConsentCheck >= _consentInterval
                            && selected.State != IceCandidatePairState.InProgress)
                        {
                            _lastConsentCheck = now;
                            _consentInterval = NextConsentInterval();
                            Check(selected, now, sends, connects);
                        }

                        TimeSpan silent = now - selected.LastConsent;
                        if (silent > _options.ConsentTimeout)
                            newState = IceConnectionState.Failed;
                        else if (silent > _options.DisconnectedTimeout)
                            newState = IceConnectionState.Disconnected;
                        else if (State == IceConnectionState.Disconnected)
                            newState = IceConnectionState.Connected;
                    }
                    else if (!IsLite && _resolving == 0 && _remoteKey != null)
                    {
                        // all the pairs failed: at once of the peer's candidates complete (RFC 8838 8), else once none came for
                        // a while; of no pair at all, once the peer's checks made none either
                        bool allFailed = _pairs.Count > 0 && _pairs.All(p => p.State == IceCandidatePairState.Failed);
                        if (allFailed && (_remoteGatheringComplete || now - _lastRemoteCandidate > TrickleWait))
                            newState = IceConnectionState.Failed;
                        else if (_pairs.Count == 0 && _remoteGatheringComplete && now - _remoteGatheringCompletedAt > _options.DisconnectedTimeout)
                            newState = IceConnectionState.Failed;
                    }
                }

                foreach (var outgoing in sends)
                    SendStun(outgoing);
                foreach (var pair in connects)
                    _ = ConnectAsync(pair);
                if (newState != null)
                    SetState(newState.Value);
            }
            catch (Exception ex)
            {
                Trace($"Tick failed: {ex}");
            }
            finally
            {
                Interlocked.Exchange(ref _ticking, 0);
            }
        }

        // under the lock: the waiting pair of the highest priority; of none, the frozen one of the highest of a foundation none
        // of whose pairs is waiting or in progress (RFC 8445 6.1.4.2)
        private IceCandidatePair NextOrdinaryCheck()
        {
            var waiting = _pairs.Where(p => p.State == IceCandidatePairState.Waiting && IsCheckable(p)).OrderByDescending(p => p.Priority).FirstOrDefault();
            if (waiting != null)
                return waiting;
            var busy = new HashSet<string>(_pairs.Where(p => p.State == IceCandidatePairState.Waiting || p.State == IceCandidatePairState.InProgress).Select(p => p.Foundation));
            return _pairs.Where(p => p.State == IceCandidatePairState.Frozen && IsCheckable(p) && !busy.Contains(p.Foundation))
                .OrderByDescending(p => p.Priority).FirstOrDefault();
        }

        // of TCP and TLS, a pair of the agent's active candidate, or one of a connection there is
        private static bool IsCheckable(IceCandidatePair pair)
            => !pair.IsStream || pair.Connection != null || pair.Local.TcpType == IceCandidate.TcpActive;

        // under the lock: the check begun, sent at once, or of TCP and TLS, once its connection is made
        private void Check(IceCandidatePair pair, DateTime now, List<Outgoing> sends, List<IceCandidatePair> connects)
        {
            byte[] bytes = BeginCheck(pair, now);
            if (pair.IsStream && pair.Connection == null)
                connects.Add(pair);
            else
                sends.Add(new Outgoing(pair.Base, pair.Connection, bytes, pair.RemoteEndPoint));
        }

        // under the lock: a check of the pair (RFC 8445 7.2.4), its request kept for its retransmissions
        private byte[] BeginCheck(IceCandidatePair pair, DateTime now)
        {
            if (pair.TransactionId != null)
                _transactions.Remove(Key(pair.TransactionId));

            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request);
            request.AddString(StunAttributeType.Username, RemoteUfrag + ":" + LocalUfrag);
            // the priority of the peer reflexive candidate the check may make of the pair's local one (RFC 8445 7.1.1)
            request.AddUInt32(StunAttributeType.Priority, IceCandidate.ComputePriority(IceCandidateType.PeerReflexive, pair.Local.LocalPreference, IceCandidate.RtpComponent, pair.Local.Transport));
            if (Role == IceRole.Controlling)
            {
                request.AddUInt64(StunAttributeType.IceControlling, TieBreaker);
                // nominated by a check of the pair that succeeded: once, and on a pair that works (RFC 8445 8.1.1)
                pair.Nominating = pair.State == IceCandidatePairState.Succeeded && !_pairs.Any(p => p.Nominated && p != pair) && (pair.Nominating || !pair.Nominated);
                if (pair.Nominating)
                    request.AddAttribute(StunAttributeType.UseCandidate, new byte[0]);
            }
            else
            {
                request.AddUInt64(StunAttributeType.IceControlled, TieBreaker);
                pair.Nominating = false;
            }
            if (_options.Software != null)
                request.AddString(StunAttributeType.Software, _options.Software);

            pair.Request = request.ToBytes(_remoteKey);
            pair.TransactionId = request.TransactionId;
            pair.Transmissions = 1;
            pair.Timeout = _options.InitialRetransmissionTimeout;
            pair.CheckStarted = now;
            // of TCP and TLS, the whole of the time UDP's retransmissions would take, at once
            pair.NextTransmission = now + (pair.IsStream
                ? TimeSpan.FromTicks(_options.InitialRetransmissionTimeout.Ticks * ((1L << _options.MaxTransmissions) - 1))
                : pair.Timeout);
            // of a pair that worked too - its consent, or its nomination - which goes back to it if no answer comes
            pair.State = IceCandidatePairState.InProgress;
            _transactions[Key(request.TransactionId)] = pair;
            return pair.Request;
        }

        private static StunTransactionKey Key(byte[] transactionId) => new StunTransactionKey(transactionId);

        #endregion // Checks

        #region Receiving

        private void StartReceiving(LocalBase local)
        {
            Task.Run(async () =>
            {
                var receiver = new UdpReceiver(local.Socket);
                while (!_closed)
                {
                    int count;
                    try
                    {
                        count = await receiver.ReceiveAsync(local.Buffer, 0, local.Buffer.Length).ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (SocketException ex)
                    {
                        if (_closed)
                            break;
                        // a datagram larger than the buffer, or a reset of a port unreachable: the next
                        Trace($"Receive on {local.EndPoint}: {ex.SocketErrorCode}");
                        continue;
                    }

                    try
                    {
                        OnDatagram(local, null, local.Buffer, 0, count, receiver.RemoteEndPoint);
                    }
                    catch (Exception ex)
                    {
                        Trace($"Datagram from {receiver.RemoteEndPoint} failed: {ex}");
                    }
                }
            });
        }

        // a datagram of a socket of UDP, or a frame of a connection of TCP
        private void OnDatagram(LocalBase local, IceTcpConnection connection, byte[] buffer, int offset, int count, IPEndPoint from)
        {
            from = Normalize(from);
            if (StunMessage.IsStun(new ReadOnlySpan<byte>(buffer, offset, count)))
            {
                var message = StunMessage.Parse(buffer, offset, count);
                if (message == null)
                    return;
                if (message.Class == StunMessageClass.Request && message.Method == StunMethod.Binding)
                    OnBindingRequest(local, connection, message, from);
                else if (message.Class == StunMessageClass.SuccessResponse || message.Class == StunMessageClass.ErrorResponse)
                    OnResponse(local, connection, message, from);
                // an indication - a keepalive (RFC 8445 11) - asks for nothing
                return;
            }

            // DTLS, RTP, RTCP: of a peer whose candidate is known, or whose checks were; or of the pair a restart left selected
            if (IsKnown(local, connection, from))
                DataReceived?.Invoke(this, (connection?.Args ?? local.Args).Set(buffer, offset, count, from));
        }

        private bool IsKnown(LocalBase local, IceTcpConnection connection, IPEndPoint from)
        {
            lock (_sync)
            {
                var selected = SelectedPair;
                if (connection != null)
                {
                    if (selected?.Connection == connection)
                        return true;
                    foreach (var pair in _pairs)
                    {
                        if (pair.Connection == connection)
                            return true;
                    }
                    return false;
                }
                if (selected != null && selected.Connection == null && selected.Base == local && selected.RemoteEndPoint.Equals(from))
                    return true;
                foreach (var pair in _pairs)
                {
                    if (pair.Base == local && pair.Connection == null && pair.RemoteEndPoint.Equals(from))
                        return true;
                }
                return false;
            }
        }

        // an IPv4 address mapped to IPv6, of a dual socket, as the IPv4 address it is
        internal static IPEndPoint Normalize(IPEndPoint endPoint)
            => endPoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port) : endPoint;

        private void OnBindingRequest(LocalBase local, IceTcpConnection connection, StunMessage request, IPEndPoint from)
        {
            // RFC 8445 7.3: of the username of our ufrag first, signed with our password
            if (!request.HasFingerprint || !request.VerifyFingerprint())
                return;
            string username = request.Username;
            string localUfrag, localPassword;
            lock (_sync)
            {
                localUfrag = LocalUfrag;
                localPassword = LocalPassword;
            }
            byte[] localKey = StunMessage.ShortTermKey(localPassword);
            if (username == null || !username.StartsWith(localUfrag + ":", StringComparison.Ordinal))
            {
                SendError(local, connection, request, from, StunErrorCode.BadRequest, "Bad Request", null);
                return;
            }
            if (!request.VerifyIntegrity(localKey))
            {
                SendError(local, connection, request, from, StunErrorCode.Unauthorized, "Unauthorized", null);
                return;
            }

            // of an attribute it is not to be understood without, a 420 that lists them (RFC 8489 6.3.1.1)
            var unknown = request.GetUnknownComprehensionRequired();
            if (unknown.Count > 0)
            {
                var error = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse, request.TransactionId)
                    .AddError(StunErrorCode.UnknownAttribute, "Unknown Attribute")
                    .AddUnknownAttributes(unknown);
                SendStun(new Outgoing(local, connection, error.ToBytes(localKey), from));
                return;
            }

            IceCandidatePair selectedNow = null;
            bool roleChanged = false;
            lock (_sync)
            {
                if (_closed)
                    return;

                // RFC 8445 7.3.1.1: of both controlling, or both controlled, the greater tie-breaker controls; a lite agent
                // never does
                ulong? controlling = request.IceControlling;
                ulong? controlled = request.IceControlled;
                if (Role == IceRole.Controlling && controlling != null)
                {
                    if (TieBreaker >= controlling.Value)
                    {
                        SendError(local, connection, request, from, StunErrorCode.RoleConflict, "Role Conflict", localKey);
                        return;
                    }
                    SwitchRole(IceRole.Controlled);
                    roleChanged = true;
                }
                else if (Role == IceRole.Controlled && controlled != null)
                {
                    if (TieBreaker >= controlled.Value && !IsLite)
                    {
                        SwitchRole(IceRole.Controlling);
                        roleChanged = true;
                    }
                    else
                    {
                        SendError(local, connection, request, from, StunErrorCode.RoleConflict, "Role Conflict", localKey);
                        return;
                    }
                }

                // a candidate the peer did not signal - a peer reflexive one (RFC 8445 7.3.1.3); over TCP or TLS, the active
                // one of the connection it made, of the transport of the candidate it connected to
                bool tcp = connection != null;
                string transport = tcp ? (local.Candidate.IsTls ? "tls" : "tcp") : "udp";
                var remote = _remoteCandidates.FirstOrDefault(c => (tcp ? IceCandidate.SameTransport(c, local.Candidate) : c.IsUdp) && Equals(c.EndPoint, from));
                if (remote == null)
                {
                    remote = new IceCandidate
                    {
                        Foundation = "p" + (_remoteCandidates.Count + 1).ToString(CultureInfo.InvariantCulture),
                        Component = IceCandidate.RtpComponent,
                        Transport = transport,
                        Priority = request.Priority ?? IceCandidate.ComputePriority(IceCandidateType.PeerReflexive, 0, IceCandidate.RtpComponent, transport),
                        Address = from.Address.ToString(),
                        Port = from.Port,
                        Type = IceCandidateType.PeerReflexive,
                    };
                    if (tcp)
                        remote.TcpType = IceCandidate.TcpActive;
                    _remoteCandidates.Add(remote);
                    Trace($"Peer reflexive {remote}");
                }

                var pair = tcp
                    ? _pairs.FirstOrDefault(p => p.Connection == connection)
                    : _pairs.FirstOrDefault(p => p.Base == local && p.Connection == null && p.RemoteEndPoint.Equals(from));
                if (pair == null)
                {
                    pair = new IceCandidatePair(local, remote, from) { Connection = connection };
                    pair.Priority = PairPriority(pair);
                    _pairs.Add(pair);
                }
                pair.LastConsent = DateTime.UtcNow;

                // a triggered check (RFC 8445 7.3.1.4), of a pair not known to work
                if (!IsLite && _started && pair.State != IceCandidatePairState.Succeeded && pair.State != IceCandidatePairState.InProgress && !_triggered.Contains(pair))
                {
                    if (pair.State == IceCandidatePairState.Failed || pair.State == IceCandidatePairState.Frozen)
                        pair.State = IceCandidatePairState.Waiting;
                    _triggered.AddLast(pair);
                }

                // nominated by the controlling agent (RFC 8445 7.3.1.5): selected once a check of ours on it succeeds too; of a
                // lite agent, which checks nothing, as it is
                if (Role == IceRole.Controlled && request.UseCandidate)
                {
                    if (!pair.Nominated)
                        Trace($"Nominated by the peer: {pair}");
                    pair.Nominated = true;
                    if (IsLite)
                    {
                        pair.State = IceCandidatePairState.Succeeded;
                        selectedNow = Select(pair);
                    }
                    else if (pair.LastSucceeded > DateTime.MinValue)
                    {
                        selectedNow = Select(pair);
                    }
                }
            }

            var response = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, request.TransactionId);
            response.AddXorAddress(from);
            if (_options.Software != null)
                response.AddString(StunAttributeType.Software, _options.Software);
            SendStun(new Outgoing(local, connection, response.ToBytes(localKey), from));

            if (roleChanged)
                Trace($"Role switched to {Role}");
            AfterSelect(selectedNow);
        }

        private void SendError(LocalBase local, IceTcpConnection connection, StunMessage request, IPEndPoint to, int code, string reason, byte[] key)
        {
            var response = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse, request.TransactionId);
            response.AddError(code, reason);
            SendStun(new Outgoing(local, connection, response.ToBytes(key), to));
        }

        // under the lock
        private void SwitchRole(IceRole role)
        {
            Role = role;
            foreach (var pair in _pairs)
                pair.Priority = PairPriority(pair);
        }

        private void OnResponse(LocalBase local, IceTcpConnection connection, StunMessage response, IPEndPoint from)
        {
            var key = Key(response.TransactionId);
            TaskCompletionSource<IPEndPoint> gathering;
            lock (_sync)
                _gatherings.TryGetValue(key, out gathering);
            if (gathering != null)
            {
                if (response.HasFingerprint && !response.VerifyFingerprint())
                    return;
                // of an attribute it is not to be understood without, the transaction failed (RFC 8489 6.3.3)
                // of a server of classic STUN, its retired attributes taken as known (RFC 8489 18.3.1)
                gathering.TrySetResult(response.GetUnknownComprehensionRequired(t => StunAttributeType.IsKnown(t) || StunAttributeType.IsRetired(t)).Count > 0
                    ? null
                    : StunClient.GetMappedAddress(response));
                return;
            }

            IceCandidatePair selectedNow = null;
            lock (_sync)
            {
                if (_closed || !_transactions.TryGetValue(key, out IceCandidatePair pair))
                    return;
                // signed with the peer's password, of the peer the request went to (RFC 8445 7.2.5.2.1: symmetric)
                if (!response.HasFingerprint || !response.VerifyFingerprint() || !response.VerifyIntegrity(_remoteKey))
                    return;
                _transactions.Remove(key);
                bool symmetric = pair.Base == local && (connection != null ? pair.Connection == connection : pair.RemoteEndPoint.Equals(from));
                if (!symmetric)
                {
                    pair.State = IceCandidatePairState.Failed;
                    return;
                }

                // of an attribute it is not to be understood without, the check failed as of an error (RFC 8489 6.3.3)
                if (response.Class == StunMessageClass.ErrorResponse || response.GetUnknownComprehensionRequired().Count > 0)
                {
                    var error = response.Error;
                    if (error?.Code == StunErrorCode.RoleConflict)
                    {
                        // RFC 8445 7.2.5.1: the role the request was not of, and the check again
                        SwitchRole(Role == IceRole.Controlling ? IceRole.Controlled : IceRole.Controlling);
                        pair.State = IceCandidatePairState.Waiting;
                        _triggered.AddFirst(pair);
                        Trace($"Role conflict: switched to {Role}");
                    }
                    else
                    {
                        pair.State = pair.LastSucceeded > DateTime.MinValue ? IceCandidatePairState.Succeeded : IceCandidatePairState.Failed;
                        Trace($"Check failed with {error?.Code} {error?.Reason}: {pair}");
                    }
                    return;
                }

                pair.State = IceCandidatePairState.Succeeded;
                pair.LastConsent = pair.LastSucceeded = DateTime.UtcNow;
                Trace($"Check succeeded: {pair}");

                // the pairs of its foundation unfrozen (RFC 8445 7.2.5.3.3)
                foreach (var other in _pairs)
                {
                    if (other.State == IceCandidatePairState.Frozen && other.Foundation == pair.Foundation)
                        other.State = IceCandidatePairState.Waiting;
                }

                if (Role == IceRole.Controlling)
                {
                    if (pair.Nominating)
                    {
                        pair.Nominated = true;
                        selectedNow = Select(pair);
                    }
                    else if (!_pairs.Any(p => p.Nominated || p.Nominating))
                    {
                        // the first pair that works, nominated by a check of USE-CANDIDATE
                        pair.Nominating = true;
                        _triggered.AddFirst(pair);
                    }
                }
                else if (pair.Nominated || SelectedPair == null || !SelectedPair.Nominated && pair.Priority > SelectedPair.Priority)
                {
                    selectedNow = Select(pair);
                }
            }
            AfterSelect(selectedNow);
        }

        // under the lock: the pair selected, if it is another; what was selected, to be told of
        private IceCandidatePair Select(IceCandidatePair pair)
        {
            if (SelectedPair == pair)
                return null;
            if (SelectedPair != null && SelectedPair.Nominated && !pair.Nominated)
                return null;
            SelectedPair = pair;
            _lastConsentCheck = DateTime.UtcNow;
            return pair;
        }

        private void AfterSelect(IceCandidatePair selected)
        {
            if (selected == null)
                return;
            Trace($"Selected {selected}");
            // of a relayed pair, a channel of its peer: ChannelData of 4 bytes rather than indications of 36 (RFC 8656 12)
            if (selected.Base.Turn != null)
                _ = BindChannelAsync(selected.Base.Turn, selected.RemoteEndPoint);
            SelectedPairChanged?.Invoke(this, selected);
            if (State == IceConnectionState.Checking || State == IceConnectionState.New || State == IceConnectionState.Disconnected)
                SetState(IceConnectionState.Connected);
        }

        #endregion // Receiving

        #region Sending

        private void SendStun(Outgoing outgoing)
        {
            if (outgoing.Connection != null)
            {
                outgoing.Connection.Send(outgoing.Bytes, 0, outgoing.Bytes.Length);
                return;
            }
            if (outgoing.Base.Turn != null)
            {
                _ = SendRelayedAsync(outgoing.Base.Turn, outgoing.To, outgoing.Bytes, 0, outgoing.Bytes.Length);
                return;
            }
            if (outgoing.Base.Socket == null)
                return;
            try
            {
                outgoing.Base.Sender.SendTo(outgoing.Bytes, 0, outgoing.Bytes.Length, outgoing.To);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException ex)
            {
                Trace($"Send to {outgoing.To} failed: {ex.SocketErrorCode}");
            }
        }

        /// <summary>Sends a datagram on the selected pair - of TCP, framed (RFC 4571). False of none selected yet, or of one that failed.</summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            var pair = SelectedPair;
            if (pair == null || _closed || State == IceConnectionState.Failed)
                return false;
            if (pair.IsStream)
                return pair.Connection?.Send(buffer, offset, count) == true;
            if (pair.Base.Turn != null)
            {
                var turn = pair.Base.Turn;
                try
                {
                    // of a channel bound, at once; else - a permission to install first - of a copy of a pool, the buffer the
                    // caller's again at once
                    if (turn.TrySend(pair.RemoteEndPoint, buffer, offset, count))
                        return turn.IsAllocated;
                }
                catch (Exception ex) when (ex is ObjectDisposedException || ex is SocketException || ex is System.IO.IOException || ex is InvalidOperationException)
                {
                    Trace($"Relayed send to {pair.RemoteEndPoint} failed: {ex.Message}");
                    return false;
                }
                byte[] copy = ArrayPool<byte>.Shared.Rent(count);
                Buffer.BlockCopy(buffer, offset, copy, 0, count);
                _ = SendRelayedAsync(turn, pair.RemoteEndPoint, copy, 0, count, true);
                return turn.IsAllocated;
            }
            try
            {
                pair.Base.Sender.SendTo(buffer, offset, count, pair.RemoteEndPoint);
                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
            catch (SocketException ex)
            {
                Trace($"Send to {pair.RemoteEndPoint} failed: {ex.SocketErrorCode}");
                return false;
            }
        }

        // through the relay: of a permission of the peer's address installed first, of none yet; a buffer of the pool's, back to it
        private async Task SendRelayedAsync(TurnClient turn, IPEndPoint to, byte[] buffer, int offset, int count, bool pooled = false)
        {
            try
            {
                await turn.SendAsync(to, buffer, offset, count).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TurnException || ex is StunException || ex is ObjectDisposedException || ex is SocketException || ex is System.IO.IOException)
            {
                Trace($"Relayed send to {to} failed: {ex.Message}");
            }
            finally
            {
                if (pooled)
                    ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        #endregion // Sending

        private async Task BindChannelAsync(TurnClient turn, IPEndPoint peer)
        {
            try
            {
                await turn.BindChannelAsync(peer).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TurnException || ex is StunException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                Trace($"No channel of {peer}: {ex.Message}");
            }
        }

        private void SetState(IceConnectionState state)
        {
            lock (_sync)
            {
                if (State == state || State == IceConnectionState.Closed)
                    return;
                State = state;
            }
            Trace($"State {state}");
            StateChanged?.Invoke(this, state);
        }

        public void Close()
        {
            List<IceTcpConnection> connections;
            List<TurnClient> turns;
            lock (_sync)
            {
                if (_closed)
                    return;
                _closed = true;
                connections = _connections.ToList();
                _connections.Clear();
                turns = _turns.ToList();
                _turns.Clear();
            }
            _timer?.Dispose();
            foreach (var local in _bases)
            {
                local.Socket?.Dispose();
                local.Listener?.Stop();
            }
            foreach (var connection in connections)
                connection.Dispose();
            _tlsServer?.Dispose();
            // the allocations deleted, a second each at most
            foreach (var turn in turns)
                turn.Dispose();
            _mdns?.Dispose();
            foreach (var gathering in _gatherings.Values.ToList())
                gathering.TrySetResult(null);
            SetState(IceConnectionState.Closed);
        }

        public void Dispose() => Close();
    }
}
