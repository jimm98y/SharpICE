// SharpICE
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
    /// Its buffer is the agent's own again once the event returns: what is kept of it is to be copied.
    /// </summary>
    public sealed class IceDataReceivedEventArgs : EventArgs
    {
        public IceDataReceivedEventArgs(byte[] buffer, int offset, int count, IPEndPoint remoteEndPoint)
        {
            Buffer = buffer;
            Offset = offset;
            Count = count;
            RemoteEndPoint = remoteEndPoint;
        }

        public byte[] Buffer { get; }
        public int Offset { get; }
        public int Count { get; }
        public IPEndPoint RemoteEndPoint { get; }
    }

    /// <summary>
    /// An ICE agent (RFC 8445) of one component - RTP and RTCP multiplexed on it (RFC 5761), all media bundled (RFC 9143), as
    /// WebRTC has it. It gathers host candidates of the local addresses, a socket each, and server reflexive ones of STUN servers;
    /// checks the pairs of them and the peer's candidates; and once one is selected, sends and receives the data of the layers
    /// above on it - every datagram that is not STUN.
    /// </summary>
    /// <remarks>
    /// Checks are paced one every Ta, triggered ones first; a check is retransmitted as RFC 8489 6.2.1 says, and its pair fails
    /// once it is not answered. Controlling, it nominates the first pair that succeeds (RFC 8445 8.1.1); controlled, it selects
    /// the pair the peer nominates, and until then the best that succeeded, so that data can flow as soon as a pair does. The
    /// consent to send on the selected pair is checked every few seconds (RFC 7675).
    /// </remarks>
    public sealed class IceAgent : IDisposable
    {
        // ICE's ufrag of at least 24 bits of randomness and pwd of 128 (RFC 8445 5.3), of the ice-char of RFC 8839
        private const string IceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private const int MaxDatagram = 65536;

        internal sealed class LocalBase
        {
            public Socket Socket;
            public IPEndPoint EndPoint;
            public IceCandidate Candidate;
            public byte[] Buffer = new byte[MaxDatagram];
        }

        private readonly object _sync = new object();
        private readonly IceAgentOptions _options;
        private readonly List<LocalBase> _bases = new List<LocalBase>();
        private readonly List<IceCandidate> _localCandidates = new List<IceCandidate>();
        private readonly List<IceCandidate> _remoteCandidates = new List<IceCandidate>();
        private readonly List<IceCandidatePair> _pairs = new List<IceCandidatePair>();
        private readonly LinkedList<IceCandidatePair> _triggered = new LinkedList<IceCandidatePair>();
        private readonly Dictionary<string, IceCandidatePair> _transactions = new Dictionary<string, IceCandidatePair>();

        // the requests of gathering, each the base it was sent from and what is waiting for its answer
        private readonly Dictionary<string, TaskCompletionSource<IPEndPoint>> _gatherings = new Dictionary<string, TaskCompletionSource<IPEndPoint>>();

        private Timer _timer;
        private int _ticking;
        private bool _started;
        private bool _closed;
        private DateTime _lastConsentCheck = DateTime.MinValue;
        private DateTime _lastRemoteCandidate = DateTime.UtcNow;
        private byte[] _remoteKey;

        public IceAgent(IceAgentOptions options = null)
        {
            _options = options ?? new IceAgentOptions();
            Role = _options.Role;
            LocalUfrag = RandomIceString(8);
            LocalPassword = RandomIceString(24);
            byte[] tieBreaker = new byte[8];
            using (var random = RandomNumberGenerator.Create())
                random.GetBytes(tieBreaker);
            TieBreaker = BitConverter.ToUInt64(tieBreaker, 0);
        }

        public IceRole Role { get; private set; }

        /// <summary>The tie-breaker a role conflict is resolved by (RFC 8445 7.3.1.1).</summary>
        public ulong TieBreaker { get; }

        public string LocalUfrag { get; }

        public string LocalPassword { get; }

        public string RemoteUfrag { get; private set; }

        public string RemotePassword { get; private set; }

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

        private void Trace(string message) => _options.Trace?.Invoke(message);

        #region Gathering

        /// <summary>The local addresses to gather candidates of: of the interfaces that are up, as the options choose.</summary>
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
                        if (!_options.IncludeIPv6 || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
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
                    else
                        addresses.Add(address);
                }
            }
            if (_options.IncludeLoopback || addresses.Count == 0)
                addresses.AddRange(loopback);
            return addresses;
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
        /// Gathers the candidates (RFC 8445 5.1.1): a host candidate of each local address, of a socket bound to it, then a server
        /// reflexive one of each STUN server that answers, of each IPv4 socket. Each is told of as it is gathered too, to be
        /// trickled. Once only: the candidates of a second call are those of the first.
        /// </summary>
        public async Task<IReadOnlyList<IceCandidate>> GatherCandidatesAsync(CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (_closed)
                    throw new ObjectDisposedException(nameof(IceAgent));
                if (_bases.Count > 0)
                    return _localCandidates.ToList();
            }

            var addresses = GetLocalAddresses();
            var gathered = new List<IceCandidate>();
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
                    Address = endPoint.Address.ToString(),
                    Port = endPoint.Port,
                    Type = IceCandidateType.Host,
                };
                var local = new LocalBase { Socket = socket, EndPoint = endPoint, Candidate = candidate };
                lock (_sync)
                {
                    _bases.Add(local);
                    _localCandidates.Add(candidate);
                    foreach (var remote in _remoteCandidates)
                        AddPair(local, remote);
                }
                gathered.Add(candidate);
                Trace($"Gathered {candidate}");
                StartReceiving(local);
                CandidateGathered?.Invoke(this, candidate);
            }

            await GatherServerReflexiveAsync(gathered, cancellationToken).ConfigureAwait(false);
            return gathered;
        }

        private async Task GatherServerReflexiveAsync(List<IceCandidate> gathered, CancellationToken cancellationToken)
        {
            if (_options.StunServers.Count == 0)
                return;

            var requests = new List<Task<(LocalBase Base, IPEndPoint Mapped)>>();
            foreach (string server in _options.StunServers)
            {
                foreach (var local in _bases.Where(b => b.EndPoint.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(b.EndPoint.Address)))
                    requests.Add(RequestMappedAsync(local, server, cancellationToken));
            }

            var results = await Task.WhenAll(requests).ConfigureAwait(false);
            int index = 0;
            foreach (var (local, mapped) in results)
            {
                if (mapped == null)
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
                    Priority = IceCandidate.ComputePriority(IceCandidateType.ServerReflexive, 65535 - _bases.IndexOf(local), IceCandidate.RtpComponent),
                    Address = mapped.Address.ToString(),
                    Port = mapped.Port,
                    Type = IceCandidateType.ServerReflexive,
                    RelatedAddress = local.EndPoint.Address.ToString(),
                    RelatedPort = local.EndPoint.Port,
                };
                lock (_sync)
                    _localCandidates.Add(candidate);
                gathered.Add(candidate);
                Trace($"Gathered {candidate}");
                CandidateGathered?.Invoke(this, candidate);
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
            string key = Key(request.TransactionId);
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

        /// <summary>The peer's ice-ufrag and ice-pwd: of its session description.</summary>
        public void SetRemoteCredentials(string ufrag, string password)
        {
            lock (_sync)
            {
                RemoteUfrag = ufrag ?? throw new ArgumentNullException(nameof(ufrag));
                RemotePassword = password ?? throw new ArgumentNullException(nameof(password));
                _remoteKey = StunMessage.ShortTermKey(password);
            }
        }

        /// <summary>
        /// A candidate of the peer's - of its session description, or trickled - of component 1 and UDP; one of a name is
        /// resolved, but not one of mDNS (".local"), which is left out. False of one that is not used.
        /// </summary>
        public bool AddRemoteCandidate(IceCandidate candidate)
        {
            if (candidate == null || !candidate.IsUdp || candidate.Component != IceCandidate.RtpComponent)
                return false;

            var endPoint = candidate.EndPoint;
            if (endPoint == null)
            {
                if (candidate.Address == null || candidate.Address.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                    return false;
                try
                {
                    var address = Dns.GetHostAddresses(candidate.Address).FirstOrDefault();
                    if (address == null)
                        return false;
                    candidate.Address = address.ToString();
                    endPoint = new IPEndPoint(address, candidate.Port);
                }
                catch (SocketException)
                {
                    return false;
                }
            }

            lock (_sync)
            {
                if (_closed || _remoteCandidates.Any(c => Equals(c.EndPoint, endPoint)))
                    return false;
                _remoteCandidates.Add(candidate);
                _lastRemoteCandidate = DateTime.UtcNow;
                foreach (var local in _bases)
                    AddPair(local, candidate);
            }
            Trace($"Remote {candidate}");
            return true;
        }

        public bool AddRemoteCandidate(string candidate) => AddRemoteCandidate(IceCandidate.Parse(candidate));

        // under the lock
        private IceCandidatePair AddPair(LocalBase local, IceCandidate remote)
        {
            var endPoint = remote.EndPoint;
            if (endPoint == null || endPoint.AddressFamily != local.EndPoint.AddressFamily)
                return null;
            // a loopback address reaches only one of its own, and one of a network only one of a network
            if (IPAddress.IsLoopback(endPoint.Address) != IPAddress.IsLoopback(local.EndPoint.Address))
                return null;

            var existing = _pairs.FirstOrDefault(p => p.Base == local && p.RemoteEndPoint.Equals(endPoint));
            if (existing != null)
                return existing;

            var pair = new IceCandidatePair(local, remote, endPoint);
            pair.Priority = PairPriority(pair);
            _pairs.Add(pair);
            return pair;
        }

        private ulong PairPriority(IceCandidatePair pair) => Role == IceRole.Controlling
            ? IceCandidatePair.ComputePriority(pair.Local.Priority, pair.Remote.Priority)
            : IceCandidatePair.ComputePriority(pair.Remote.Priority, pair.Local.Priority);

        #endregion // Remote

        #region Checks

        /// <summary>Begins the checks: of the pairs there are, and of those of candidates added after.</summary>
        public void Start()
        {
            lock (_sync)
            {
                if (_closed)
                    throw new ObjectDisposedException(nameof(IceAgent));
                if (_started)
                    return;
                if (RemoteUfrag == null)
                    throw new InvalidOperationException("The peer's credentials are not known: see SetRemoteCredentials.");
                _started = true;
                _lastRemoteCandidate = DateTime.UtcNow;
            }
            SetState(IceConnectionState.Checking);
            _timer = new Timer(_ => Tick(), null, TimeSpan.Zero, _options.CheckInterval);
        }

        private void Tick()
        {
            if (Interlocked.Exchange(ref _ticking, 1) == 1)
                return;
            try
            {
                var sends = new List<(LocalBase Base, byte[] Bytes, IPEndPoint To)>();
                IceConnectionState? newState = null;
                lock (_sync)
                {
                    if (_closed)
                        return;
                    DateTime now = DateTime.UtcNow;

                    // the checks in flight, retransmitted, or given up
                    foreach (var pair in _pairs)
                    {
                        if (pair.State != IceCandidatePairState.InProgress || now < pair.NextTransmission)
                            continue;
                        if (pair.Transmissions >= _options.MaxTransmissions)
                        {
                            _transactions.Remove(Key(pair.TransactionId));
                            pair.State = pair.LastSucceeded > DateTime.MinValue ? IceCandidatePairState.Succeeded : IceCandidatePairState.Failed;
                            Trace($"Check timed out: {pair}");
                            continue;
                        }
                        pair.Transmissions++;
                        pair.Timeout = TimeSpan.FromTicks(pair.Timeout.Ticks * 2);
                        pair.NextTransmission = now + pair.Timeout;
                        sends.Add((pair.Base, pair.Request, pair.RemoteEndPoint));
                    }

                    // one new check every Ta: a triggered one first, else the waiting pair of the highest priority
                    IceCandidatePair next = null;
                    while (_triggered.Count > 0 && next == null)
                    {
                        var triggered = _triggered.First.Value;
                        _triggered.RemoveFirst();
                        if (triggered.State != IceCandidatePairState.InProgress)
                            next = triggered;
                    }
                    if (next == null)
                    {
                        next = _pairs.Where(p => p.State == IceCandidatePairState.Waiting || p.State == IceCandidatePairState.Frozen)
                            .OrderByDescending(p => p.Priority).FirstOrDefault();
                    }
                    if (next != null)
                        sends.Add((next.Base, BeginCheck(next, now), next.RemoteEndPoint));

                    // the consent of the selected pair
                    var selected = SelectedPair;
                    if (selected != null)
                    {
                        if (now - _lastConsentCheck >= _options.ConsentInterval && selected.State != IceCandidatePairState.InProgress)
                        {
                            _lastConsentCheck = now;
                            sends.Add((selected.Base, BeginCheck(selected, now), selected.RemoteEndPoint));
                        }

                        TimeSpan silent = now - selected.LastConsent;
                        if (silent > _options.ConsentTimeout)
                            newState = IceConnectionState.Failed;
                        else if (silent > _options.DisconnectedTimeout)
                            newState = IceConnectionState.Disconnected;
                        else if (State == IceConnectionState.Disconnected)
                            newState = IceConnectionState.Connected;
                    }
                    else if (_pairs.Count > 0 && _pairs.All(p => p.State == IceCandidatePairState.Failed)
                        && now - _lastRemoteCandidate > TimeSpan.FromSeconds(5))
                    {
                        newState = IceConnectionState.Failed;
                    }
                }

                foreach (var (local, bytes, to) in sends)
                    Send(local, bytes, to);
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

        // under the lock: a check of the pair (RFC 8445 7.2.4), its request kept for its retransmissions
        private byte[] BeginCheck(IceCandidatePair pair, DateTime now)
        {
            if (pair.TransactionId != null)
                _transactions.Remove(Key(pair.TransactionId));

            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request);
            request.AddString(StunAttributeType.Username, RemoteUfrag + ":" + LocalUfrag);
            request.AddUInt32(StunAttributeType.Priority, IceCandidate.ComputePriority(IceCandidateType.PeerReflexive, 65535 - _bases.IndexOf(pair.Base), IceCandidate.RtpComponent));
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
            pair.NextTransmission = now + pair.Timeout;
            // of a pair that worked too - its consent, or its nomination - which goes back to it if no answer comes
            pair.State = IceCandidatePairState.InProgress;
            _transactions[Key(request.TransactionId)] = pair;
            return pair.Request;
        }

        private static string Key(byte[] transactionId) => Convert.ToBase64String(transactionId);

        #endregion // Checks

        #region Receiving

        private void StartReceiving(LocalBase local)
        {
            Task.Run(async () =>
            {
                var any = new IPEndPoint(local.EndPoint.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                while (!_closed)
                {
                    SocketReceiveFromResult result;
                    try
                    {
                        result = await local.Socket.ReceiveFromAsync(new ArraySegment<byte>(local.Buffer), SocketFlags.None, any).ConfigureAwait(false);
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
                        OnDatagram(local, local.Buffer, result.ReceivedBytes, (IPEndPoint)result.RemoteEndPoint);
                    }
                    catch (Exception ex)
                    {
                        Trace($"Datagram from {result.RemoteEndPoint} failed: {ex}");
                    }
                }
            });
        }

        private void OnDatagram(LocalBase local, byte[] buffer, int count, IPEndPoint from)
        {
            from = Normalize(from);
            if (StunMessage.IsStun(new ReadOnlySpan<byte>(buffer, 0, count)))
            {
                var message = StunMessage.Parse(buffer, 0, count);
                if (message == null)
                    return;
                if (message.Class == StunMessageClass.Request && message.Method == StunMethod.Binding)
                    OnBindingRequest(local, message, from);
                else if (message.Class == StunMessageClass.SuccessResponse || message.Class == StunMessageClass.ErrorResponse)
                    OnResponse(local, message, from);
                // an indication - a keepalive (RFC 8445 11) - asks for nothing
                return;
            }

            // DTLS, RTP, RTCP: of a peer whose candidate is known, or whose checks were
            bool known;
            lock (_sync)
                known = _pairs.Any(p => p.Base == local && p.RemoteEndPoint.Equals(from));
            if (known)
                DataReceived?.Invoke(this, new IceDataReceivedEventArgs(buffer, 0, count, from));
        }

        // an IPv4 address mapped to IPv6, of a dual socket, as the IPv4 address it is
        private static IPEndPoint Normalize(IPEndPoint endPoint)
            => endPoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port) : endPoint;

        private void OnBindingRequest(LocalBase local, StunMessage request, IPEndPoint from)
        {
            // RFC 8445 7.3: of the username of our ufrag first, signed with our password
            if (!request.HasFingerprint || !request.VerifyFingerprint())
                return;
            string username = request.Username;
            if (username == null || !username.StartsWith(LocalUfrag + ":", StringComparison.Ordinal))
            {
                SendError(local, request, from, StunErrorCode.BadRequest, "Bad Request", false);
                return;
            }
            if (!request.VerifyIntegrity(StunMessage.ShortTermKey(LocalPassword)))
            {
                SendError(local, request, from, StunErrorCode.Unauthorized, "Unauthorized", false);
                return;
            }

            IceCandidatePair selectedNow = null;
            bool roleChanged = false;
            lock (_sync)
            {
                if (_closed)
                    return;

                // RFC 8445 7.3.1.1: of both controlling, or both controlled, the greater tie-breaker controls
                ulong? controlling = request.IceControlling;
                ulong? controlled = request.IceControlled;
                if (Role == IceRole.Controlling && controlling != null)
                {
                    if (TieBreaker >= controlling.Value)
                    {
                        SendError(local, request, from, StunErrorCode.RoleConflict, "Role Conflict", true);
                        return;
                    }
                    SwitchRole(IceRole.Controlled);
                    roleChanged = true;
                }
                else if (Role == IceRole.Controlled && controlled != null)
                {
                    if (TieBreaker >= controlled.Value)
                    {
                        SwitchRole(IceRole.Controlling);
                        roleChanged = true;
                    }
                    else
                    {
                        SendError(local, request, from, StunErrorCode.RoleConflict, "Role Conflict", true);
                        return;
                    }
                }

                // a candidate the peer did not signal - a peer reflexive one (RFC 8445 7.3.1.3)
                var remote = _remoteCandidates.FirstOrDefault(c => Equals(c.EndPoint, from));
                if (remote == null)
                {
                    remote = new IceCandidate
                    {
                        Foundation = "p" + (_remoteCandidates.Count + 1).ToString(CultureInfo.InvariantCulture),
                        Component = IceCandidate.RtpComponent,
                        Transport = "udp",
                        Priority = request.Priority ?? IceCandidate.ComputePriority(IceCandidateType.PeerReflexive, 0, IceCandidate.RtpComponent),
                        Address = from.Address.ToString(),
                        Port = from.Port,
                        Type = IceCandidateType.PeerReflexive,
                    };
                    _remoteCandidates.Add(remote);
                    Trace($"Peer reflexive {remote}");
                }

                var pair = _pairs.FirstOrDefault(p => p.Base == local && p.RemoteEndPoint.Equals(from));
                if (pair == null)
                {
                    pair = new IceCandidatePair(local, remote, from);
                    pair.Priority = PairPriority(pair);
                    _pairs.Add(pair);
                }
                pair.LastConsent = DateTime.UtcNow;

                // a triggered check (RFC 8445 7.3.1.4), of a pair not known to work
                if (_started && pair.State != IceCandidatePairState.Succeeded && pair.State != IceCandidatePairState.InProgress && !_triggered.Contains(pair))
                {
                    if (pair.State == IceCandidatePairState.Failed)
                        pair.State = IceCandidatePairState.Waiting;
                    _triggered.AddLast(pair);
                }

                // nominated by the controlling agent (RFC 8445 7.3.1.5): selected once a check of ours on it succeeds too
                if (Role == IceRole.Controlled && request.UseCandidate)
                {
                    if (!pair.Nominated)
                        Trace($"Nominated by the peer: {pair}");
                    pair.Nominated = true;
                    if (pair.LastSucceeded > DateTime.MinValue)
                        selectedNow = Select(pair);
                }
            }

            var response = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, request.TransactionId);
            response.AddXorAddress(from);
            if (_options.Software != null)
                response.AddString(StunAttributeType.Software, _options.Software);
            Send(local, response.ToBytes(StunMessage.ShortTermKey(LocalPassword)), from);

            if (roleChanged)
                Trace($"Role switched to {Role}");
            AfterSelect(selectedNow);
        }

        private void SendError(LocalBase local, StunMessage request, IPEndPoint to, int code, string reason, bool signed)
        {
            var response = new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse, request.TransactionId);
            response.AddError(code, reason);
            Send(local, response.ToBytes(signed ? StunMessage.ShortTermKey(LocalPassword) : null), to);
        }

        // under the lock
        private void SwitchRole(IceRole role)
        {
            Role = role;
            foreach (var pair in _pairs)
                pair.Priority = PairPriority(pair);
        }

        private void OnResponse(LocalBase local, StunMessage response, IPEndPoint from)
        {
            string key = Key(response.TransactionId);
            TaskCompletionSource<IPEndPoint> gathering;
            lock (_sync)
                _gatherings.TryGetValue(key, out gathering);
            if (gathering != null)
            {
                if (response.HasFingerprint && !response.VerifyFingerprint())
                    return;
                gathering.TrySetResult(StunClient.GetMappedAddress(response));
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
                if (pair.Base != local || !pair.RemoteEndPoint.Equals(from))
                {
                    pair.State = IceCandidatePairState.Failed;
                    return;
                }

                if (response.Class == StunMessageClass.ErrorResponse)
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
            SelectedPairChanged?.Invoke(this, selected);
            if (State == IceConnectionState.Checking || State == IceConnectionState.New || State == IceConnectionState.Disconnected)
                SetState(IceConnectionState.Connected);
        }

        #endregion // Receiving

        #region Sending

        private void Send(LocalBase local, byte[] bytes, IPEndPoint to)
        {
            try
            {
                local.Socket.SendTo(bytes, 0, bytes.Length, SocketFlags.None, to);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException ex)
            {
                Trace($"Send to {to} failed: {ex.SocketErrorCode}");
            }
        }

        /// <summary>Sends a datagram on the selected pair. False of none selected yet, or of one that failed.</summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            var pair = SelectedPair;
            if (pair == null || _closed || State == IceConnectionState.Failed)
                return false;
            try
            {
                pair.Base.Socket.SendTo(buffer, offset, count, SocketFlags.None, pair.RemoteEndPoint);
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

        #endregion // Sending

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
            lock (_sync)
            {
                if (_closed)
                    return;
                _closed = true;
            }
            _timer?.Dispose();
            foreach (var local in _bases)
                local.Socket.Dispose();
            foreach (var gathering in _gatherings.Values.ToList())
                gathering.TrySetResult(null);
            SetState(IceConnectionState.Closed);
        }

        public void Dispose() => Close();
    }
}
