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

#if NET8_0_OR_GREATER
using ReadTask = System.Threading.Tasks.ValueTask<bool>;
#else
using ReadTask = System.Threading.Tasks.Task<bool>;
#endif
using SharpSTUN;
using SharpTURN;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE
{
    /// <summary>
    /// ICE over TCP (RFC 6544): of each local address, a passive candidate - a listener whose connections the peer's checks
    /// come over - and an active one, of port 9, which connects to the peer's passive ones; the checks and the data framed as
    /// RFC 4571 frames RTP, of a 16 bit length each. Simultaneous-open is not done.
    /// </summary>
    public sealed partial class IceAgent
    {
        private static readonly TimeSpan TcpConnectTimeout = TimeSpan.FromSeconds(5);

        // the discard port, which an active candidate says it is of (RFC 6544 4.5)
        private const int ActivePort = 9;

        // the connections to passive candidates being made - of a relay's ConnectionBind - of the
        // connections' limit too
        private int _pendingConnections;
        // the pending connections of each source address, counted with the established ones against MaxTcpConnectionsPerAddress
        private readonly Dictionary<IPAddress, int> _pendingFrom = new Dictionary<IPAddress, int>();

        // the clients of the TCP allocations of the relayed candidates of TCP: of the peers' permissions on them
        private readonly List<TurnClient> _tcpRelays = new List<TurnClient>();

        // relayed candidates of TCP (RFC 6544 5.1, of a TCP allocation of RFC 6062): the relayed address a passive candidate,
        // the peers' connections to it told of of ConnectionAttempts; and an active one, of port 9, which connects to the
        // peer's passive ones of Connect. Each connection of them framed as of any of TCP (RFC 4571).
        private void GatherTcpRelayed(TurnClient turn, int index, List<IceCandidate> gathered)
        {
            var relayed = turn.RelayedEndPoint;
            if (relayed == null)
                return;
            string foundation = "rt" + (index + 1).ToString(CultureInfo.InvariantCulture);
            // of mDNS candidates, no address of the host's
            string relatedAddress = _mdns != null || turn.MappedEndPoint == null ? NoAddress(relayed.AddressFamily) : turn.MappedEndPoint.Address.ToString();
            int relatedPort = _mdns != null || turn.MappedEndPoint == null ? 0 : turn.MappedEndPoint.Port;
            var passive = new IceCandidate
            {
                Foundation = foundation,
                Component = IceCandidate.RtpComponent,
                Transport = "tcp",
                Priority = IceCandidate.ComputePriority(IceCandidateType.Relayed, IceCandidate.TcpLocalPreference(IceCandidate.TcpPassive, 8191 - index), IceCandidate.RtpComponent, true),
                Address = relayed.Address.ToString(),
                Port = relayed.Port,
                Type = IceCandidateType.Relayed,
                RelatedAddress = relatedAddress,
                RelatedPort = relatedPort,
            };
            passive.TcpType = IceCandidate.TcpPassive;
            var active = new IceCandidate
            {
                Foundation = foundation,
                Component = IceCandidate.RtpComponent,
                Transport = "tcp",
                Priority = IceCandidate.ComputePriority(IceCandidateType.Relayed, IceCandidate.TcpLocalPreference(IceCandidate.TcpActive, 8191 - index), IceCandidate.RtpComponent, true),
                Address = relayed.Address.ToString(),
                Port = ActivePort,
                Type = IceCandidateType.Relayed,
                RelatedAddress = relatedAddress,
                RelatedPort = relatedPort,
            };
            active.TcpType = IceCandidate.TcpActive;

            var passiveBase = new LocalBase { TcpRelay = turn, EndPoint = relayed, Candidate = passive };
            turn.ConnectionAttempt += (s, e) => _ = AcceptRelayedAsync(passiveBase, e);
            List<IPAddress> known;
            lock (_sync)
            {
                _tcpRelays.Add(turn);
                known = _remoteCandidates.Select(c => c.EndPoint?.Address).Where(a => a != null).Distinct().ToList();
            }
            AddBase(passiveBase, gathered);
            AddBase(new LocalBase { TcpRelay = turn, EndPoint = new IPEndPoint(relayed.Address, ActivePort), Candidate = active }, gathered);
            // the peer's candidates told of before: their permissions now
            foreach (var address in known)
                PermitOnTcpRelays(address);
        }

        // a permission of the address on each relay of TCP of its family: of a peer's connection to it, of no other source,
        // let through (RFC 6062 5.3)
        private void PermitOnTcpRelays(IPAddress address)
        {
            List<TurnClient> relays;
            lock (_sync)
                relays = _tcpRelays.Where(r => r.RelayedEndPoint?.AddressFamily == address.AddressFamily).ToList();
            foreach (var relay in relays)
                _ = PermitAsync(relay, address);
        }

        private async Task PermitAsync(TurnClient relay, IPAddress address)
        {
            try
            {
                await relay.CreatePermissionAsync(address).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TurnException || ex is StunException || ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                Trace($"No permission of {address} on {relay.RelayedEndPoint}: {ex.Message}");
            }
        }

        // Under the lock: whether a source address has MaxTcpConnectionsPerAddress connections, established or pending, already.
        private bool IsFullFrom(IPAddress address)
        {
            if (_options.MaxTcpConnectionsPerAddress <= 0)
                return false;
            address = Unmapped(address);
            _pendingFrom.TryGetValue(address, out int count);
            foreach (var connection in _connections)
            {
                var remote = connection.RemoteEndPoint?.Address;
                if (remote != null && Unmapped(remote).Equals(address))
                    count++;
            }
            return count >= _options.MaxTcpConnectionsPerAddress;
        }

        private static IPAddress Unmapped(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

        private void AddPending(IPAddress address)
        {
            address = Unmapped(address);
            _pendingConnections++;
            _pendingFrom[address] = _pendingFrom.TryGetValue(address, out int count) ? count + 1 : 1;
        }

        private void RemovePending(IPAddress address)
        {
            address = Unmapped(address);
            _pendingConnections--;
            if (_pendingFrom.TryGetValue(address, out int count))
            {
                if (count <= 1)
                    _pendingFrom.Remove(address);
                else
                    _pendingFrom[address] = count - 1;
            }
        }

        // a peer's connection to the relayed address of a passive candidate of TCP: its data connection of the agent's, of a
        // ConnectionBind, as a connection to a passive candidate of the agent's own is
        private async Task AcceptRelayedAsync(LocalBase local, TurnConnectionAttemptEventArgs attempt)
        {
            lock (_sync)
            {
                if (_closed)
                    return;
                if (_connections.Count + _pendingConnections >= _options.MaxTcpConnections || IsFullFrom(attempt.Peer.Address))
                {
                    // left: the server closes it of no ConnectionBind in 30 seconds
                    Trace($"Connection from {attempt.Peer} to {local.EndPoint} refused: {_options.MaxTcpConnections} already, or {_options.MaxTcpConnectionsPerAddress} of its address");
                    return;
                }
                AddPending(attempt.Peer.Address);
            }
            IceTcpConnection connection = null;
            try
            {
                var relayed = await local.TcpRelay.AcceptPeerAsync(attempt).ConfigureAwait(false);
                connection = new IceTcpConnection(relayed.Stream, local.EndPoint, attempt.Peer, relayed);
            }
            catch (Exception ex) when (ex is TurnException || ex is StunException || ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                Trace($"Connection from {attempt.Peer} to {local.EndPoint} not taken: {ex.Message}");
            }
            lock (_sync)
            {
                RemovePending(attempt.Peer.Address);
                if (connection != null && !_closed)
                {
                    _connections.Add(connection);
                }
                else
                {
                    connection?.Dispose();
                    connection = null;
                }
            }
            if (connection != null)
                Accepted(local, connection);
        }

        // a pair of the agent's active relayed candidate of TCP: its connection to the peer's passive one of Connect
        private async Task<IceTcpConnection> ConnectRelayedAsync(IceCandidatePair pair)
        {
            var relay = pair.Base.TcpRelay;
            using (var timeout = new CancellationTokenSource(TcpConnectTimeout))
            {
                var relayed = await relay.ConnectPeerAsync(pair.RemoteEndPoint, timeout.Token).ConfigureAwait(false);
                // of the address the peer sees: the relayed one
                return new IceTcpConnection(relayed.Stream, relay.RelayedEndPoint ?? pair.Base.EndPoint, pair.RemoteEndPoint, relayed);
            }
        }

        private void GatherTcp(List<IPAddress> addresses, List<IceCandidate> gathered)
        {
            for (int i = 0; i < addresses.Count; i++)
            {
                var address = addresses[i];
                TcpListener listener;
                try
                {
                    listener = Listen(address);
                }
                catch (SocketException ex)
                {
                    Trace($"Could not listen on {address}: {ex.Message}");
                    continue;
                }

                // one foundation of the address: its passive and active candidates are of one base address, type and transport
                var endPoint = (IPEndPoint)listener.LocalEndpoint;
                string foundation = "t" + (i + 1).ToString(CultureInfo.InvariantCulture);
                var passive = new IceCandidate
                {
                    Foundation = foundation,
                    Component = IceCandidate.RtpComponent,
                    Transport = "tcp",
                    Priority = IceCandidate.ComputePriority(IceCandidateType.Host, IceCandidate.TcpLocalPreference(IceCandidate.TcpPassive, 8191 - i), IceCandidate.RtpComponent, true),
                    Address = HostAddress(endPoint.Address),
                    Port = endPoint.Port,
                    Type = IceCandidateType.Host,
                };
                passive.TcpType = IceCandidate.TcpPassive;
                var active = new IceCandidate
                {
                    Foundation = foundation,
                    Component = IceCandidate.RtpComponent,
                    Transport = "tcp",
                    Priority = IceCandidate.ComputePriority(IceCandidateType.Host, IceCandidate.TcpLocalPreference(IceCandidate.TcpActive, 8191 - i), IceCandidate.RtpComponent, true),
                    Address = HostAddress(endPoint.Address),
                    Port = ActivePort,
                    Type = IceCandidateType.Host,
                };
                active.TcpType = IceCandidate.TcpActive;

                var passiveBase = new LocalBase { Listener = listener, EndPoint = endPoint, Candidate = passive };
                AddBase(passiveBase, gathered);
                AddBase(new LocalBase { EndPoint = new IPEndPoint(address, ActivePort), Candidate = active }, gathered);
                _ = AcceptAsync(passiveBase);
            }
        }

        private TcpListener Listen(IPAddress address)
        {
            if (_options.PortMin > 0 && _options.PortMax >= _options.PortMin)
            {
                for (int port = _options.PortMin; port <= _options.PortMax; port++)
                {
                    var listener = new TcpListener(address, port);
                    try
                    {
                        listener.Start();
                        return listener;
                    }
                    catch (SocketException)
                    {
                    }
                }
                throw new SocketException((int)SocketError.AddressAlreadyInUse);
            }

            var any = new TcpListener(address, 0);
            any.Start();
            return any;
        }

        // the peer's connections to a passive candidate: its checks come over them, and make their pairs
        private async Task AcceptAsync(LocalBase local)
        {
            while (!_closed)
            {
                TcpClient client;
                try
                {
                    client = await local.Listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is ObjectDisposedException || ex is InvalidOperationException)
                {
                    return;
                }
                catch (SocketException)
                {
                    if (_closed)
                        return;
                    continue;
                }

                var connection = new IceTcpConnection(client);
                lock (_sync)
                {
                    if (_closed)
                    {
                        connection.Dispose();
                        return;
                    }
                    if (_connections.Count + _pendingConnections >= _options.MaxTcpConnections || IsFullFrom(connection.RemoteEndPoint.Address))
                    {
                        Trace($"Connection from {connection.RemoteEndPoint} refused: {_options.MaxTcpConnections} already, or {_options.MaxTcpConnectionsPerAddress} of its address");
                        connection.Dispose();
                        continue;
                    }
                    _connections.Add(connection);
                }
                Accepted(local, connection);
            }
        }

        private void Accepted(LocalBase local, IceTcpConnection connection)
        {
            Trace($"Connection from {connection.RemoteEndPoint} to {local.EndPoint}");
            StartReceiving(local, connection);
            _ = CloseUnpairedAsync(connection);
        }

        // A connection anyone may make. It is closed unless a pair of it is checked in time (an authenticated check from
        // the peer), and then unless a check of the agent's on it succeeds - a check replayed over a connection pairs it,
        // but only the peer can answer the agent's own. Before the agent starts its checks, and of a lite agent, a pair
        // is enough.
        private async Task CloseUnpairedAsync(IceTcpConnection connection)
        {
            const int Rounds = 4;
            for (int round = 0; round < Rounds; round++)
            {
                await Task.Delay(_options.TcpCheckTimeout).ConfigureAwait(false);
                bool keep, paired;
                lock (_sync)
                {
                    if (_closed || !_connections.Contains(connection) || SelectedPair?.Connection == connection)
                        return;
                    var pairs = _pairs.Where(p => p.Connection == connection).ToList();
                    paired = pairs.Count > 0;
                    // a lite agent sends no checks of its own: a pair, of the peer's authenticated check, is all it has
                    keep = pairs.Any(p => p.State == IceCandidatePairState.Succeeded) || IsLite && paired;
                    // a pair still being checked, or waiting for checks to begin, is given another round
                    bool pending = pairs.Any(p => p.State != IceCandidatePairState.Failed) && (round < Rounds - 1 || !_started);
                    if (!keep && (round == 0 ? paired : pending))
                        continue;
                }
                if (keep)
                    return;
                Trace(paired
                    ? $"Connection from {connection.RemoteEndPoint} closed: no check of the agent's succeeded on it"
                    : $"Connection from {connection.RemoteEndPoint} closed: no check of it in {_options.TcpCheckTimeout.TotalSeconds}s");
                connection.Dispose();
                return;
            }
        }

        // the connection of a pair of the agent's active candidate - of its own, or of a relay of TCP - and the check begun of
        // it sent over it
        private async Task ConnectAsync(IceCandidatePair pair)
        {
            IceTcpConnection connection;
            try
            {
                connection = pair.Base.TcpRelay != null
                    ? await ConnectRelayedAsync(pair).ConfigureAwait(false)
                    : await ConnectDirectAsync(pair).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException || ex is IOException || ex is OperationCanceledException
                || ex is InvalidOperationException || ex is TurnException || ex is StunException)
            {
                lock (_sync)
                {
                    if (pair.State == IceCandidatePairState.InProgress)
                    {
                        _transactions.Remove(Key(pair.TransactionId));
                        pair.State = pair.LastSucceeded > DateTime.MinValue ? IceCandidatePairState.Succeeded : IceCandidatePairState.Failed;
                    }
                }
                Trace($"Could not connect {pair}: {ex.Message}");
                return;
            }

            byte[] request;
            lock (_sync)
            {
                if (_closed || pair.Connection != null)
                {
                    connection.Dispose();
                    return;
                }
                pair.Connection = connection;
                _connections.Add(connection);
                request = pair.State == IceCandidatePairState.InProgress ? pair.Request : null;
            }
            Trace($"Connected {pair}");
            StartReceiving(pair.Base, connection);
            if (request != null)
                connection.Send(request, 0, request.Length);
        }

        // a connection of the agent's own
        private async Task<IceTcpConnection> ConnectDirectAsync(IceCandidatePair pair)
        {
            var client = new TcpClient(pair.RemoteEndPoint.AddressFamily);
            try
            {
                client.Client.Bind(new IPEndPoint(pair.Base.EndPoint.Address, 0));
                var connect = client.ConnectAsync(pair.RemoteEndPoint.Address, pair.RemoteEndPoint.Port);
                if (await Task.WhenAny(connect, Task.Delay(TcpConnectTimeout)).ConfigureAwait(false) != connect)
                    throw new SocketException((int)SocketError.TimedOut);
                await connect.ConfigureAwait(false);
            }
            catch
            {
                client.Dispose();
                throw;
            }
            return new IceTcpConnection(client);
        }

        private void StartReceiving(LocalBase local, IceTcpConnection connection)
        {
            Task.Run(async () =>
            {
                await connection.ReceiveAsync((buffer, count) =>
                {
                    try
                    {
                        OnDatagram(local, connection, buffer, 0, count, connection.RemoteEndPoint);
                    }
                    catch (Exception ex)
                    {
                        Trace($"Frame from {connection.RemoteEndPoint} failed: {ex}");
                    }
                }).ConfigureAwait(false);

                // closed: its pairs failed
                lock (_sync)
                {
                    _connections.Remove(connection);
                    foreach (var pair in _pairs.Where(p => p.Connection == connection))
                    {
                        if (pair.State == IceCandidatePairState.InProgress && pair.TransactionId != null)
                            _transactions.Remove(Key(pair.TransactionId));
                        pair.State = IceCandidatePairState.Failed;
                    }
                }
                connection.Dispose();
                if (!_closed)
                    Trace($"Connection to {connection.RemoteEndPoint} closed");
            });
        }
    }

    /// <summary>
    /// A connection of ICE over TCP: its packets - STUN, DTLS, RTP, RTCP - each of a 16 bit length before it (RFC 4571).
    /// </summary>
    internal sealed class IceTcpConnection : IDisposable
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly IDisposable _owner;
        private readonly object _writing = new object();
        private int _disposed;

        /// <summary>How long a write may take before the connection is closed: a peer that reads nothing ends it.</summary>
        internal static TimeSpan WriteTimeout = TimeSpan.FromSeconds(5);

        // Closes the connection when a write overruns WriteTimeout. Closing the socket ends the blocked write, whatever the
        // stream (TCP, or a TURN relay's data connection), so no thread - the agent's Tick included - is held longer.
        private Timer _writeDeadline;

        /// <summary>
        /// A connection of a stream of what else - of a relay of TCP, its data connection to the server - of the addresses the
        /// peer and the agent are of to each other, closed with what owns it.
        /// </summary>
        public IceTcpConnection(Stream stream, IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, IDisposable owner)
        {
            _stream = stream;
            _owner = owner;
            LocalEndPoint = IceAgent.Normalize(localEndPoint);
            RemoteEndPoint = IceAgent.Normalize(remoteEndPoint);
        }

        /// <summary>The connection, of its own stream.</summary>
        public IceTcpConnection(TcpClient client)
        {
            _client = client;
            _client.NoDelay = true;
            // a write to a peer that reads nothing ends, rather than holding the thread it blocks
            _client.SendTimeout = (int)WriteTimeout.TotalMilliseconds;
            _stream = client.GetStream();
            LocalEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.LocalEndPoint);
            RemoteEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.RemoteEndPoint);
        }

        public IPEndPoint LocalEndPoint { get; }

        public IPEndPoint RemoteEndPoint { get; }

        // of its one receiving loop: told of again of each packet
        public readonly IceDataReceivedEventArgs Args = new IceDataReceivedEventArgs();

        /// <summary>A packet, framed in a buffer of a pool; false of one longer than a frame takes, or of the connection closed.</summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            if (count > ushort.MaxValue)
                return false;
            byte[] frame = ArrayPool<byte>.Shared.Rent(2 + count);
            frame[0] = (byte)(count >> 8);
            frame[1] = (byte)count;
            Buffer.BlockCopy(buffer, offset, frame, 2, count);
            try
            {
                lock (_writing)
                {
                    if (Volatile.Read(ref _disposed) != 0)
                        return false;
                    _writeDeadline ??= new Timer(_ => Dispose(), null, Timeout.Infinite, Timeout.Infinite);
                    _writeDeadline.Change(WriteTimeout, Timeout.InfiniteTimeSpan);
                    try
                    {
                        _stream.Write(frame, 0, 2 + count);
                    }
                    finally
                    {
                        _writeDeadline.Change(Timeout.Infinite, Timeout.Infinite);
                    }
                }
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException || ex is InvalidOperationException)
            {
                // a frame written in part leaves the stream out of step: the connection is of no further use
                Dispose();
                return false;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(frame);
            }
        }

        /// <summary>Each packet as it comes, in a buffer that is its own again once the callback returns, until the connection closes.</summary>
        public async Task ReceiveAsync(Action<byte[], int> received)
        {
            // the connection's one buffer, of a pool: of a frame's length, then of the frame
            byte[] buffer = ArrayPool<byte>.Shared.Rent(ushort.MaxValue);
            try
            {
                while (true)
                {
                    if (!await ReadAsync(buffer, 2).ConfigureAwait(false))
                        return;
                    int length = buffer[0] << 8 | buffer[1];
                    if (!await ReadAsync(buffer, length).ConfigureAwait(false))
                        return;
                    received(buffer, length);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
            }
            finally
            {
                // cleared, before the pool hands it to anything else
                ArrayPool<byte>.Shared.Return(buffer, true);
            }
        }

#if NET8_0_OR_GREATER
        [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
#endif
        private async ReadTask ReadAsync(byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
#if NET8_0_OR_GREATER
                int read = await _stream.ReadAsync(buffer.AsMemory(offset, count - offset)).ConfigureAwait(false);
#else
                int read = await _stream.ReadAsync(buffer, offset, count - offset).ConfigureAwait(false);
#endif
                if (read == 0)
                    return false;
                offset += read;
            }
            return true;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            _writeDeadline?.Dispose();
            _stream.Dispose();
            _client?.Dispose();
            _owner?.Dispose();
        }
    }
}
