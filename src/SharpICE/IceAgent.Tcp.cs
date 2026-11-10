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

#if NET8_0_OR_GREATER
using ReadTask = System.Threading.Tasks.ValueTask<bool>;
#else
using ReadTask = System.Threading.Tasks.Task<bool>;
#endif
using SharpDTLS;
using SharpStunCommon;
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
    /// RFC 4571 frames RTP, of a 16 bit length each. Simultaneous-open is not done. Of ICE-TCP over TLS, alike, each
    /// connection of TLS of SharpDTLS: the agent of the active candidate its client, of the passive one its server.
    /// </summary>
    public sealed partial class IceAgent
    {
        private static readonly TimeSpan TcpConnectTimeout = TimeSpan.FromSeconds(5);

        // the discard port, which an active candidate says it is of (RFC 6544 4.5)
        private const int ActivePort = 9;

        // of TLS: the server the passive candidates' connections are answered of, of the agent's certificate
        private TlsServer _tlsServer;

        // of TLS: the connections to passive candidates whose handshakes are under way, of the connections' limit too
        private int _tlsHandshakes;

        private void GatherTcp(List<IPAddress> addresses, List<IceCandidate> gathered) => GatherStream(addresses, gathered, false);

        // of ICE-TCP over TLS, as of TCP: the candidates of transport "tls", their connections of TLS
        private void GatherTls(List<IPAddress> addresses, List<IceCandidate> gathered)
        {
            if (_tlsServer == null)
            {
                // of the certificate given, else of one of the agent's own, of ECDSA
                var credentials = _options.TlsCertificate != null
                    ? DtlsCertificates.Load(_options.TlsCertificate)
                    : DtlsCertificates.CreateSelfSigned("SharpICE");
                var server = new TlsServer(credentials.KeyPair, credentials.Certificate) { IntermediateCertificates = credentials.Intermediates };
                lock (_sync)
                {
                    if (_closed)
                    {
                        server.Dispose();
                        return;
                    }
                    _tlsServer = server;
                }
            }
            GatherStream(addresses, gathered, true);
        }

        private void GatherStream(List<IPAddress> addresses, List<IceCandidate> gathered, bool tls)
        {
            string transport = tls ? "tls" : "tcp";
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

                // one foundation of the address, of TCP or of TLS: its passive and active candidates are of one base address,
                // type and transport
                var endPoint = (IPEndPoint)listener.LocalEndpoint;
                string foundation = (tls ? "l" : "t") + (i + 1).ToString(CultureInfo.InvariantCulture);
                var passive = new IceCandidate
                {
                    Foundation = foundation,
                    Component = IceCandidate.RtpComponent,
                    Transport = transport,
                    Priority = IceCandidate.ComputePriority(IceCandidateType.Host, IceCandidate.TcpLocalPreference(IceCandidate.TcpPassive, 8191 - i), IceCandidate.RtpComponent, transport),
                    Address = HostAddress(endPoint.Address),
                    Port = endPoint.Port,
                    Type = IceCandidateType.Host,
                };
                passive.TcpType = IceCandidate.TcpPassive;
                var active = new IceCandidate
                {
                    Foundation = foundation,
                    Component = IceCandidate.RtpComponent,
                    Transport = transport,
                    Priority = IceCandidate.ComputePriority(IceCandidateType.Host, IceCandidate.TcpLocalPreference(IceCandidate.TcpActive, 8191 - i), IceCandidate.RtpComponent, transport),
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

                if (local.Candidate.IsTls)
                {
                    // of TLS, its handshake of a task of its own, that a peer slow of it holds up no other
                    lock (_sync)
                    {
                        if (_closed)
                        {
                            client.Dispose();
                            return;
                        }
                        if (_connections.Count + _tlsHandshakes >= _options.MaxTcpConnections)
                        {
                            Trace($"Connection from {client.Client.RemoteEndPoint} refused: {_options.MaxTcpConnections} already");
                            client.Dispose();
                            continue;
                        }
                        _tlsHandshakes++;
                    }
                    _ = AcceptTlsAsync(local, client);
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
                    if (_connections.Count + _tlsHandshakes >= _options.MaxTcpConnections)
                    {
                        Trace($"Connection from {connection.RemoteEndPoint} refused: {_options.MaxTcpConnections} already");
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

        // a connection to a passive candidate of TLS: its handshake, of the agent's server, done in the time a connection has
        // to make a pair of its checks - else closed, as anyone may connect
        private async Task AcceptTlsAsync(LocalBase local, TcpClient client)
        {
            IceTcpConnection connection = null;
            try
            {
                using (var timeout = new CancellationTokenSource(_options.TcpCheckTimeout))
                {
                    var stream = await TlsStream.AcceptAsync(_tlsServer, client.GetStream(), timeout.Token).ConfigureAwait(false);
                    connection = new IceTcpConnection(client, stream);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is OperationCanceledException || ex is InvalidOperationException || ex is DtlsException)
            {
                Trace($"TLS of {SafeRemote(client)} failed: {ex.Message}");
            }

            lock (_sync)
            {
                _tlsHandshakes--;
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
            if (connection == null)
            {
                client.Dispose();
                return;
            }
            Accepted(local, connection);
        }

        // of a connection that may be gone already: its peer's address, or nothing
        private static string SafeRemote(TcpClient client)
        {
            try
            {
                return client.Client.RemoteEndPoint?.ToString();
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
            {
                return null;
            }
        }

        // a connection anyone made: of no pair of its checks - authenticated, each - in time, closed
        private async Task CloseUnpairedAsync(IceTcpConnection connection)
        {
            await Task.Delay(_options.TcpCheckTimeout).ConfigureAwait(false);
            bool paired;
            lock (_sync)
                paired = _closed || !_connections.Contains(connection) || _pairs.Any(p => p.Connection == connection) || SelectedPair?.Connection == connection;
            if (!paired)
            {
                Trace($"Connection from {connection.RemoteEndPoint} closed: no check of it in {_options.TcpCheckTimeout.TotalSeconds}s");
                connection.Dispose();
            }
        }

        // the connection of a pair of the agent's active candidate, and the check begun of it sent over it
        private async Task ConnectAsync(IceCandidatePair pair)
        {
            var client = new TcpClient(pair.RemoteEndPoint.AddressFamily);
            TlsStream tls = null;
            try
            {
                var deadline = DateTime.UtcNow + TcpConnectTimeout;
                client.Client.Bind(new IPEndPoint(pair.Base.EndPoint.Address, 0));
                var connect = client.ConnectAsync(pair.RemoteEndPoint.Address, pair.RemoteEndPoint.Port);
                if (await Task.WhenAny(connect, Task.Delay(TcpConnectTimeout)).ConfigureAwait(false) != connect)
                    throw new SocketException((int)SocketError.TimedOut);
                await connect.ConfigureAwait(false);

                if (pair.IsTls)
                {
                    // of TLS, the agent the client, its handshake of the time left of the connection's: the peer's certificate
                    // taken as it is, as nothing signalled tells of it (see IceAgentOptions.IncludeTls)
                    var left = deadline - DateTime.UtcNow;
                    using (var timeout = new CancellationTokenSource(left > TimeSpan.Zero ? left : TimeSpan.FromMilliseconds(1)))
                    {
                        tls = await TlsStream.ConnectAsync(client.GetStream(), c => c.ServerCertificateValidator = (leaf, chain) => true, timeout.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException || ex is IOException || ex is OperationCanceledException || ex is InvalidOperationException || ex is DtlsException)
            {
                client.Dispose();
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

            var connection = new IceTcpConnection(client, tls);
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
    /// A connection of ICE over TCP, or of TLS over it: its packets - STUN, DTLS, RTP, RTCP - each of a 16 bit length before it
    /// (RFC 4571), of TLS in its records.
    /// </summary>
    internal sealed class IceTcpConnection : IDisposable
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly object _writing = new object();

        /// <summary>The connection, of its own stream, or of the TLS of it given.</summary>
        public IceTcpConnection(TcpClient client, Stream tls = null)
        {
            _client = client;
            _client.NoDelay = true;
            // a write to a peer that reads nothing ends, rather than holding the thread it blocks
            _client.SendTimeout = 5000;
            _stream = tls ?? client.GetStream();
            IsTls = tls != null;
            LocalEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.LocalEndPoint);
            RemoteEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.RemoteEndPoint);
        }

        public IPEndPoint LocalEndPoint { get; }

        public IPEndPoint RemoteEndPoint { get; }

        public bool IsTls { get; }

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
                    _stream.Write(frame, 0, 2 + count);
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
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
            _stream.Dispose();
            _client.Dispose();
        }
    }
}
