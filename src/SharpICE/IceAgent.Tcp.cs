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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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

                // one foundation of the address, of TCP: its passive and active candidates are of one base address and type
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
                    _connections.Add(connection);
                }
                Trace($"Connection from {connection.RemoteEndPoint} to {local.EndPoint}");
                StartReceiving(local, connection);
            }
        }

        // the connection of a pair of the agent's active candidate, and the check begun of it sent over it
        private async Task ConnectAsync(IceCandidatePair pair)
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
            catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
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

            var connection = new IceTcpConnection(client);
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

    /// <summary>A connection of ICE over TCP: its packets - STUN, DTLS, RTP, RTCP - each of a 16 bit length before it (RFC 4571).</summary>
    internal sealed class IceTcpConnection : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly object _writing = new object();

        public IceTcpConnection(TcpClient client)
        {
            _client = client;
            _client.NoDelay = true;
            _stream = client.GetStream();
            LocalEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.LocalEndPoint);
            RemoteEndPoint = IceAgent.Normalize((IPEndPoint)client.Client.RemoteEndPoint);
        }

        public IPEndPoint LocalEndPoint { get; }

        public IPEndPoint RemoteEndPoint { get; }

        /// <summary>A packet, framed; false of one longer than a frame takes, or of the connection closed.</summary>
        public bool Send(byte[] buffer, int offset, int count)
        {
            if (count > ushort.MaxValue)
                return false;
            byte[] frame = new byte[2 + count];
            frame[0] = (byte)(count >> 8);
            frame[1] = (byte)count;
            Buffer.BlockCopy(buffer, offset, frame, 2, count);
            try
            {
                lock (_writing)
                    _stream.Write(frame, 0, frame.Length);
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
                return false;
            }
        }

        /// <summary>Each packet as it comes, in a buffer that is its own again once the callback returns, until the connection closes.</summary>
        public async Task ReceiveAsync(Action<byte[], int> received)
        {
            byte[] header = new byte[2];
            byte[] buffer = new byte[ushort.MaxValue];
            try
            {
                while (true)
                {
                    if (!await ReadAsync(header, 2).ConfigureAwait(false))
                        return;
                    int length = header[0] << 8 | header[1];
                    if (!await ReadAsync(buffer, length).ConfigureAwait(false))
                        return;
                    received(buffer, length);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is ObjectDisposedException || ex is SocketException)
            {
            }
        }

        private async Task<bool> ReadAsync(byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = await _stream.ReadAsync(buffer, offset, count - offset).ConfigureAwait(false);
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
