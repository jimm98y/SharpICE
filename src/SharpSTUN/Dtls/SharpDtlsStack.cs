// SharpSTUN
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

using SharpDTLS;
using SharpDTLS.UDP;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpSTUN
{
    /// <summary>
    /// DTLS of SharpDTLS: DTLS 1.3 and 1.2, its cipher suites and groups SharpDTLS's defaults; of a server, a fragmented
    /// ClientHello reassembled, and one SharpDTLS server of all its peers, of its events.
    /// </summary>
    public sealed class SharpDtlsStack : IDtlsStack
    {
        public string Name => "SharpDTLS";

        public async Task<IDtlsAssociation> ConnectAsync(Socket socket, DtlsClientSettings settings, CancellationToken cancellationToken = default)
        {
            if (socket == null)
                throw new ArgumentNullException(nameof(socket));
            settings ??= new DtlsClientSettings();
            var datagrams = new SocketClientTransport(socket);
            var client = new DtlsClient(datagrams)
            {
                ServerName = string.IsNullOrEmpty(settings.ServerName) || IPAddress.TryParse(settings.ServerName, out _) ? null : settings.ServerName,
                ServerCertificateValidator = (leaf, chain) => settings.ValidateServerCertificate?.Invoke(chain) ?? true,
            };
            var association = new Association(client, datagrams, settings);
            var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.HandshakeFinished += (s, e) => handshake.TrySetResult(true);
            client.Failed += (s, ex) =>
            {
                handshake.TrySetException(new IOException("The DTLS handshake failed: " + ex.Message, ex));
                association.Ended(ex);
            };
            client.Closed += (s, e) =>
            {
                handshake.TrySetException(new IOException("The DTLS association closed during its handshake."));
                association.Ended(null);
            };
            client.ApplicationDataReceived += (s, data) => association.Record(data);
            datagrams.Failed += ex =>
            {
                handshake.TrySetException(ex);
                association.Ended(ex);
            };

            try
            {
                datagrams.Start();
                client.BeginHandshake();
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    timeout.CancelAfter(settings.HandshakeTimeout);
                    using (timeout.Token.Register(() => handshake.TrySetCanceled()))
                        await handshake.Task.ConfigureAwait(false);
                }
                association.Established();
                return association;
            }
            catch (Exception ex) when (ex is OperationCanceledException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                association.Dispose();
                cancellationToken.ThrowIfCancellationRequested();
                throw new IOException(ex is OperationCanceledException ? "The DTLS handshake timed out." : "The DTLS handshake failed: " + ex.Message, ex);
            }
            catch
            {
                association.Dispose();
                throw;
            }
        }

        public IDtlsServer CreateServer(DtlsServerSettings settings) => new Server(settings ?? throw new ArgumentNullException(nameof(settings)));

        private sealed class Association : IDtlsAssociation
        {
            private readonly DtlsClient _client;
            private readonly SocketClientTransport _datagrams;
            private readonly DtlsClientSettings _settings;
            private readonly object _writing = new object();
            private volatile bool _established;
            private volatile bool _closed;

            public Association(DtlsClient client, SocketClientTransport datagrams, DtlsClientSettings settings)
            {
                _client = client;
                _datagrams = datagrams;
                _settings = settings;
            }

            public ushort NegotiatedVersion => _client.NegotiatedVersion;

            public void Established() => _established = true;

            public void Record(byte[] data)
            {
                if (_established && !_closed)
                    _settings.RecordReceived?.Invoke(data, 0, data.Length);
            }

            // of the server's close_notify, of an alert, or of its port unreachable: told of once established alone
            public void Ended(Exception error)
            {
                if (!_established || _closed)
                    return;
                _closed = true;
                _datagrams.Stop();
                _settings.Closed?.Invoke(error);
            }

            public void Send(byte[] buffer, int offset, int count)
            {
                if (_closed)
                    throw new IOException("The DTLS association ended.");
                // SharpDTLS takes a record's data as an array of its own
                byte[] data = new byte[count];
                Buffer.BlockCopy(buffer, offset, data, 0, count);
                try
                {
                    lock (_writing)
                        _client.SendApplicationData(data);
                }
                catch (Exception ex) when (ex is SocketException || ex is InvalidOperationException || ex is ObjectDisposedException)
                {
                    throw new IOException("The DTLS association ended: " + ex.Message, ex);
                }
            }

            private bool _disposed;

            public void Dispose()
            {
                if (_disposed)
                    return;
                _disposed = true;
                _closed = true;
                try
                {
                    // its close_notify
                    lock (_writing)
                        _client.Close();
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
                {
                }
                _datagrams.Stop();
            }
        }

        /// <summary>
        /// The datagrams of a socket connected to the server, as SharpDTLS reads and writes them: each handed to the client, as
        /// it comes, of a thread of its own.
        /// </summary>
        private sealed class SocketClientTransport : IClientTransport
        {
            private readonly Socket _socket;
            private readonly Thread _receiver;
            private volatile bool _stopped;

            public SocketClientTransport(Socket socket)
            {
                _socket = socket;
                _receiver = new Thread(Receive) { IsBackground = true, Name = "DTLS of SharpDTLS" };
            }

            public event EventHandler<byte[]> OnDataReceived;

            /// <summary>Of an ICMP port unreachable of the server's port: no server there.</summary>
            public event Action<IOException> Failed;

            public void Start() => _receiver.Start();

            public void Stop() => _stopped = true;

            public void Send(byte[] buf)
            {
                if (_stopped)
                    return;
                try
                {
                    _socket.Send(buf, 0, buf.Length, SocketFlags.None);
                }
                catch (ObjectDisposedException)
                {
                }
                catch (SocketException)
                {
                    // a datagram lost, as of UDP: the handshake retransmits it, and an unreachable port is told of the receiver
                }
            }

            private void Receive()
            {
                byte[] buffer = new byte[ushort.MaxValue];
                EndPoint remote;
                try
                {
                    remote = _socket.RemoteEndPoint;
                }
                catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                {
                    return;
                }
                while (!_stopped)
                {
                    int count;
                    try
                    {
                        if (!_socket.Poll(1000 * 1000, SelectMode.SelectRead))
                            continue;
                        count = _socket.Receive(buffer, 0, buffer.Length, SocketFlags.None);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        // an ICMP port unreachable, as the socket is connected: no server there, as of a TCP connection refused
                        if (!_stopped)
                            Failed?.Invoke(new IOException("The server's port is unreachable.", ex));
                        return;
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                    if (count <= 0 || _stopped)
                        continue;
                    byte[] datagram = new byte[count];
                    Buffer.BlockCopy(buffer, 0, datagram, 0, count);
                    try
                    {
                        OnDataReceived?.Invoke(remote, datagram);
                    }
                    catch (Exception)
                    {
                        // of a thread of its own: a datagram the client failed of is the association's to tell of, never the process's
                    }
                }
            }
        }

        /// <summary>
        /// One SharpDTLS server of the peers of a socket, of a cookie exchange of each first: the datagrams handed to it of the
        /// socket's loop, its own sent of the settings' sender - of its timers too, as it retransmits.
        /// </summary>
        private sealed class Server : IDtlsServer, IServerTransport
        {
            private readonly DtlsServerSettings _settings;
            private readonly DtlsServer _dtls;
            // the peers of an association, and of each, its connection and whether it is established
            private readonly ConcurrentDictionary<EndPoint, Peer> _peers = new ConcurrentDictionary<EndPoint, Peer>();
            private readonly Timer _handshakes;

            private sealed class Peer
            {
                public TlsConnectionBase Connection;
                public DateTime Created = DateTime.UtcNow;
                public volatile bool Established;
                public readonly object Writing = new object();
            }

            public Server(DtlsServerSettings settings)
            {
                if (settings.Certificate == null)
                    throw new ArgumentException("A server of DTLS takes a certificate.", nameof(settings));
                _settings = settings;
                var credentials = DtlsCertificates.Load(settings.Certificate);
                _dtls = new DtlsServer(this, credentials.KeyPair, credentials.Certificate)
                {
                    IntermediateCertificates = credentials.Intermediates,
                    // a HelloVerifyRequest, or of DTLS 1.3 a HelloRetryRequest, of a cookie before any state of the peer's
                    RequireCookie = true,
                };
                _dtls.ConnectionCreated += (s, connection) => _peers.TryAdd(connection.RemoteEndPoint, new Peer { Connection = connection });
                _dtls.HandshakeFinished += (s, connection) =>
                {
                    var peer = _peers.GetOrAdd(connection.RemoteEndPoint, _ => new Peer { Connection = connection });
                    peer.Connection = connection;
                    peer.Established = true;
                    _settings.Established?.Invoke((IPEndPoint)connection.RemoteEndPoint);
                };
                _dtls.ApplicationDataReceived += (s, e) =>
                {
                    if (_peers.TryGetValue(e.RemoteEndPoint, out var peer) && peer.Established)
                        _settings.RecordReceived?.Invoke((IPEndPoint)e.RemoteEndPoint, e.Data, 0, e.Data.Length);
                };
                _dtls.ConnectionClosed += (s, connection) =>
                {
                    if (_peers.TryRemove(connection.RemoteEndPoint, out _))
                        _settings.Closed?.Invoke((IPEndPoint)connection.RemoteEndPoint);
                };
                // the handshakes of no end in time, ended
                _handshakes = new Timer(_ => EndLateHandshakes(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
            }

            // of IServerTransport: what the SharpDTLS server sends, and the datagrams handed to it
            public event EventHandler<byte[]> OnDataReceived;

            void IServerTransport.Send(EndPoint endpoint, byte[] buf)
            {
                try
                {
                    _settings.SendDatagram?.Invoke((IPEndPoint)endpoint, buf, 0, buf.Length);
                }
                catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                {
                    // a datagram lost, as of UDP: a handshake's flight is retransmitted
                }
            }

            public void Receive(IPEndPoint from, byte[] buffer, int offset, int count)
            {
                byte[] datagram = new byte[count];
                Buffer.BlockCopy(buffer, offset, datagram, 0, count);
                OnDataReceived?.Invoke(from, datagram);
            }

            public bool HasAssociation(IPEndPoint peer) => _peers.ContainsKey(peer);

            public IReadOnlyCollection<IPEndPoint> Peers => _peers.Keys.Cast<IPEndPoint>().ToList();

            public int Count => _peers.Count;

            public void Send(IPEndPoint peer, byte[] buffer, int offset, int count)
            {
                if (!_peers.TryGetValue(peer, out var state) || !state.Established)
                    throw new IOException($"No DTLS association of {peer}.");
                byte[] data = new byte[count];
                Buffer.BlockCopy(buffer, offset, data, 0, count);
                try
                {
                    lock (state.Writing)
                        state.Connection.SendApplicationData(data);
                }
                catch (Exception ex) when (ex is SocketException || ex is InvalidOperationException || ex is ObjectDisposedException)
                {
                    throw new IOException("The DTLS association ended: " + ex.Message, ex);
                }
            }

            public void Close(IPEndPoint peer)
            {
                if (!_peers.TryRemove(peer, out var state))
                    return;
                CloseQuietly(state.Connection);
                _settings.Closed?.Invoke(peer);
            }

            // of a timer's thread: whatever a handler of Closed throws ends this round alone, never the process
            private void EndLateHandshakes()
            {
                var now = DateTime.UtcNow;
                foreach (var entry in _peers.ToList())
                {
                    if (!entry.Value.Established && now - entry.Value.Created > _settings.HandshakeTimeout)
                    {
                        try
                        {
                            Close((IPEndPoint)entry.Key);
                        }
                        catch (Exception)
                        {
                        }
                    }
                }
            }

            private static void CloseQuietly(TlsConnectionBase connection)
            {
                try
                {
                    // its close_notify
                    connection?.Close();
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
                {
                }
            }

            public void Dispose()
            {
                _handshakes.Dispose();
                foreach (var peer in _peers.Keys.ToList())
                    Close((IPEndPoint)peer);
            }
        }
    }
}
