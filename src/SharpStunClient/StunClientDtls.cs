// SharpStunClient
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

using SharpDTLS;
using SharpDTLS.UDP;
using SharpStunCommon;
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    /// <summary>
    /// STUN over DTLS (RFC 8489 6.2.3): a STUN message in each record of a DTLS 1.3 or 1.2 association of the server's, of
    /// SharpDTLS, its certificate checked as one of TLS is - of the host name given, of the system's checks or of a callback's.
    /// Requests over it are retransmitted, as over UDP.
    /// </summary>
    public sealed class StunDtlsTransport : StunTransport
    {
        private readonly Socket _socket;
        private readonly SocketClientTransport _datagrams;
        private readonly DtlsClient _dtls;
        private readonly string _host;
        private readonly RemoteCertificateValidationCallback _validation;
        private readonly object _writing = new object();
        private volatile bool _closed;

        private StunDtlsTransport(Socket socket, SocketClientTransport datagrams, DtlsClient dtls, IPEndPoint server, string host, RemoteCertificateValidationCallback validation)
        {
            _socket = socket;
            _datagrams = datagrams;
            _dtls = dtls;
            _host = host;
            _validation = validation;
            RemoteEndPoint = server;
        }

        /// <summary>
        /// The association of a handshake with the server: its certificate checked of the host name, or of the callback given
        /// rather than the system's checks.
        /// </summary>
        /// <exception cref="IOException">Of a handshake that failed, as of a certificate refused.</exception>
        public static async Task<StunDtlsTransport> ConnectAsync(IPEndPoint server, string host, RemoteCertificateValidationCallback validation = null, CancellationToken cancellationToken = default)
        {
            if (host == null)
                throw new ArgumentNullException(nameof(host));
            var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            SocketClientTransport datagrams = null;
            DtlsClient dtls = null;
            try
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                socket.Connect(server);
                datagrams = new SocketClientTransport(socket);
                var client = new DtlsClient(datagrams)
                {
                    // of a name, not an address, its SNI (RFC 6066 3)
                    ServerName = IPAddress.TryParse(host, out _) ? null : host,
                };
                dtls = client;
                client.ServerCertificateValidator = (leaf, chain) => DtlsCertificates.Validate(chain, host, validation, client);

                // what the association is told of, once its handshake is done: of the transport made of it
                StunDtlsTransport transport = null;
                var handshake = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.HandshakeFinished += (s, e) => handshake.TrySetResult(true);
                client.Failed += (s, ex) =>
                {
                    handshake.TrySetException(new IOException("The DTLS handshake failed: " + ex.Message, ex));
                    transport?.OnEnded(ex);
                };
                client.Closed += (s, e) =>
                {
                    handshake.TrySetException(new IOException("The DTLS association closed during its handshake."));
                    transport?.OnEnded(null);
                };
                client.ApplicationDataReceived += (s, data) => transport?.OnRecord(data);
                datagrams.Failed += ex =>
                {
                    handshake.TrySetException(ex);
                    transport?.OnEnded(ex);
                };

                datagrams.Start();
                client.BeginHandshake();
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    timeout.CancelAfter(DtlsDefaults.HandshakeTimeout);
                    using (timeout.Token.Register(() => handshake.TrySetCanceled()))
                        await handshake.Task.ConfigureAwait(false);
                }
                transport = new StunDtlsTransport(socket, datagrams, client, server, host, validation);
                return transport;
            }
            catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is OperationCanceledException)
            {
                Abandon(socket, datagrams, dtls);
                cancellationToken.ThrowIfCancellationRequested();
                if (ex is OperationCanceledException)
                    throw new IOException("The DTLS handshake timed out.", ex);
                throw ex as IOException ?? new IOException("The DTLS handshake failed: " + ex.Message, ex);
            }
            catch
            {
                Abandon(socket, datagrams, dtls);
                throw;
            }
        }

        private static void Abandon(Socket socket, SocketClientTransport datagrams, DtlsClient dtls)
        {
            datagrams?.Stop();
            CloseQuietly(dtls);
            socket.Dispose();
        }

        private static void CloseQuietly(DtlsClient dtls)
        {
            try
            {
                // its close_notify
                dtls?.Close();
            }
            catch (Exception ex) when (ex is IOException || ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
            {
            }
        }

        public override bool IsReliable => false;

        public override IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint;

        public override Task SendAsync(byte[] message, CancellationToken cancellationToken = default) => SendAsync(message, 0, message.Length, cancellationToken);

        public override Task SendAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (_closed)
                throw new IOException("The DTLS association ended.");
            // SharpDTLS takes a record's data as an array of its own
            byte[] data = new byte[count];
            Buffer.BlockCopy(buffer, offset, data, 0, count);
            try
            {
                lock (_writing)
                    _dtls.SendApplicationData(data);
            }
            catch (Exception ex) when (ex is SocketException || ex is InvalidOperationException || ex is ObjectDisposedException)
            {
                throw new IOException("The DTLS association ended: " + ex.Message, ex);
            }
            return Task.CompletedTask;
        }

        public override async Task<StunTransport> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken = default)
            => await ConnectAsync(server, domain ?? _host, _validation, cancellationToken).ConfigureAwait(false);

        // a record's data: a STUN message, or of TURN, ChannelData
        private void OnRecord(byte[] data)
        {
            if (_closed)
                return;
            var message = StunMessage.Parse(data, 0, data.Length);
            if (message != null)
                OnMessageReceived(message, RemoteEndPoint);
            else if (data.Length >= 4 && StunFraming.IsChannelData(data[0]))
                OnDataReceived(data, 0, data.Length);
        }

        // the association ended of the server's close_notify, of an alert, or of its port unreachable
        private void OnEnded(Exception error)
        {
            if (_closed)
                return;
            _closed = true;
            _datagrams.Stop();
            _socket.Dispose();
            OnClosed(error);
        }

        public override void Dispose()
        {
            if (_closed)
                return;
            _closed = true;
            lock (_writing)
                CloseQuietly(_dtls);
            _datagrams.Stop();
            _socket.Dispose();
        }
    }

    /// <summary>
    /// The datagrams of a socket connected to the server, as SharpDTLS reads and writes them: each handed to the client, as it
    /// comes, of a thread of its own.
    /// </summary>
    internal sealed class SocketClientTransport : IClientTransport
    {
        private readonly Socket _socket;
        private readonly Thread _receiver;
        private volatile bool _stopped;

        public SocketClientTransport(Socket socket)
        {
            _socket = socket;
            _receiver = new Thread(Receive) { IsBackground = true, Name = "STUN over DTLS" };
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
            var remote = _socket.RemoteEndPoint;
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
}
