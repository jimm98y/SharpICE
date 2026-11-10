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

using SharpStunCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace SharpStunClient
{
    public sealed class StunClientOptions
    {
        /// <summary>The long-term credentials (RFC 8489 9.2) a server that asks for them - of a 401 - is answered with.</summary>
        public string Username { get; set; }
        public string Password { get; set; }

        /// <summary>The SOFTWARE of its Binding requests; none, of null.</summary>
        public string Software { get; set; }

        /// <summary>The first retransmission timeout of a request over UDP, doubled at each retransmission (RFC 8489 6.2.1).</summary>
        public TimeSpan InitialRetransmissionTimeout { get; set; } = TimeSpan.FromMilliseconds(500);

        /// <summary>How many times a request over UDP is sent (Rc of RFC 8489 6.2.1).</summary>
        public int MaxTransmissions { get; set; } = 7;

        /// <summary>How many first timeouts to wait after the last of them (Rm of RFC 8489 6.2.1).</summary>
        public int LastWaitMultiplier { get; set; } = 16;

        /// <summary>How long to wait for the answer to a request over TCP (Ti of RFC 8489 6.2.2).</summary>
        public TimeSpan ReliableTimeout { get; set; } = TimeSpan.FromSeconds(39.5);

        /// <summary>How long to wait for a DNS server's answer to an SRV query.</summary>
        public TimeSpan DnsTimeout { get; set; } = TimeSpan.FromSeconds(2);

        /// <summary>Checks a TLS or DTLS server's certificate in place of the system's checks; of none, the system's.</summary>
        public RemoteCertificateValidationCallback CertificateValidation { get; set; }

        /// <summary>
        /// Whether a "stuns" URI is of DTLS over UDP (RFC 8489 6.2.3), its SRV records "_stuns._udp", rather than of TLS over TCP;
        /// a "turns" URI says which of its "?transport=".
        /// </summary>
        public bool UseDtls { get; set; }

        /// <summary>
        /// Whether to take SHA-256 of a server that lists it among its password algorithms, whatever its order: as a TURN client
        /// is to (RFC 8656 6), rather than the first of the list (RFC 8489 9.2.5).
        /// </summary>
        public bool PreferSha256 { get; set; }

        /// <summary>
        /// Which attributes the client knows: a response of a comprehension-required one it does not fails its transaction (RFC
        /// 8489 6.3.3). Of STUN and ICE, of none given; a TURN client's, of TURN's too.
        /// </summary>
        public Func<ushort, bool> IsKnownAttribute { get; set; } = StunAttributeType.IsKnown;
    }

    /// <summary>A transaction that failed otherwise than of no answer, or of an error response: what failed, and the response of it.</summary>
    public sealed class StunException : Exception
    {
        public StunException(string message, StunMessage response = null, Exception innerException = null) : base(message, innerException)
        {
            Response = response;
        }

        public StunMessage Response { get; }
    }

    /// <summary>
    /// A STUN client (RFC 8489): request/response transactions with a server over a <see cref="StunTransport"/> - UDP, TCP,
    /// TLS or DTLS - retransmitted over UDP and DTLS, of long-term credentials when the server asks for them, and redirected by its
    /// ALTERNATE-SERVER. Its static methods are of the Binding method alone: the address a NAT maps a socket to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A request goes as it is until the server answers 401 (Unauthenticated); then it is sent again, and so is each request
    /// after it, of the username - or of its USERHASH, of a server of username anonymity - the realm and nonce the server
    /// gave, and of MESSAGE-INTEGRITY, or MESSAGE-INTEGRITY-SHA256 and the first of the server's PASSWORD-ALGORITHMS this
    /// client has, of a server that lists them (RFC 8489 9.2). A 438 (Stale Nonce) is answered of the new nonce. A response
    /// to a request of credentials counts only of its integrity of them.
    /// </para>
    /// <para>
    /// A client made of a URI tries the next of the URI's servers - of their SRV records, then of their addresses - once one
    /// does not answer. One request at a time goes to a server that redirects, or that fails over.
    /// </para>
    /// </remarks>
    public sealed class StunClient : IDisposable
    {
        public const int DefaultPort = StunUri.DefaultPort;
        public const int DefaultSecurePort = StunUri.DefaultSecurePort;

        // the redirections, the challenges and the stale nonces one request is sent again of
        private const int MaxAttempts = 8;

        private sealed class Transaction
        {
            public byte[] Key;
            public bool Reliable;
            public bool IntegrityViolated;
            public readonly TaskCompletionSource<StunMessage> Completion = new TaskCompletionSource<StunMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private readonly StunClientOptions _options;
        private readonly object _sync = new object();
        private readonly Dictionary<StunTransactionKey, Transaction> _transactions = new Dictionary<StunTransactionKey, Transaction>();
        private List<IPEndPoint> _servers = new List<IPEndPoint>();
        private string _tlsHost;
        private StunTransport _transport;
        private bool _ownsTransport;

        // long-term credentials, of the server's challenge (RFC 8489 9.2)
        private string _realm;
        private string _nonce;
        private byte[] _key;
        private byte[] _passwordAlgorithms; // the attribute's value, sent back as it came
        private StunPasswordAlgorithm _passwordAlgorithm;
        private bool _useUserhash;

        /// <summary>A client not yet connected: of <see cref="ConnectAsync"/>, to a server of a URI.</summary>
        public StunClient(StunClientOptions options = null)
        {
            _options = options ?? new StunClientOptions();
        }

        /// <summary>A client of a transport the caller keeps: not disposed with it.</summary>
        public StunClient(StunTransport transport, StunClientOptions options = null) : this(options)
        {
            Attach(transport ?? throw new ArgumentNullException(nameof(transport)));
        }

        /// <summary>The transport to the server; null before the client is connected.</summary>
        public StunTransport Transport => _transport;

        public bool IsConnected => _transport != null;

        /// <summary>Of TLS, the name the server's certificate was checked of: of TURN, its data connections' too (RFC 6062 4.3).</summary>
        internal string TlsHost => _tlsHost;

        private StunTransport Connected => _transport ?? throw new InvalidOperationException("The client is not connected.");

        public StunClientOptions Options => _options;

        /// <summary>An indication of the server's: of TURN, a Data indication (RFC 8656 11.4).</summary>
        public event EventHandler<StunMessageEventArgs> IndicationReceived;

        /// <summary>What the server sent that is not STUN: of TURN, ChannelData (RFC 8656 12.4).</summary>
        public event EventHandler<StunDataEventArgs> DataReceived;

        /// <summary>The connection of a reliable transport ended: of the error, or of null, closed by the server.</summary>
        public event EventHandler<Exception> Closed;

        /// <summary>An indication (RFC 8489 6.1), of no credentials, as an indication is never authenticated (RFC 8656 5).</summary>
        public Task SendIndicationAsync(StunMessage indication, CancellationToken cancellationToken = default)
        {
            if (indication == null)
                throw new ArgumentNullException(nameof(indication));
            if (indication.Class != StunMessageClass.Indication)
                throw new ArgumentException("Of an indication.", nameof(indication));
            return Connected.SendAsync(indication.ToBytes(null, false), cancellationToken);
        }

        /// <summary>Bytes as they are: of TURN, a ChannelData message.</summary>
        public Task SendRawAsync(byte[] data, CancellationToken cancellationToken = default) => Connected.SendAsync(data, cancellationToken);

        /// <summary>Bytes of a buffer's part, the caller's again once the task completes: of TURN, ChannelData of a buffer of a pool.</summary>
        public Task SendRawAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default) => Connected.SendAsync(buffer, offset, count, cancellationToken);

        /// <summary>Whether a request of the long-term credentials succeeded: the next ones are sent of them.</summary>
        public bool IsAuthenticated { get; private set; }

        /// <summary>The realm of the server's challenge; null of none yet.</summary>
        public string Realm => _realm;

        /// <summary>
        /// Connects to a server of a STUN or TURN URI (RFC 7064, RFC 7065): of an IP address, it; of a host name and a port,
        /// its addresses; of a host name alone, its SRV records' (RFC 8489 8.1), else its addresses of the default port. Over
        /// UDP, of the first address, the others tried once it does not answer; over TCP and TLS, connected to the first
        /// that takes a connection, or of DTLS, an association. A "stuns" URI is of a host name, its certificate checked of it;
        /// of TLS, or of DTLS, of <see cref="StunClientOptions.UseDtls"/>.
        /// </summary>
        /// <exception cref="StunException">Of no address, or of none that takes a connection.</exception>
        /// <exception cref="InvalidOperationException">Of a client connected already.</exception>
        public async Task ConnectAsync(string uri, CancellationToken cancellationToken = default)
        {
            if (_transport != null)
                throw new InvalidOperationException("The client is connected already.");
            var options = _options;
            var parsed = StunUri.Parse(uri);
            if (parsed.IsSecure && parsed.Address != null)
                throw new StunException($"Of {uri}: a secure URI is of a host name, which the server's certificate is checked of (RFC 8489 8.1).");
            string protocol = parsed.IsSecure && parsed.Transport == null && options.UseDtls ? "udp" : parsed.TransportProtocol;

            var servers = await ResolveAllAsync(parsed, options.DnsTimeout, cancellationToken, protocol).ConfigureAwait(false);
            if (servers.Count == 0)
                throw new StunException($"{uri} resolves to no address.");

            if (protocol == "udp" && !parsed.IsSecure)
            {
                Connect(new StunUdpTransport(servers[0]), servers.Skip(1).ToList(), null);
                return;
            }

            string tlsHost = parsed.IsSecure ? parsed.Host : null;
            bool dtls = protocol == "udp";
            Exception last = null;
            for (int i = 0; i < servers.Count; i++)
            {
                try
                {
                    StunTransport transport = dtls
                        ? await StunDtlsTransport.ConnectAsync(servers[i], tlsHost, options.CertificateValidation, cancellationToken).ConfigureAwait(false)
                        : await StunStreamTransport.ConnectAsync(servers[i], tlsHost, options.CertificateValidation, cancellationToken).ConfigureAwait(false);
                    Connect(transport, servers.Skip(i + 1).ToList(), tlsHost);
                    return;
                }
                catch (Exception e) when (IsConnectionFailure(e))
                {
                    last = e;
                }
            }
            throw new StunException($"No server of {uri} takes a connection.", null, last);
        }

        // of a transport of the client's own, the URI's other servers to try after it
        private void Connect(StunTransport transport, List<IPEndPoint> servers, string tlsHost)
        {
            _servers = servers;
            _tlsHost = tlsHost;
            _ownsTransport = true;
            Attach(transport);
        }

        private static bool IsConnectionFailure(Exception e) => e is SocketException || e is IOException || e is AuthenticationException;

        #region Transactions

        /// <summary>
        /// Sends the request and waits for its answer, sent again as the server asks for credentials or a new nonce, or
        /// redirected: the success response, or the error response the server ends with; null of no answer, of any server.
        /// </summary>
        /// <exception cref="StunException">
        /// Of no response of integrity of the credentials, of a response of a comprehension-required attribute this library
        /// does not know, or of an error response of no ERROR-CODE, which end the transaction (RFC 8489 6.3.3, 6.3.4, 9.2.5);
        /// or of the connection ended.
        /// </exception>
        public async Task<StunMessage> RequestAsync(StunMessage request, CancellationToken cancellationToken = default)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            if (request.Class != StunMessageClass.Request)
                throw new ArgumentException("A transaction is of a request.", nameof(request));

            var visited = new List<IPEndPoint> { Connected.RemoteEndPoint };
            for (int attempt = 0; attempt < MaxAttempts; attempt++)
            {
                // the first attempt of the request's own transaction ID, each after it - a new transaction - of a new one
                var (message, key, integrity) = Prepare(request, attempt == 0);
                var response = await TransactAsync(message, key, integrity, cancellationToken).ConfigureAwait(false);
                if (response == null)
                {
                    if (await NextServerAsync(cancellationToken).ConfigureAwait(false))
                    {
                        visited.Add(_transport.RemoteEndPoint);
                        continue;
                    }
                    return null;
                }

                // of a server of classic STUN, its retired attributes taken as known (RFC 8489 18.3.1)
                var unknown = response.GetUnknownComprehensionRequired(t => _options.IsKnownAttribute(t) || StunAttributeType.IsRetired(t));
                if (unknown.Count > 0)
                    throw new StunException($"The response is of attributes it is not to be understood without: {string.Join(", ", unknown.Select(t => "0x" + t.ToString("X4")))}.", response);

                if (response.Class == StunMessageClass.SuccessResponse)
                {
                    if (key != null)
                        IsAuthenticated = true;
                    return response;
                }

                var error = response.Error;
                if (error == null)
                    throw new StunException("An error response of no ERROR-CODE.", response);
                switch (error.Value.Code)
                {
                    case StunErrorCode.Unauthorized:
                        if (!TakeChallenge(response, key != null))
                            return response;
                        break;

                    case StunErrorCode.StaleNonce:
                        if (key == null || !TakeStaleNonce(response))
                            return response;
                        break;

                    case StunErrorCode.TryAlternate:
                        // of the address family of the request, to a server it has not been to (RFC 8489 10)
                        var alternate = response.AlternateServers.FirstOrDefault(s => s.AddressFamily == _transport.RemoteEndPoint.AddressFamily);
                        if (alternate == null || visited.Contains(alternate) || !await RedirectAsync(alternate, response.AlternateDomain, cancellationToken).ConfigureAwait(false))
                            return response;
                        visited.Add(alternate);
                        break;

                    default:
                        return response;
                }
            }
            throw new StunException($"The request was sent {MaxAttempts} times, each challenged, its nonce stale or redirected.");
        }

        /// <summary>The address the server sees a Binding request come from; null of no answer, or of an error response.</summary>
        public async Task<IPEndPoint> GetMappedAddressAsync(CancellationToken cancellationToken = default)
        {
            var response = await RequestAsync(CreateBindingRequest(_options.Software), cancellationToken).ConfigureAwait(false);
            return GetMappedAddress(response);
        }

        // the request as it is to go: of the credentials, of a server that asked for them
        private (StunMessage Message, byte[] Key, StunIntegrity Integrity) Prepare(StunMessage request, bool sameTransaction)
        {
            var message = new StunMessage(request.Method, request.Class, sameTransaction ? request.TransactionId : null);
            byte[] key;
            lock (_sync)
                key = _key;

            foreach (var attribute in request.Attributes)
            {
                if (IsAddedHere(attribute.Type, key != null))
                    continue;
                message.Attributes.Add(attribute);
            }
            if (key == null)
                return (message, null, StunIntegrity.None);

            lock (_sync)
            {
                if (_useUserhash)
                    message.AddAttribute(StunAttributeType.Userhash, StunCredentials.UserHash(_options.Username, _realm));
                else
                    message.AddString(StunAttributeType.Username, StunCredentials.OpaqueString(_options.Username));
                message.AddString(StunAttributeType.Realm, _realm);
                message.AddString(StunAttributeType.Nonce, _nonce);
                if (_passwordAlgorithms != null)
                {
                    message.AddAttribute(StunAttributeType.PasswordAlgorithms, _passwordAlgorithms);
                    message.AddPasswordAlgorithm(_passwordAlgorithm);
                }
                // MESSAGE-INTEGRITY-SHA256 alone once the server listed its algorithms (RFC 8489 9.2.5)
                return (message, key, _passwordAlgorithms != null ? StunIntegrity.Sha256 : StunIntegrity.Sha1);
            }
        }

        private static bool IsAddedHere(ushort type, bool credentials)
        {
            switch (type)
            {
                case StunAttributeType.MessageIntegrity:
                case StunAttributeType.MessageIntegritySha256:
                case StunAttributeType.Fingerprint:
                    return true;
                case StunAttributeType.Username:
                case StunAttributeType.Userhash:
                case StunAttributeType.Realm:
                case StunAttributeType.Nonce:
                case StunAttributeType.PasswordAlgorithms:
                case StunAttributeType.PasswordAlgorithm:
                    return credentials;
                default:
                    return false;
            }
        }

        // one transaction: retransmitted over UDP (RFC 8489 6.2.1), waited for over TCP (6.2.2); null of no answer
        private async Task<StunMessage> TransactAsync(StunMessage message, byte[] key, StunIntegrity integrity, CancellationToken cancellationToken)
        {
            var transport = _transport;
            byte[] bytes = message.ToBytes(key, integrity);
            var transaction = new Transaction { Key = key, Reliable = transport.IsReliable };
            var id = new StunTransactionKey(message.TransactionId);
            lock (_sync)
                _transactions[id] = transaction;

            try
            {
                if (transport.IsReliable)
                {
                    await transport.SendAsync(bytes, cancellationToken).ConfigureAwait(false);
                    var done = await Task.WhenAny(transaction.Completion.Task, Task.Delay(_options.ReliableTimeout, cancellationToken)).ConfigureAwait(false);
                    if (done == transaction.Completion.Task)
                        return await transaction.Completion.Task.ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    return null;
                }

                TimeSpan rto = _options.InitialRetransmissionTimeout;
                for (int sent = 1; sent <= _options.MaxTransmissions; sent++)
                {
                    await transport.SendAsync(bytes, cancellationToken).ConfigureAwait(false);
                    TimeSpan wait = sent == _options.MaxTransmissions
                        ? TimeSpan.FromTicks(_options.InitialRetransmissionTimeout.Ticks * _options.LastWaitMultiplier)
                        : rto;
                    var done = await Task.WhenAny(transaction.Completion.Task, Task.Delay(wait, cancellationToken)).ConfigureAwait(false);
                    if (done == transaction.Completion.Task)
                        return await transaction.Completion.Task.ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    rto = TimeSpan.FromTicks(rto.Ticks * 2);
                }

                // every answer discarded of its integrity: that, rather than no answer (RFC 8489 9.2.5)
                if (transaction.IntegrityViolated)
                    throw new StunException("No response was of integrity of the credentials.");
                return null;
            }
            finally
            {
                lock (_sync)
                    _transactions.Remove(id);
            }
        }

        private void OnMessageReceived(object sender, StunMessageEventArgs e)
        {
            var message = e.Message;
            if (message.Class == StunMessageClass.Indication)
            {
                if (!message.HasFingerprint || message.VerifyFingerprint())
                    IndicationReceived?.Invoke(this, e);
                return;
            }
            if (message.Class != StunMessageClass.SuccessResponse && message.Class != StunMessageClass.ErrorResponse)
                return;
            Transaction transaction;
            lock (_sync)
            {
                if (!_transactions.TryGetValue(new StunTransactionKey(message.TransactionId), out transaction))
                    return;
            }
            if (message.HasFingerprint && !message.VerifyFingerprint())
                return;

            if (transaction.Key != null && !message.VerifyAnyIntegrity(transaction.Key))
            {
                int? code = message.Class == StunMessageClass.ErrorResponse ? message.Error?.Code : null;

                // a challenge, or a new nonce, is not of the credentials it asks for
                if (code == StunErrorCode.Unauthorized || code == StunErrorCode.StaleNonce)
                {
                    transaction.Completion.TrySetResult(message);
                    return;
                }
                // a 400 of no integrity is as if it never came: retransmissions go on (RFC 8489 9.2.5)
                if (code == StunErrorCode.BadRequest && !message.HasIntegrity && !message.HasIntegritySha256)
                    return;

                if (transaction.Reliable)
                    transaction.Completion.TrySetException(new StunException("The response is not of integrity of the credentials.", message));
                else
                    transaction.IntegrityViolated = true;
                return;
            }
            transaction.Completion.TrySetResult(message);
        }

        private void OnClosed(object sender, Exception error)
        {
            List<Transaction> pending;
            lock (_sync)
                pending = _transactions.Values.ToList();
            foreach (var transaction in pending)
                transaction.Completion.TrySetException(new StunException("The connection to the server ended.", null, error));
            if (sender is StunTransport)
                Closed?.Invoke(this, error);
        }

        private void OnDataReceived(object sender, StunDataEventArgs e) => DataReceived?.Invoke(this, e);

        #endregion // Transactions

        #region Credentials

        // a 401: the realm and nonce to send the request again of; false of none to send it again of (RFC 8489 9.2.5)
        private bool TakeChallenge(StunMessage response, bool sentCredentials)
        {
            if (_options.Username == null || _options.Password == null)
                return false;
            string realm = response.Realm;
            string nonce = response.Nonce;
            if (realm == null || nonce == null)
                return false;
            var features = StunCredentials.GetSecurityFeatures(nonce) ?? StunSecurityFeatures.None;
            var algorithmsAttribute = response.GetAttribute(StunAttributeType.PasswordAlgorithms);
            if ((features & StunSecurityFeatures.PasswordAlgorithms) != 0 && algorithmsAttribute == null)
                return false;

            lock (_sync)
            {
                // of the same username, realm and password, refused again
                if (sentCredentials && realm == _realm)
                    return false;

                var algorithm = StunPasswordAlgorithm.Md5;
                if (algorithmsAttribute != null)
                {
                    var listed = response.PasswordAlgorithms;
                    ushort? first = _options.PreferSha256 && listed.Contains((ushort)StunPasswordAlgorithm.Sha256)
                        ? (ushort)StunPasswordAlgorithm.Sha256
                        : listed.Cast<ushort?>().FirstOrDefault(a => a == (ushort)StunPasswordAlgorithm.Md5 || a == (ushort)StunPasswordAlgorithm.Sha256);
                    if (first == null)
                        return false;
                    algorithm = (StunPasswordAlgorithm)first.Value;
                }

                _realm = realm;
                _nonce = nonce;
                _passwordAlgorithms = algorithmsAttribute?.Value;
                _passwordAlgorithm = algorithm;
                _useUserhash = (features & StunSecurityFeatures.UsernameAnonymity) != 0;
                _key = StunCredentials.LongTermKey(_options.Username, realm, _options.Password, algorithm);
                IsAuthenticated = false;
                return true;
            }
        }

        // a 438: the new nonce, and the realm, if the server changed it
        private bool TakeStaleNonce(StunMessage response)
        {
            string nonce = response.Nonce;
            if (nonce == null)
                return false;
            var features = StunCredentials.GetSecurityFeatures(nonce) ?? StunSecurityFeatures.None;
            if ((features & StunSecurityFeatures.PasswordAlgorithms) != 0 && !response.HasAttribute(StunAttributeType.PasswordAlgorithms))
                return false;

            lock (_sync)
            {
                _nonce = nonce;
                string realm = response.Realm;
                if (realm != null && realm != _realm)
                {
                    _realm = realm;
                    _key = StunCredentials.LongTermKey(_options.Username, realm, _options.Password, _passwordAlgorithm);
                }
                return true;
            }
        }

        private void ForgetCredentials()
        {
            lock (_sync)
            {
                _realm = null;
                _nonce = null;
                _key = null;
                _passwordAlgorithms = null;
                _useUserhash = false;
                IsAuthenticated = false;
            }
        }

        #endregion // Credentials

        #region Servers

        private void Attach(StunTransport transport)
        {
            _transport = transport;
            transport.MessageReceived += OnMessageReceived;
            transport.DataReceived += OnDataReceived;
            transport.Closed += OnClosed;
        }

        // to another server: of its own credentials, which it asks for
        private void Replace(StunTransport transport, bool owned)
        {
            var old = _transport;
            if (transport != old)
            {
                old.MessageReceived -= OnMessageReceived;
                old.DataReceived -= OnDataReceived;
                old.Closed -= OnClosed;
                if (_ownsTransport)
                    old.Dispose();
                _ownsTransport = owned;
                Attach(transport);
            }
            ForgetCredentials();
        }

        private async Task<bool> RedirectAsync(IPEndPoint server, string domain, CancellationToken cancellationToken)
        {
            StunTransport transport;
            try
            {
                transport = await _transport.RedirectAsync(server, domain, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (IsConnectionFailure(e))
            {
                return false;
            }
            if (transport == null)
                return false;
            Replace(transport, transport == _transport ? _ownsTransport : true);
            return true;
        }

        // the next of the URI's servers, of a transport like this one; false of none left
        private async Task<bool> NextServerAsync(CancellationToken cancellationToken)
        {
            while (_servers.Count > 0)
            {
                var server = _servers[0];
                _servers.RemoveAt(0);
                StunTransport transport;
                try
                {
                    transport = _transport is StunUdpTransport ? new StunUdpTransport(server)
                        : _transport is StunDtlsTransport ? await StunDtlsTransport.ConnectAsync(server, _tlsHost, _options.CertificateValidation, cancellationToken).ConfigureAwait(false)
                        : await StunStreamTransport.ConnectAsync(server, _tlsHost, _options.CertificateValidation, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception e) when (IsConnectionFailure(e))
                {
                    continue;
                }
                Replace(transport, true);
                return true;
            }
            return false;
        }

        #endregion // Servers

        public void Dispose()
        {
            OnClosed(this, null);
            if (_transport == null)
                return;
            _transport.MessageReceived -= OnMessageReceived;
            _transport.DataReceived -= OnDataReceived;
            _transport.Closed -= OnClosed;
            if (_ownsTransport)
                _transport.Dispose();
        }

        #region Binding

        /// <summary>
        /// The endpoints of a server's URI, in the order to try them: of an IP address, it; of a host name and a port, its
        /// addresses; of a host name alone, those of its SRV records (RFC 8489 8.1) - "_stun._udp", "_stuns._tcp", "_turn._tcp"
        /// and so on - else its addresses of the default port. Both IPv4 and IPv6 ones, as a dual-stack client is to try. Of a
        /// transport given, of its SRV records rather than the URI's: "udp" of a "stuns" URI, of DTLS.
        /// </summary>
        public static async Task<List<IPEndPoint>> ResolveAllAsync(StunUri uri, TimeSpan dnsTimeout, CancellationToken cancellationToken = default, string transportProtocol = null)
        {
            var address = uri.Address;
            if (address != null)
                return new List<IPEndPoint> { new IPEndPoint(address, uri.EffectivePort) };

            if (!uri.Port.HasValue)
            {
                var records = await DnsSrv.QueryAsync($"_{uri.Scheme}._{transportProtocol ?? uri.TransportProtocol}.{uri.Host}", dnsTimeout, cancellationToken).ConfigureAwait(false);
                var endPoints = new List<IPEndPoint>();
                foreach (var record in records)
                {
                    foreach (var target in await GetHostAddressesAsync(record.Target).ConfigureAwait(false))
                        endPoints.Add(new IPEndPoint(target, record.Port));
                }
                if (endPoints.Count > 0)
                    return endPoints;
            }

            return (await GetHostAddressesAsync(uri.Host).ConfigureAwait(false)).Select(a => new IPEndPoint(a, uri.EffectivePort)).ToList();
        }

        private static async Task<IPAddress[]> GetHostAddressesAsync(string host)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                return addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork || a.AddressFamily == AddressFamily.InterNetworkV6).ToArray();
            }
            catch (SocketException)
            {
                return new IPAddress[0];
            }
        }

        /// <summary>
        /// The endpoint of a STUN server of "host", "host:port", "stun:host:port" or "[ipv6]:port", of the address family given:
        /// of a host name alone, of its SRV records, else of the default port. Null of one that does not resolve.
        /// </summary>
        public static async Task<IPEndPoint> ResolveAsync(string server, AddressFamily family = AddressFamily.InterNetwork)
        {
            if (!StunUri.TryParse(server, out StunUri uri))
                return null;
            var endPoints = await ResolveAllAsync(uri, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            return endPoints.FirstOrDefault(e => e.AddressFamily == family);
        }

        /// <summary>A Binding request (RFC 8489 6.1), of a new transaction ID.</summary>
        public static StunMessage CreateBindingRequest(string software = null)
        {
            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request);
            if (software != null)
                request.AddString(StunAttributeType.Software, software);
            return request;
        }

        /// <summary>
        /// The address a server sees a Binding request come from: of its XOR-MAPPED-ADDRESS, or of a server of RFC 3489, its
        /// MAPPED-ADDRESS. Null of a message that is no success response, or has neither.
        /// </summary>
        public static IPEndPoint GetMappedAddress(StunMessage response)
        {
            if (response == null || response.Class != StunMessageClass.SuccessResponse)
                return null;
            return response.GetXorAddress() ?? response.MappedAddress;
        }

        /// <summary>
        /// Sends a Binding request from a socket of its own to the server and waits for its answer, retransmitting it (RFC 8489
        /// 6.2.1) until the time given is up. The mapped address; null of no answer.
        /// </summary>
        public static async Task<IPEndPoint> GetMappedAddressAsync(IPEndPoint server, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            using (var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                socket.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
                return await GetMappedAddressAsync(socket, server, timeout, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Sends a Binding request from a bound socket - one nothing else reads at the time - to the server and waits for its
        /// answer. The mapped address; null of no answer.
        /// </summary>
        public static async Task<IPEndPoint> GetMappedAddressAsync(Socket socket, IPEndPoint server, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            var request = CreateBindingRequest();
            byte[] bytes = request.ToBytes();
            byte[] buffer = new byte[1500];
            DateTime deadline = DateTime.UtcNow + timeout;
            TimeSpan rto = TimeSpan.FromMilliseconds(250);

            // one receive at a time, kept across the retransmissions: one left behind would take a datagram of its own
            Task<SocketReceiveFromResult> receive = null;
            var any = new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
            while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
            {
                socket.SendTo(bytes, server);
                TimeSpan wait = TimeSpan.FromTicks(Math.Min(rto.Ticks, (deadline - DateTime.UtcNow).Ticks));
                DateTime until = DateTime.UtcNow + wait;
                while (DateTime.UtcNow < until)
                {
                    receive ??= socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any);
                    TimeSpan left = until - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero)
                        break;
                    var completed = await Task.WhenAny(receive, Task.Delay(left, cancellationToken)).ConfigureAwait(false);
                    if (completed != receive)
                        break;

                    SocketReceiveFromResult result;
                    try
                    {
                        result = await receive.ConfigureAwait(false);
                    }
                    catch (SocketException)
                    {
                        // an ICMP port unreachable of a request before, reported by Windows as a reset
                        receive = null;
                        continue;
                    }
                    receive = null;

                    var response = StunMessage.Parse(buffer, 0, result.ReceivedBytes);
                    if (response != null && response.IsTransaction(request) && (!response.HasFingerprint || response.VerifyFingerprint()))
                        return GetMappedAddress(response);
                }
                rto = TimeSpan.FromTicks(rto.Ticks * 2);
            }
            return null;
        }

        #endregion // Binding
    }
}
