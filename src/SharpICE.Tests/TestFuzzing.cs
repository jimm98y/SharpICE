using SharpStun;
using SharpTurn;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// Mutation fuzzing of what the network hands the libraries: each parser of STUN, TURN, ICE candidates, URIs and DNS fed
    /// mutants of well formed inputs, of no exception to escape it; and each listener - STUN and TURN over UDP, TCP, DTLS
    /// and TLS, of each stack, an ICE agent's sockets and passive candidates, and its mDNS responder - fed mutants and noise,
    /// then still answering what is well formed. Of a fixed seed, repeatable; of SHARPICE_FUZZ_ITERATIONS, deeper.
    /// </summary>
    [TestClass]
    public class TestFuzzing
    {
        private static readonly int Iterations = int.TryParse(Environment.GetEnvironmentVariable("SHARPICE_FUZZ_ITERATIONS"), out int n) ? n : 20000;
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        #region Mutator

        /// <summary>Mutants of the seeds, of what breaks parsers: bits flipped, bytes set, lengths of extremes, truncations, splices.</summary>
        private sealed class Mutator
        {
            private readonly Random _random;
            private readonly List<byte[]> _seeds;

            public Mutator(int seed, IEnumerable<byte[]> seeds)
            {
                _random = new Random(seed);
                _seeds = seeds.Where(s => s.Length > 0).ToList();
            }

            public byte[] Next()
            {
                if (_random.Next(16) == 0)
                {
                    // noise alone, of a length of anything up to a datagram's
                    byte[] noise = new byte[_random.Next(0, 1500)];
                    _random.NextBytes(noise);
                    return noise;
                }
                var data = new List<byte>(_seeds[_random.Next(_seeds.Count)]);
                int mutations = 1 + _random.Next(4);
                for (int m = 0; m < mutations; m++)
                {
                    if (data.Count == 0)
                        data.Add((byte)_random.Next(256));
                    int at = _random.Next(data.Count);
                    switch (_random.Next(9))
                    {
                        case 0:
                            data[at] ^= (byte)(1 << _random.Next(8));
                            break;
                        case 1:
                            data[at] = (byte)_random.Next(256);
                            break;
                        case 2:
                            // a 16 bit length of an extreme: 0, 1, the most, past what there is
                            if (at + 1 < data.Count)
                            {
                                ushort value = new ushort[] { 0, 1, 3, 4, 0x7FFF, 0xFFFF, (ushort)data.Count, (ushort)(data.Count + 4) }[_random.Next(8)];
                                data[at] = (byte)(value >> 8);
                                data[at + 1] = (byte)value;
                            }
                            break;
                        case 3:
                            data.RemoveRange(at, data.Count - at);
                            break;
                        case 4:
                            data.RemoveRange(at, Math.Min(data.Count - at, 1 + _random.Next(8)));
                            break;
                        case 5:
                            data.InsertRange(at, Enumerable.Range(0, 1 + _random.Next(16)).Select(_ => (byte)_random.Next(256)));
                            break;
                        case 6:
                            // a chunk of its own repeated
                            int length = Math.Min(data.Count - at, 1 + _random.Next(32));
                            data.InsertRange(at, data.GetRange(at, length));
                            break;
                        case 7:
                            // spliced of another seed
                            var other = _seeds[_random.Next(_seeds.Count)];
                            int from = _random.Next(other.Length);
                            data.InsertRange(at, other.Skip(from).Take(1 + _random.Next(64)));
                            break;
                        default:
                            data[at] = new byte[] { 0x00, 0xFF, 0x7F, 0x80, 0xC0, 0x40 }[_random.Next(6)];
                            break;
                    }
                }
                return data.ToArray();
            }

            public string NextText(IReadOnlyList<string> seeds)
            {
                var text = new StringBuilder(seeds[_random.Next(seeds.Count)]);
                int mutations = 1 + _random.Next(4);
                for (int m = 0; m < mutations && text.Length > 0; m++)
                {
                    int at = _random.Next(text.Length);
                    switch (_random.Next(6))
                    {
                        case 0: text[at] = (char)_random.Next(32, 127); break;
                        case 1: text.Remove(at, Math.Min(text.Length - at, 1 + _random.Next(8))); break;
                        case 2: text.Insert(at, new[] { " ", "  ", "-1", "99999999999999999999", "4294967296", ":", ".local", "\0", "é", "typ", "tcptype" }[_random.Next(11)]); break;
                        case 3: text.Length = at; break;
                        case 4: text.Insert(at, new string((char)_random.Next(32, 127), 1 + _random.Next(300))); break;
                        default: text[at] = ' '; break;
                    }
                }
                return text.ToString();
            }
        }

        // the first input of a parser that threw, of its exception: what the test fails of
        private static void Fuzz(string what, Func<int, byte[]> input, Action<byte[]> parse)
        {
            for (int i = 0; i < Iterations; i++)
            {
                byte[] data = input(i);
                try
                {
                    parse(data);
                }
                catch (Exception ex)
                {
                    Assert.Fail($"{what} threw {ex.GetType().Name} at {i} of {BitConverter.ToString(data).Replace("-", "")}: {ex}");
                }
            }
        }

        #endregion

        #region Seeds

        private static readonly byte[] Key = StunMessage.ShortTermKey("password");
        private static readonly byte[] LongTermKey = StunCredentials.LongTermKey("user", "example.org", "secret", StunPasswordAlgorithm.Sha256);

        private static IEnumerable<byte[]> StunSeeds()
        {
            var peer4 = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 5000);
            var peer6 = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 6000);
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.Request).ToBytes();
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.Request)
                .AddString(StunAttributeType.Username, "abcd:efgh").AddUInt32(StunAttributeType.Priority, 0x6E7F00FF)
                .AddUInt64(StunAttributeType.IceControlling, 0x0102030405060708).AddAttribute(StunAttributeType.UseCandidate, new byte[0])
                .ToBytes(Key, true);
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse).AddXorAddress(peer4).AddXorAddress(peer6, StunAttributeType.XorMappedAddress).ToBytes(Key, true);
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse).AddError(401, "Unauthorized")
                .AddString(StunAttributeType.Realm, "example.org").AddString(StunAttributeType.Nonce, "obMatJos2AAAB" + new string('x', 20))
                .AddPasswordAlgorithms(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5).ToBytes();
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse).AddError(300, "Try Alternate")
                .AddAddress(peer4, StunAttributeType.AlternateServer).AddString(StunAttributeType.AlternateDomain, "stun.example.org").ToBytes();
            yield return new StunMessage(StunMethod.Binding, StunMessageClass.ErrorResponse).AddError(420, "Unknown").AddUnknownAttributes(new ushort[] { 0x0031, 0x7FFF }).ToBytes();
            yield return new StunMessage(TurnMethod.Allocate, StunMessageClass.Request).AddRequestedTransport()
                .AddAddressFamily(TurnAttributeType.AdditionalAddressFamily, AddressFamily.InterNetworkV6).AddLifetime(TimeSpan.FromMinutes(10)).AddEvenPort(true)
                .AddString(StunAttributeType.Username, "user").AddString(StunAttributeType.Realm, "example.org").AddString(StunAttributeType.Nonce, "nonce")
                .ToBytes(LongTermKey, StunIntegrity.Sha256, true);
            yield return new StunMessage(TurnMethod.Allocate, StunMessageClass.SuccessResponse).AddXorAddress(peer4, TurnAttributeType.XorRelayedAddress)
                .AddXorAddress(peer6, TurnAttributeType.XorRelayedAddress).AddLifetime(TimeSpan.FromMinutes(10)).AddAddressError(AddressFamily.InterNetworkV6, 440, "Not Supported")
                .AddAttribute(TurnAttributeType.ReservationToken, new byte[8]).AddXorAddress(peer4).ToBytes();
            yield return new StunMessage(TurnMethod.CreatePermission, StunMessageClass.Request).AddXorAddress(peer4, TurnAttributeType.XorPeerAddress).AddXorAddress(peer6, TurnAttributeType.XorPeerAddress).ToBytes();
            yield return new StunMessage(TurnMethod.ChannelBind, StunMessageClass.Request).AddChannelNumber(0x4000).AddXorAddress(peer4, TurnAttributeType.XorPeerAddress).ToBytes();
            yield return new StunMessage(TurnMethod.Connect, StunMessageClass.Request).AddXorAddress(peer4, TurnAttributeType.XorPeerAddress).ToBytes();
            yield return new StunMessage(TurnMethod.ConnectionBind, StunMessageClass.Request).AddConnectionId(0x12345678).ToBytes();
            yield return new StunMessage(TurnMethod.ConnectionAttempt, StunMessageClass.Indication).AddConnectionId(1).AddXorAddress(peer4, TurnAttributeType.XorPeerAddress).ToBytes(null, false);
            byte[] data = Encoding.UTF8.GetBytes("relayed data");
            byte[] indication = new byte[TurnIndication.Size(peer4, data.Length, true)];
            TurnIndication.Write(indication, TurnMethod.Send, peer4, data, true);
            yield return indication;
            yield return TurnChannelData.Create(0x4000, data, 0, data.Length, false);
            yield return TurnChannelData.Create(0x4FFF, data, 0, data.Length, true);
        }

        #endregion

        #region Parsers

        [TestMethod]
        public void ParsesMutantsOfStunAndTurnMessagesOfNoException()
        {
            var mutator = new Mutator(1, StunSeeds());
            Fuzz("StunMessage.Parse", _ => mutator.Next(), data =>
            {
                StunMessage.IsStun(data);
                var message = StunMessage.Parse(data, 0, data.Length);
                if (message == null)
                    return;
                // every reading of it, as a client, a server or an agent reads one
                _ = message.Error;
                _ = message.AlternateServers.ToList();
                _ = message.AlternateDomain;
                _ = message.Priority;
                message.GetXorAddress();
                message.GetXorAddresses(TurnAttributeType.XorPeerAddress);
                message.GetXorAddresses(TurnAttributeType.XorRelayedAddress);
                message.GetString(StunAttributeType.Username);
                message.GetString(StunAttributeType.Realm);
                message.GetString(StunAttributeType.Nonce);
                message.GetUInt32(StunAttributeType.Priority);
                message.GetUInt64(StunAttributeType.IceControlling);
                message.GetUnknownComprehensionRequired(TurnAttributeType.IsKnownOfTurn);
                message.VerifyFingerprint();
                message.VerifyIntegrity(Key);
                message.VerifyIntegritySha256(LongTermKey);
                message.VerifyAnyIntegrity(Key);
                _ = message.PasswordAlgorithms;
                _ = message.UnknownAttributeTypes;
                message.GetRequestedTransport();
                message.GetAddressFamily(TurnAttributeType.RequestedAddressFamily);
                message.GetAddressFamily(TurnAttributeType.AdditionalAddressFamily);
                message.GetEvenPort();
                message.GetChannelNumber();
                message.GetLifetime();
                message.GetAddressError();
                message.GetIcmp();
                message.GetConnectionId();
                // and written again, as a server answers of one
                message.ToBytes(Key, true);
            });
        }

        [TestMethod]
        public void ReadsMutantsOfChannelDataOfNoException()
        {
            var mutator = new Mutator(2, StunSeeds());
            Fuzz("TurnChannelData.TryRead", _ => mutator.Next(), data =>
            {
                if (TurnChannelData.TryRead(data, 0, data.Length, out _, out int offset, out int length))
                    Assert.IsTrue(offset >= 0 && length >= 0 && offset + length <= data.Length, "of the buffer alone");
                if (data.Length >= 4)
                    StunFraming.IsChannelData(data[0]);
            });
        }

        [TestMethod]
        public void ParsesMutantsOfCandidatesAndUrisOfNoException()
        {
            var candidates = new[]
            {
                "candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host generation 0 ufrag abcd network-id 1 network-cost 10",
                "a=candidate:842163049 1 udp 1677729535 203.0.113.7 61234 typ srflx raddr 192.168.1.10 rport 50000 generation 0",
                "candidate:1340066476 1 tcp 1518280447 192.168.1.10 9 typ host tcptype active generation 0",
                "candidate:3 1 tcp 1518214911 [2001:db8::1] 50001 typ host tcptype passive",
                "candidate:4 1 udp 41885695 198.51.100.9 3478 typ relay raddr 203.0.113.7 rport 61234",
                "candidate:5 1 udp 2122260223 2d3a0f5c-1234-4bcd-9e8f-0123456789ab.local 50002 typ host generation 0",
                "candidate:l1 1 tls 1442840575 127.0.0.1 50000 typ host tcptype passive",
            };
            var uris = new[]
            {
                "stun:stun.l.google.com:19302", "stuns:stun.example.org", "turn:198.51.100.9:3478?transport=udp",
                "turns:turn.example.org:5349?transport=tcp", "turn:[2001:db8::1]:3478", "stun:127.0.0.1",
            };
            var mutator = new Mutator(3, new[] { new byte[1] });
            var texts = new List<string>();
            Fuzz("IceCandidate.Parse", i =>
            {
                string text = mutator.NextText(candidates);
                texts.Add(text);
                return Encoding.UTF8.GetBytes(text);
            }, data =>
            {
                var candidate = IceCandidate.Parse(Encoding.UTF8.GetString(data));
                if (candidate == null)
                    return;
                _ = candidate.EndPoint;
                _ = candidate.TcpType;
                _ = candidate.LocalPreference;
                _ = candidate.IsStream;
                IceCandidate.Parse(candidate.ToString());
            });
            Fuzz("StunUri.Parse", _ => Encoding.UTF8.GetBytes(mutator.NextText(uris)), data =>
            {
                try
                {
                    var uri = StunUri.Parse(Encoding.UTF8.GetString(data));
                    _ = uri.Address;
                    _ = uri.EffectivePort;
                    _ = uri.TransportProtocol;
                }
                catch (FormatException)
                {
                    // what it is to throw of a URI that is not one
                }
            });
        }

        [TestMethod]
        public void ParsesMutantsOfDnsResponsesOfNoException()
        {
            // an SRV response of two records and an A one, of names compressed of pointers to the question's
            var response = new List<byte>(DnsMessage.BuildQuery(0x1234, "_stun._udp.example.org", DnsMessage.TypeSrv, DnsMessage.ClassIn, true));
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 2;
            response[11] = 1;
            foreach (ushort port in new ushort[] { 3478, 3479 })
            {
                response.AddRange(new byte[] { 0xC0, 0x0C, 0, 33, 0, 1, 0, 0, 0, 60 });
                var target = new List<byte> { 0, 10, 0, 5, (byte)(port >> 8), (byte)port, 4 };
                target.AddRange(Encoding.ASCII.GetBytes("stun"));
                target.AddRange(new byte[] { 0xC0, 0x17 });
                response.AddRange(new byte[] { 0, (byte)target.Count });
                response.AddRange(target);
            }
            response.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 });
            // a pointer to itself, and one past the message: of a loop and of what is not there
            var loop = response.ToArray();
            var self = (byte[])loop.Clone();
            self[12] = 0xC0;
            self[13] = 12;
            var mutator = new Mutator(4, new[] { loop, self });
            Fuzz("DnsMessage.ParseResponse", _ => mutator.Next(), data =>
            {
                var records = DnsMessage.ParseResponse(data, data.Length, null, out _);
                if (records != null)
                {
                    foreach (var record in records)
                        record.GetAddress(data);
                }
                DnsSrv.ParseResponse(data, data.Length, 0x1234);
            });
        }

        #endregion

        #region Listeners

        private static X509Certificate2 CreateCertificate()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
#pragma warning disable SYSLIB0057
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        private static StunClientOptions ClientOptions() => new StunClientOptions
        {
            Username = "user",
            Password = "secret",
            CertificateValidation = (s, c, ch, e) => true,
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
        };

        // the first datagram a client of DTLS of the stack sends - its ClientHello - of a socket that answers nothing
        private static async Task<byte[]> ClientHelloOf(IDtlsStack stack)
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            // of a machine busy of the other fuzzers: long enough for any
            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var connecting = StunDtlsTransport.ConnectAsync((IPEndPoint)listener.LocalEndPoint, "localhost", (s, c, ch, e) => true, stack, cancel.Token);
            byte[] buffer = new byte[4096];
            listener.ReceiveTimeout = 15000;
            int count = listener.Receive(buffer);
            cancel.Cancel();
            try
            {
                await connecting;
            }
            catch (Exception ex) when (ex is IOException || ex is OperationCanceledException)
            {
            }
            return buffer.Take(count).ToArray();
        }

        // the first bytes a client of TLS of the stack sends - its ClientHello - of a listener that answers nothing
        private static async Task<byte[]> TlsClientHelloOf(ITlsStack stack)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var connecting = StunStreamTransport.ConnectAsync((IPEndPoint)listener.LocalEndpoint, "localhost", (s, c, ch, e) => true, stack, cancel.Token);
                using var accepted = await listener.AcceptTcpClientAsync();
                byte[] buffer = new byte[4096];
                var stream = accepted.GetStream();
                stream.ReadTimeout = 15000;
                int count = stream.Read(buffer, 0, buffer.Length);
                cancel.Cancel();
                try
                {
                    await connecting;
                }
                catch (Exception ex) when (ex is IOException || ex is OperationCanceledException || ex is ObjectDisposedException)
                {
                }
                return buffer.Take(count).ToArray();
            }
            finally
            {
                listener.Stop();
            }
        }

        private static int ListenerIterations => Math.Max(200, Iterations / 20);

        private static void SendDatagrams(IPEndPoint to, Mutator mutator, int count)
        {
            // of many sources, as of attackers of spoofed addresses, each of a socket of its own of a few
            var sockets = Enumerable.Range(0, 16).Select(_ =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                return socket;
            }).ToList();
            try
            {
                for (int i = 0; i < count; i++)
                {
                    byte[] datagram = mutator.Next();
                    if (datagram.Length == 0 || datagram.Length > 65000)
                        continue;
                    sockets[i % sockets.Count].SendTo(datagram, to);
                    // a pause now and then, that the loopback drops none of a burst
                    if (i % 64 == 63)
                        Thread.Sleep(1);
                }
            }
            finally
            {
                sockets.ForEach(s => s.Dispose());
            }
        }

        private static async Task SendStreams(IPEndPoint to, Mutator mutator, int connections, int writes)
        {
            for (int c = 0; c < connections; c++)
            {
                using var client = new TcpClient(AddressFamily.InterNetwork);
                try
                {
                    await client.ConnectAsync(to.Address, to.Port);
                    var stream = client.GetStream();
                    for (int w = 0; w < writes; w++)
                    {
                        byte[] bytes = mutator.Next();
                        await stream.WriteAsync(bytes, 0, bytes.Length);
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException)
                {
                    // closed of the server, of what it would not take: as it is to
                }
            }
        }

        [TestMethod]
        public async Task StunAndTurnListenersSurviveMutants()
        {
            using var certificate = CreateCertificate();
            using var server = new TurnServer(new TurnServerOptions
            {
                Stun = new StunServerOptions
                {
                    Realm = "example.org",
                    Users = new Dictionary<string, string> { ["user"] = "secret" },
                    AuthenticateBinding = false,
                    Certificate = certificate,
                    FirstMessageTimeout = TimeSpan.FromSeconds(2),
                },
                RelayAddress = IPAddress.Loopback,
                AllowPeer = peer => true,
            });
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));

            // an allocation of a real client's, whose 5-tuple the mutants are not of
            using var turn = new TurnClient(ClientOptions());
            await turn.ConnectAsync("turn:127.0.0.1:" + udp.Port);
            await turn.AllocateAsync();

            var mutator = new Mutator(5, StunSeeds().Concat(new[] { await TlsClientHelloOf(TlsStacks.SharpDtls), await TlsClientHelloOf(TlsStacks.BouncyCastle) }));
            SendDatagrams(udp, mutator, ListenerIterations);
            await SendStreams(tcp, mutator, 50, 20);
            await SendStreams(tls, mutator, 50, 3);

            // what is well formed is still answered, of each transport, and the allocation is still the client's
            using (var client = new StunClient(ClientOptions()))
            {
                await client.ConnectAsync("stun:127.0.0.1:" + udp.Port);
                Assert.IsNotNull(await client.GetMappedAddressAsync(), "UDP");
            }
            using (var client = new StunClient(await StunStreamTransport.ConnectAsync(tcp), ClientOptions()))
                Assert.IsNotNull(await client.GetMappedAddressAsync(), "TCP");
            using (var client = new StunClient(ClientOptions()))
            {
                await client.ConnectAsync("stuns:localhost:" + tls.Port);
                Assert.IsNotNull(await client.GetMappedAddressAsync(), "TLS");
            }
            await turn.RefreshAsync();
            Assert.IsTrue(turn.IsAllocated);
            Assert.AreEqual(1, server.AllocationCount, "of no allocation of the mutants'");
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        public async Task DtlsListenersSurviveMutants(string stack)
        {
            var dtlsStack = stack == "bc" ? DtlsStacks.BouncyCastle : DtlsStacks.SharpDtls;
            using var certificate = CreateCertificate();
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, DtlsStack = dtlsStack, DtlsIdleTimeout = TimeSpan.FromSeconds(2) });
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));

            var mutator = new Mutator(6, new[] { await ClientHelloOf(DtlsStacks.SharpDtls), await ClientHelloOf(DtlsStacks.BouncyCastle) }.Concat(StunSeeds()));
            SendDatagrams(dtls, mutator, ListenerIterations);

            var options = ClientOptions();
            options.UseDtls = true;
            options.DtlsStack = dtlsStack;
            using var client = new StunClient(options);
            await client.ConnectAsync("stuns:localhost:" + dtls.Port);
            Assert.IsNotNull(await client.GetMappedAddressAsync(), "a client of DTLS answered still");
        }

        [TestMethod]
        public async Task AnIceAgentSurvivesMutants()
        {
            var options = new IceAgentOptions
            {
                Role = IceRole.Controlled,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                IncludeTcp = true,
                IncludeTls = true,
                MdnsCandidates = true,
                TcpCheckTimeout = TimeSpan.FromSeconds(2),
            };
            using var agent = new IceAgent(options) { MdnsResponderEndPoint = new IPEndPoint(IPAddress.Loopback, 0) };
            await agent.GatherCandidatesAsync();
            using var peer = new IceAgent(new IceAgentOptions
            {
                Role = IceRole.Controlling,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
            });
            await peer.GatherCandidatesAsync();
            agent.SetRemoteCredentials(peer.LocalUfrag, peer.LocalPassword);
            peer.SetRemoteCredentials(agent.LocalUfrag, agent.LocalPassword);

            // checks of the agent's credentials, and of others', and what else a socket of ICE gets
            var key = StunMessage.ShortTermKey(agent.LocalPassword);
            var seeds = StunSeeds().Concat(new[]
            {
                new StunMessage(StunMethod.Binding, StunMessageClass.Request).AddString(StunAttributeType.Username, agent.LocalUfrag + ":" + peer.LocalUfrag)
                    .AddUInt32(StunAttributeType.Priority, 1).AddUInt64(StunAttributeType.IceControlling, 5).AddAttribute(StunAttributeType.UseCandidate, new byte[0]).ToBytes(key, true),
                new StunMessage(StunMethod.Binding, StunMessageClass.Indication).ToBytes(null, true),
            }).ToList();
            var mutator = new Mutator(7, seeds);
            var udp = agent.LocalCandidates.First(c => c.IsUdp && c.Type == IceCandidateType.Host);
            // of mDNS candidates, of names: their sockets of the loopback, of the port told of
            var udpEndPoint = new IPEndPoint(IPAddress.Loopback, udp.Port);
            SendDatagrams(udpEndPoint, mutator, ListenerIterations);
            foreach (var passive in agent.LocalCandidates.Where(c => c.IsStream && c.TcpType == IceCandidate.TcpPassive))
            {
                // RFC 4571 frames of mutants, and of lengths of their own
                var framed = new Mutator(8, seeds.Select(s => new byte[] { (byte)(s.Length >> 8), (byte)s.Length }.Concat(s).ToArray()));
                await SendStreams(new IPEndPoint(IPAddress.Loopback, passive.Port), framed, 20, 10);
            }
            if (agent.MdnsResponder != null)
            {
                var query = DnsMessage.BuildQuery(0, udp.Address, DnsMessage.TypeA, DnsMessage.ClassIn, false);
                SendDatagrams(agent.MdnsResponder.EndPoint, new Mutator(9, new[] { query }), ListenerIterations);
            }
            Assert.IsTrue(agent.RemoteCandidates.Count <= options.MaxRemoteCandidates, "of no more remote candidates than it takes");

            // the agent connects still, of the peer's checks of its credentials
            foreach (var candidate in agent.LocalCandidates.Where(c => c.IsUdp))
                peer.AddRemoteCandidate(new IceCandidate { Foundation = candidate.Foundation, Component = 1, Transport = "udp", Priority = candidate.Priority, Address = "127.0.0.1", Port = candidate.Port, Type = IceCandidateType.Host });
            foreach (var candidate in peer.LocalCandidates)
                agent.AddRemoteCandidate(candidate);
            agent.Start();
            peer.Start();
            var deadline = DateTime.UtcNow + Timeout;
            while (!(agent.SelectedPair?.Nominated == true && peer.SelectedPair?.Nominated == true) && DateTime.UtcNow < deadline)
                await Task.Delay(20);
            Assert.IsTrue(agent.SelectedPair?.Nominated == true && peer.SelectedPair?.Nominated == true, $"connected still: {agent.State} {peer.State}");
        }

        #endregion
    }
}
