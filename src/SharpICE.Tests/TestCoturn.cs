using SharpStun;
using SharpTurn;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// SharpTurn's client of coturn's server, of one given of the environment - inconclusive of none:
    /// <list type="bullet">
    /// <item><c>SHARPICE_COTURN_URI</c>: "turn:host:3478" (UDP and TCP of it are tried)</item>
    /// <item><c>SHARPICE_COTURN_TLS_URI</c>: "turns:host:5349", of a host name: TLS over each TLS stack, and DTLS over each
    /// DTLS stack of coturn's <c>--dtls</c> (optional)</item>
    /// <item><c>SHARPICE_COTURN_USER</c> and <c>SHARPICE_COTURN_PASSWORD</c>: a user of its long-term credentials</item>
    /// <item><c>SHARPICE_COTURN_PEER_ADDRESS</c>: an address of this host's coturn relays to, and coturn's allowed-peer-ip
    /// lets through - of the data relayed both ways, and of TCP allocations (optional)</item>
    /// </list>
    /// e.g. <c>turnserver -n --lt-cred-mech --user=user:pass --realm=example.org --listening-port=3478 --tls-listening-port=5349
    /// --cert=... --pkey=... --allowed-peer-ip=192.168.1.10 --no-cli</c>
    /// </summary>
    [TestClass]
    public class TestCoturn
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static string Uri => Environment.GetEnvironmentVariable("SHARPICE_COTURN_URI");
        private static string TlsUri => Environment.GetEnvironmentVariable("SHARPICE_COTURN_TLS_URI");
        private static IPAddress PeerAddress => IPAddress.TryParse(Environment.GetEnvironmentVariable("SHARPICE_COTURN_PEER_ADDRESS"), out var address) ? address : null;

        private static StunClientOptions Options(Action<StunClientOptions> configure = null)
        {
            var options = new StunClientOptions
            {
            Username = Environment.GetEnvironmentVariable("SHARPICE_COTURN_USER") ?? "user",
            Password = Environment.GetEnvironmentVariable("SHARPICE_COTURN_PASSWORD") ?? "pass",
            // coturn's certificate is often self-signed of a test's
            CertificateValidation = (s, c, ch, e) => true,
            };
            configure?.Invoke(options);
            return options;
        }

        private static void RequireServer()
        {
            if (string.IsNullOrEmpty(Uri))
                Assert.Inconclusive("Of no coturn: set SHARPICE_COTURN_URI, SHARPICE_COTURN_USER and SHARPICE_COTURN_PASSWORD.");
        }

        // a transport to coturn: its name, its URI, the client's options of it, and whether it is a stream - of TCP allocations
        private sealed class Transport
        {
            public string Name;
            public string Uri;
            public Action<StunClientOptions> Configure;
            public bool IsStream;
            public override string ToString() => Name;
        }

        private static IEnumerable<Transport> Transports()
        {
            yield return new Transport { Name = "UDP", Uri = Uri + (Uri.Contains("?") ? "" : "?transport=udp") };
            yield return new Transport { Name = "TCP", Uri = Uri.Split('?')[0] + "?transport=tcp", IsStream = true };
            if (string.IsNullOrEmpty(TlsUri))
                yield break;
            foreach (var stack in new[] { TlsStacks.SharpDtls, TlsStacks.BouncyCastle, TlsStacks.System })
                yield return new Transport { Name = "TLS of " + stack.Name, Uri = TlsUri, Configure = o => o.TlsStack = stack, IsStream = true };
            foreach (var stack in new[] { DtlsStacks.SharpDtls, DtlsStacks.BouncyCastle })
                yield return new Transport { Name = "DTLS of " + stack.Name, Uri = TlsUri, Configure = o => { o.UseDtls = true; o.DtlsStack = stack; } };
        }

        [TestMethod]
        public async Task AllocatesRefreshesAndDeletesOfEachTransport()
        {
            RequireServer();
            foreach (var transport in Transports())
            {
                using var turn = new TurnClient(Options(transport.Configure));
                await turn.ConnectAsync(transport.Uri);
                await turn.AllocateAsync();
                Assert.IsNotNull(turn.RelayedEndPoint, transport.Name);
                Assert.IsNotNull(turn.MappedEndPoint, transport.Name);
                await turn.RefreshAsync(TimeSpan.FromMinutes(5));
                var peer = new IPEndPoint(PeerAddress ?? IPAddress.Parse("8.8.8.8"), 9);
                await turn.CreatePermissionAsync(peer.Address);
                Assert.AreEqual((ushort)0x4000, await turn.BindChannelAsync(peer), transport.Name);
                await turn.DeallocateAsync();
                Assert.IsFalse(turn.IsAllocated, transport.Name);
            }
        }

        [TestMethod]
        public async Task RelaysToAPeerAndBackOfIndicationsAndChannels()
        {
            RequireServer();
            if (PeerAddress == null)
                Assert.Inconclusive("Of no peer coturn relays to: set SHARPICE_COTURN_PEER_ADDRESS.");
            foreach (var transport in Transports())
            {
                using var turn = new TurnClient(Options(transport.Configure));
                await turn.ConnectAsync(transport.Uri);
                await turn.AllocateAsync();
                var received = new System.Collections.Concurrent.BlockingCollection<string>();
                turn.DataReceived += (s, e) => received.Add(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));

                using var peer = new Socket(PeerAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                peer.Bind(new IPEndPoint(PeerAddress, 0));
                peer.ReceiveTimeout = (int)Timeout.TotalMilliseconds;
                var peerEndPoint = (IPEndPoint)peer.LocalEndPoint;
                foreach (bool channel in new[] { false, true })
                {
                    if (channel)
                        await turn.BindChannelAsync(peerEndPoint);
                    await turn.SendAsync(peerEndPoint, Encoding.UTF8.GetBytes("to the peer"));
                    byte[] buffer = new byte[1500];
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int count = peer.ReceiveFrom(buffer, ref from);
                    Assert.AreEqual("to the peer", Encoding.UTF8.GetString(buffer, 0, count), transport.Name);
                    Assert.AreEqual(turn.RelayedEndPoint.Port, ((IPEndPoint)from).Port, "of the relayed address: " + transport.Name);
                    peer.SendTo(Encoding.UTF8.GetBytes("to the client"), from);
                    Assert.IsTrue(received.TryTake(out string text, Timeout), $"relayed back, {(channel ? "of a channel" : "of a Data indication")}: {transport.Name}");
                    Assert.AreEqual("to the client", text);
                }
            }
        }

        [TestMethod]
        public async Task ConnectsToAPeerOfATcpAllocation()
        {
            RequireServer();
            if (PeerAddress == null)
                Assert.Inconclusive("Of no peer coturn relays to: set SHARPICE_COTURN_PEER_ADDRESS.");
            var listener = new TcpListener(PeerAddress, 0);
            listener.Start();
            try
            {
                foreach (var transport in Transports().Where(t => t.IsStream))
                {
                    using var turn = new TurnClient(Options(transport.Configure));
                    await turn.ConnectAsync(transport.Uri);
                    await turn.AllocateAsync(new TurnAllocateOptions { Tcp = true });

                    // of Connect: coturn connects to the peer, its stream the client's of a ConnectionBind
                    var accepting = listener.AcceptTcpClientAsync();
                    await turn.CreatePermissionAsync(PeerAddress);
                    using var connection = await turn.ConnectPeerAsync((IPEndPoint)listener.LocalEndpoint);
                    Assert.AreSame(accepting, await Task.WhenAny(accepting, Task.Delay(Timeout)), "coturn connected to the peer: " + transport.Name);
                    using var peer = await accepting;
                    byte[] hello = Encoding.UTF8.GetBytes("hello over TCP");
                    await connection.Stream.WriteAsync(hello, 0, hello.Length);
                    byte[] buffer = new byte[hello.Length];
                    int read = 0;
                    while (read < buffer.Length)
                    {
                        int count = await peer.GetStream().ReadAsync(buffer, read, buffer.Length - read);
                        Assert.AreNotEqual(0, count);
                        read += count;
                    }
                    Assert.AreEqual("hello over TCP", Encoding.UTF8.GetString(buffer), transport.Name);

                    // of a peer that connects: told of of a ConnectionAttempt, taken of AcceptPeerAsync
                    var attempts = new System.Collections.Concurrent.BlockingCollection<TurnConnectionAttemptEventArgs>();
                    turn.ConnectionAttempt += (s, e) => attempts.Add(e);
                    using var incoming = new TcpClient(PeerAddress.AddressFamily);
                    incoming.Client.Bind(new IPEndPoint(PeerAddress, 0));
                    await incoming.ConnectAsync(turn.RelayedEndPoint.Address, turn.RelayedEndPoint.Port);
                    Assert.IsTrue(attempts.TryTake(out var attempt, Timeout), "a ConnectionAttempt: " + transport.Name);
                    using var accepted = await turn.AcceptPeerAsync(attempt);
                    await incoming.GetStream().WriteAsync(hello, 0, hello.Length);
                    read = 0;
                    while (read < buffer.Length)
                    {
                        int count = await accepted.Stream.ReadAsync(buffer, read, buffer.Length - read);
                        Assert.AreNotEqual(0, count);
                        read += count;
                    }
                    Assert.AreEqual("hello over TCP", Encoding.UTF8.GetString(buffer), transport.Name);
                }
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}
