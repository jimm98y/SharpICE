using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// ICE-TCP over TLS, of SharpDTLS: agents on this machine's loopback of candidates of transport "tls" alone, of a
    /// certificate given and of one of their own; TCP's preferred over them; a connection that is not of TLS closed; and an
    /// agent of TCP alone, which leaves them out.
    /// </summary>
    [TestClass]
    public class TestIceTls
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static IceAgentOptions Loopback(IceRole role = IceRole.Controlled, bool udp = false, bool tcp = false, bool tls = true) => new IceAgentOptions
        {
            Role = role,
            IncludeLoopback = true,
            AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
            IncludeUdp = udp,
            IncludeTcp = tcp,
            IncludeTls = tls,
        };

        private static void Exchange(IceAgent a, IceAgent b)
        {
            a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
            b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
            foreach (var candidate in b.LocalCandidates)
                a.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in a.LocalCandidates)
                b.AddRemoteCandidate(candidate.ToString());
        }

        private static async Task WaitUntil(Func<bool> condition, string what)
        {
            DateTime deadline = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < deadline)
            {
                if (condition())
                    return;
                await Task.Delay(20);
            }
            Assert.Fail(what);
        }

        private static async Task Connect(IceAgent a, IceAgent b)
        {
            await a.GatherCandidatesAsync();
            await b.GatherCandidatesAsync();
            Exchange(a, b);
            a.Start();
            b.Start();
            await WaitUntil(() => a.SelectedPair?.Nominated == true && b.SelectedPair?.Nominated == true,
                $"Not connected: {a.State} {a.SelectedPair}, {b.State} {b.SelectedPair}");
        }

        private static async Task<string> SendAndReceive(IceAgent from, IceAgent to, string text)
        {
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler<IceDataReceivedEventArgs> handler = (s, e) => received.TrySetResult(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            to.DataReceived += handler;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text);
                Assert.IsTrue(from.Send(bytes, 0, bytes.Length));
                Assert.AreSame(received.Task, await Task.WhenAny(received.Task, Task.Delay(Timeout)));
                return await received.Task;
            }
            finally
            {
                to.DataReceived -= handler;
            }
        }

        private static X509Certificate2 CreateCertificate()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=ice", key, HashAlgorithmName.SHA256);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            // of a key SharpDTLS can export
#pragma warning disable SYSLIB0057
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        [TestMethod]
        public async Task ConnectsOverTlsAlone()
        {
            using var controlling = new IceAgent(Loopback(IceRole.Controlling));
            using var controlled = new IceAgent(Loopback());

            await Connect(controlling, controlled);

            Assert.AreEqual(2, controlling.LocalCandidates.Count, "of TLS passive and of TLS active");
            Assert.IsTrue(controlling.LocalCandidates.All(c => c.Transport == "tls" && c.TcpType != null));
            Assert.IsTrue(controlling.SelectedPair.IsTls && controlled.SelectedPair.IsTls);
            Assert.IsFalse(controlling.SelectedPair.IsTcp);
            // each agent connects to the other's passive candidate, and either connection may be the one nominated
            var selected = controlling.SelectedPair;
            CollectionAssert.AreEquivalent(new[] { IceCandidate.TcpActive, IceCandidate.TcpPassive }, new[] { selected.Local.TcpType, selected.Remote.TcpType },
                "an active candidate of a passive one");
            Assert.AreEqual(controlling.SelectedPair.LocalEndPoint, controlled.SelectedPair.RemoteEndPoint);
            Assert.AreEqual("hello", await SendAndReceive(controlling, controlled, "hello"));
            Assert.AreEqual("world", await SendAndReceive(controlled, controlling, "world"));

            // packets one after another come apart as they went, of their frames in TLS's records
            string large = new string('x', 1400);
            var received = new ConcurrentQueue<string>();
            controlled.DataReceived += (s, e) => received.Enqueue(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            for (int i = 0; i < 20; i++)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(i + large);
                Assert.IsTrue(controlling.Send(bytes, 0, bytes.Length));
            }
            await WaitUntil(() => received.Count == 20, $"{received.Count} of 20 received");
            CollectionAssert.AreEqual(Enumerable.Range(0, 20).Select(i => i + large).ToArray(), received.ToArray());
        }

        [TestMethod]
        public async Task ConnectsOfTheCertificateGiven()
        {
            using var certificate = CreateCertificate();
            var options = Loopback();
            options.TlsCertificate = certificate;
            using var controlling = new IceAgent(Loopback(IceRole.Controlling));
            using var controlled = new IceAgent(options);

            await Connect(controlling, controlled);

            Assert.IsTrue(controlling.SelectedPair.IsTls);
            Assert.AreEqual("hello", await SendAndReceive(controlling, controlled, "hello"));
        }

        [TestMethod]
        public async Task PrefersTcpOverTls()
        {
            using var controlling = new IceAgent(Loopback(IceRole.Controlling, tcp: true));
            using var controlled = new IceAgent(Loopback(tcp: true));

            await Connect(controlling, controlled);

            Assert.AreEqual(4, controlling.LocalCandidates.Count, "of TCP and of TLS, passive and active each");
            var tcp = controlling.LocalCandidates.Where(c => c.IsTcp).ToList();
            var tls = controlling.LocalCandidates.Where(c => c.IsTls).ToList();
            Assert.IsTrue(tls.All(t => tcp.All(c => c.Priority > t.Priority)), "each of TCP before each of TLS");
            Assert.AreNotEqual(tcp[0].Foundation, tls[0].Foundation, "of a foundation each of a transport");
            Assert.IsTrue(controlling.SelectedPair.IsTcp && !controlling.SelectedPair.IsTls);
            Assert.IsTrue(controlled.SelectedPair.IsTcp);
        }

        [TestMethod]
        public void TellsTheTypePreferencesOfTls()
        {
            foreach (var type in new[] { IceCandidateType.Host, IceCandidateType.PeerReflexive, IceCandidateType.ServerReflexive })
            {
                Assert.IsTrue(IceCandidate.TypePreference(type, "tls") < IceCandidate.TypePreference(type, "tcp"), type.ToString());
                Assert.AreEqual(IceCandidate.TypePreference(type, true), IceCandidate.TypePreference(type, "tcp"), type.ToString());
                Assert.AreEqual(IceCandidate.TypePreference(type, false), IceCandidate.TypePreference(type, "udp"), type.ToString());
            }

            var candidate = IceCandidate.Parse("candidate:l1 1 tls 1442840575 127.0.0.1 50000 typ host tcptype passive");
            Assert.IsNotNull(candidate);
            Assert.IsTrue(candidate.IsTls && candidate.IsStream && !candidate.IsTcp && !candidate.IsUdp);
            Assert.AreEqual(IceCandidate.TcpPassive, candidate.TcpType);
            Assert.AreEqual("candidate:l1 1 tls 1442840575 127.0.0.1 50000 typ host tcptype passive", candidate.ToString());
            Assert.IsFalse(IceCandidate.SameTransport(candidate, IceCandidate.Parse("candidate:t1 1 tcp 1 127.0.0.1 50000 typ host tcptype passive")));
            Assert.IsTrue(IceCandidate.SameTransport(candidate, IceCandidate.Parse("candidate:l2 1 TLS 1 127.0.0.1 9 typ host tcptype active")));
        }

        [TestMethod]
        public async Task ClosesAConnectionThatIsNotOfTls()
        {
            var options = Loopback();
            options.TcpCheckTimeout = TimeSpan.FromSeconds(2);
            using var agent = new IceAgent(options);
            await agent.GatherCandidatesAsync();
            var passive = agent.LocalCandidates.Single(c => c.TcpType == IceCandidate.TcpPassive);

            // a frame of RFC 4571 of a STUN Binding request's header, as plain ICE-TCP would send it, rather than a ClientHello
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, passive.Port);
            var stream = client.GetStream();
            byte[] frame = new byte[2 + 20];
            frame[1] = 20;
            frame[2] = 0x00;
            frame[3] = 0x01;
            frame[6] = 0x21;
            frame[7] = 0x12;
            frame[8] = 0xA4;
            frame[9] = 0x42;
            await stream.WriteAsync(frame, 0, frame.Length);

            var read = ReadOrReset(stream);
            Assert.AreSame(read, await Task.WhenAny(read, Task.Delay(Timeout)), "closed, not left open");
            Assert.AreEqual(0, await read, "nothing answered of it");
            Assert.AreEqual(0, agent.Pairs.Count);
        }

        // what a closed connection reads: its end, or of one reset, nothing
        private static async Task<int> ReadOrReset(NetworkStream stream)
        {
            try
            {
                return await stream.ReadAsync(new byte[16], 0, 16);
            }
            catch (System.IO.IOException)
            {
                return 0;
            }
        }

        [TestMethod]
        public async Task AnAgentOfTcpAloneLeavesThemOut()
        {
            using var tls = new IceAgent(Loopback(IceRole.Controlling));
            using var tcp = new IceAgent(Loopback(tcp: true, tls: false));
            await tls.GatherCandidatesAsync();
            await tcp.GatherCandidatesAsync();

            foreach (var candidate in tls.LocalCandidates)
                Assert.IsFalse(tcp.AddRemoteCandidate(candidate), $"left out: {candidate}");
            foreach (var candidate in tcp.LocalCandidates)
                Assert.IsFalse(tls.AddRemoteCandidate(candidate), $"left out: {candidate}");
            Assert.AreEqual(0, tls.Pairs.Count);
            Assert.AreEqual(0, tcp.Pairs.Count);
        }
    }
}
