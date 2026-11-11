using SharpStun;
using SharpTurn;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// The TLS stacks of each other: STUN over TLS of each client's of each server's, a certificate refused of each, a TCP
    /// allocation's data connection of each, and ICE-TCP over TLS of each.
    /// </summary>
    [TestClass]
    public class TestTlsStacks
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        // of a DataRow's name: "sharp" of SharpDTLS, "bc" of BouncyCastle, "system" of SslStream
        private static ITlsStack Stack(string name) => name switch
        {
            "bc" => TlsStacks.BouncyCastle,
            "system" => TlsStacks.System,
            _ => TlsStacks.SharpDtls,
        };

        private static X509Certificate2 CreateCertificate(string host, bool ecdsa)
        {
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            X509Certificate2 certificate;
            if (ecdsa)
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest("CN=" + host, key, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(names.Build());
                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            }
            else
            {
                using var key = RSA.Create(2048);
                var request = new CertificateRequest("CN=" + host, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(names.Build());
                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            }
            using (certificate)
            {
#pragma warning disable SYSLIB0057
                return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
            }
        }

        [TestMethod]
        [DataRow("sharp", "sharp", false)]
        [DataRow("sharp", "sharp", true)]
        [DataRow("bc", "bc", false)]
        [DataRow("bc", "bc", true)]
        [DataRow("system", "system", false)]
        [DataRow("sharp", "bc", true)]
        [DataRow("bc", "sharp", false)]
        [DataRow("sharp", "system", false)]
        [DataRow("system", "sharp", true)]
        [DataRow("bc", "system", false)]
        [DataRow("system", "bc", false)]
        public async Task AnswersAClientOverTls(string clientStack, string serverStack, bool ecdsa)
        {
            using var certificate = CreateCertificate("localhost", ecdsa);
            using var server = new StunServer(new StunServerOptions
            {
                Realm = "example.org",
                Users = new Dictionary<string, string> { ["user"] = "secret" },
                Certificate = certificate,
                TlsStack = Stack(serverStack),
            });
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));

            using var client = new StunClient(new StunClientOptions
            {
                Username = "user",
                Password = "secret",
                CertificateValidation = (s, c, ch, e) => true,
                TlsStack = Stack(clientStack),
            });
            await client.ConnectAsync("stuns:localhost:" + tls.Port);

            var transport = (StunStreamTransport)client.Transport;
            Assert.IsTrue(transport.IsSecure);
            Assert.AreSame(Stack(clientStack), transport.TlsStack);
            Assert.AreEqual(transport.LocalEndPoint.Port, (await client.GetMappedAddressAsync()).Port);
            Assert.IsTrue(client.IsAuthenticated);
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        [DataRow("system")]
        public async Task RefusesACertificateTheSystemDoesNotTrust(string stack)
        {
            using var certificate = CreateCertificate("localhost", false);
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, TlsStack = Stack(stack) });
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));

            // of no callback, the system's checks: a self-signed certificate is not of a root it trusts
            await Assert.ThrowsExactlyAsync<StunException>(() => new StunClient(new StunClientOptions { TlsStack = Stack(stack) }).ConnectAsync("stuns:localhost:" + tls.Port));
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        [DataRow("system")]
        public async Task TellsTheCallbackOfACertificateOfAnotherName(string stack)
        {
            using var certificate = CreateCertificate("stun.example.org", true);
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, TlsStack = Stack(stack) });
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));
            var told = SslPolicyErrors.None;

            using var transport = await StunStreamTransport.ConnectAsync(tls, "other.example.org", (s, c, chain, errors) => { told = errors; return true; }, Stack(stack));

            Assert.IsTrue((told & SslPolicyErrors.RemoteCertificateNameMismatch) != 0);
            using var client = new StunClient(transport);
            Assert.IsNotNull(await client.GetMappedAddressAsync());
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        [DataRow("system")]
        public async Task ConnectsToAPeerOfATcpAllocationOverTls(string stack)
        {
            using var certificate = CreateCertificate("localhost", true);
            using var server = new TurnServer(new TurnServerOptions
            {
                Stun = new StunServerOptions
                {
                    Realm = "example.org",
                    Users = new Dictionary<string, string> { ["user"] = "secret" },
                    AuthenticateBinding = false,
                    Certificate = certificate,
                    TlsStack = Stack(stack),
                },
                RelayAddress = IPAddress.Loopback,
                AllowPeer = peer => true,
            });
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                using var client = new TurnClient(new StunClientOptions
                {
                    Username = "user",
                    Password = "secret",
                    CertificateValidation = (s, c, ch, e) => true,
                    TlsStack = Stack(stack),
                });
                await client.ConnectAsync($"turns:localhost:{tls.Port}");
                await client.AllocateAsync(new TurnAllocateOptions { Tcp = true });

                // the data connection of the control connection's TLS stack
                var accepting = listener.AcceptTcpClientAsync();
                using var connection = await client.ConnectPeerAsync((IPEndPoint)listener.LocalEndpoint);
                Assert.AreSame(accepting, await Task.WhenAny(accepting, Task.Delay(Timeout)), "connected");
                using var peer = await accepting;
                byte[] hello = Encoding.UTF8.GetBytes("hello");
                await connection.Stream.WriteAsync(hello, 0, hello.Length);
                byte[] buffer = new byte[hello.Length];
                int read = 0;
                while (read < buffer.Length)
                {
                    int count = await peer.GetStream().ReadAsync(buffer, read, buffer.Length - read);
                    Assert.AreNotEqual(0, count);
                    read += count;
                }
                Assert.AreEqual("hello", Encoding.UTF8.GetString(buffer));
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        [DataRow("sharp", "sharp")]
        [DataRow("bc", "bc")]
        [DataRow("system", "system")]
        [DataRow("sharp", "system")]
        [DataRow("bc", "sharp")]
        public async Task ConnectsOverIceTcpOfTls(string controllingStack, string controlledStack)
        {
            IceAgentOptions Options(IceRole role, string stack) => new IceAgentOptions
            {
                Role = role,
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                IncludeUdp = false,
                IncludeTls = true,
                TlsStack = Stack(stack),
            };
            using var controlling = new IceAgent(Options(IceRole.Controlling, controllingStack));
            using var controlled = new IceAgent(Options(IceRole.Controlled, controlledStack));
            await controlling.GatherCandidatesAsync();
            await controlled.GatherCandidatesAsync();
            controlling.SetRemoteCredentials(controlled.LocalUfrag, controlled.LocalPassword);
            controlled.SetRemoteCredentials(controlling.LocalUfrag, controlling.LocalPassword);
            foreach (var candidate in controlled.LocalCandidates)
                controlling.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in controlling.LocalCandidates)
                controlled.AddRemoteCandidate(candidate.ToString());
            controlling.Start();
            controlled.Start();

            DateTime deadline = DateTime.UtcNow + Timeout;
            while (!(controlling.SelectedPair?.Nominated == true && controlled.SelectedPair?.Nominated == true) && DateTime.UtcNow < deadline)
                await Task.Delay(20);
            Assert.IsTrue(controlling.SelectedPair?.Nominated == true && controlled.SelectedPair?.Nominated == true, "connected");
            Assert.IsTrue(controlling.SelectedPair.IsTls);

            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            controlled.DataReceived += (s, e) => received.TrySetResult(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            byte[] bytes = Encoding.UTF8.GetBytes("of TLS");
            Assert.IsTrue(controlling.Send(bytes, 0, bytes.Length));
            Assert.AreSame(received.Task, await Task.WhenAny(received.Task, Task.Delay(Timeout)));
            Assert.AreEqual("of TLS", await received.Task);
        }
    }
}
