using SharpSTUN;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// STUN over DTLS (RFC 8489 6.2.3): the client and the server of each other over the loopback, of RSA and of ECDSA, of
    /// long-term credentials; a certificate the system does not trust refused, and one of another name told of; and the names
    /// a certificate is of, as RFC 6125 matches them.
    /// </summary>
    [TestClass]
    public class TestStunDtls
    {
        private static X509Certificate2 CreateCertificate(string host, bool ecdsa = false, string ipAddress = null)
        {
            var names = new SubjectAlternativeNameBuilder();
            if (host != null)
                names.AddDnsName(host);
            if (ipAddress != null)
                names.AddIpAddress(IPAddress.Parse(ipAddress));
            X509Certificate2 certificate;
            if (ecdsa)
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var request = new CertificateRequest("CN=" + (host ?? "x"), key, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(names.Build());
                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            }
            else
            {
                using var key = RSA.Create(2048);
                var request = new CertificateRequest("CN=" + (host ?? "x"), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(names.Build());
                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            }
            using (certificate)
            {
                // of a key DTLS can export, and SChannel can use
#pragma warning disable SYSLIB0057
                return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
            }
        }

        private static StunClientOptions DtlsOptions() => new StunClientOptions
        {
            Username = "user",
            Password = "secret",
            UseDtls = true,
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxTransmissions = 3,
            LastWaitMultiplier = 2,
            CertificateValidation = (s, c, ch, e) => true,
        };

        // of a DataRow's name: "sharp" of SharpDTLS, "bc" of BouncyCastle
        private static IDtlsStack Stack(string name) => name == "bc" ? DtlsStacks.BouncyCastle : DtlsStacks.SharpDtls;

        private const ushort Dtls12 = 0xFEFD;
        private const ushort Dtls13 = 0xFEFC;

        [TestMethod]
        [DataRow(false, "sharp", "sharp")]
        [DataRow(true, "sharp", "sharp")]
        [DataRow(false, "bc", "bc")]
        [DataRow(true, "bc", "bc")]
        [DataRow(false, "sharp", "bc")]
        [DataRow(true, "bc", "sharp")]
        public async Task AnswersAClientOverDtls(bool ecdsa, string clientStack, string serverStack)
        {
            using var certificate = CreateCertificate("localhost", ecdsa);
            using var server = new StunServer(new StunServerOptions
            {
                Realm = "example.org",
                Users = new Dictionary<string, string> { ["user"] = "secret" },
                Certificate = certificate,
                DtlsStack = Stack(serverStack),
            });
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));

            var options = DtlsOptions();
            options.DtlsStack = Stack(clientStack);
            using var client = new StunClient(options);
            await client.ConnectAsync("stuns:localhost:" + dtls.Port);

            var transport = (StunDtlsTransport)client.Transport;
            Assert.AreSame(Stack(clientStack), transport.Stack);
            // DTLS 1.3 of SharpDTLS of both sides; of BouncyCastle of either, DTLS 1.2, which it alone has
            Assert.AreEqual(clientStack == "sharp" && serverStack == "sharp" ? Dtls13 : Dtls12, transport.NegotiatedVersion);
            Assert.IsFalse(client.Transport.IsReliable, "retransmitted, as over UDP");
            Assert.AreEqual(client.Transport.LocalEndPoint.Port, (await client.GetMappedAddressAsync()).Port);
            Assert.IsTrue(client.IsAuthenticated);
            Assert.IsNotNull(await client.GetMappedAddressAsync());
        }

        // one address holds at most MaxDtlsPeersPerAddress associations, of either stack: the one past them is closed once its
        // handshake is done, and answered nothing
        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        public async Task CapsTheAssociationsOfOneAddress(string stack)
        {
            using var certificate = CreateCertificate("localhost");
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, DtlsStack = Stack(stack), MaxDtlsPeersPerAddress = 2 });
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));

            var clients = new List<StunClient>();
            try
            {
                for (int i = 0; i < 2; i++)
                {
                    var options = DtlsOptions();
                    options.DtlsStack = Stack(stack);
                    var client = new StunClient(options);
                    clients.Add(client);
                    await client.ConnectAsync("stuns:localhost:" + dtls.Port);
                    Assert.IsNotNull(await client.GetMappedAddressAsync(), "within the cap: " + i);
                }

                var thirdOptions = DtlsOptions();
                thirdOptions.DtlsStack = Stack(stack);
                var third = new StunClient(thirdOptions);
                clients.Add(third);
                IPEndPoint mapped = null;
                try
                {
                    await third.ConnectAsync("stuns:localhost:" + dtls.Port);
                    mapped = await third.GetMappedAddressAsync();
                }
                catch (Exception ex) when (ex is StunException || ex is System.IO.IOException || ex is System.Security.Authentication.AuthenticationException || ex is ObjectDisposedException)
                {
                }
                Assert.IsNull(mapped, "an association past the cap was answered");

                // the ones within it go on
                Assert.IsNotNull(await clients[0].GetMappedAddressAsync());
            }
            finally
            {
                foreach (var client in clients)
                    client.Dispose();
            }
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        public async Task RefusesACertificateTheSystemDoesNotTrust(string stack)
        {
            using var certificate = CreateCertificate("localhost");
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, DtlsStack = Stack(stack) });
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));
            var options = DtlsOptions();
            options.CertificateValidation = null;
            options.DtlsStack = Stack(stack);

            await Assert.ThrowsExactlyAsync<StunException>(() => new StunClient(options).ConnectAsync("stuns:localhost:" + dtls.Port));
        }

        [TestMethod]
        [DataRow("sharp")]
        [DataRow("bc")]
        public async Task TellsTheCallbackOfACertificateOfAnotherName(string stack)
        {
            using var certificate = CreateCertificate("stun.example.org");
            using var server = new StunServer(new StunServerOptions { Certificate = certificate, DtlsStack = Stack(stack) });
            var dtls = server.ListenDtls(new IPEndPoint(IPAddress.Loopback, 0));
            var told = SslPolicyErrors.None;

            using var transport = await StunDtlsTransport.ConnectAsync(dtls, "other.example.org", (s, c, chain, errors) => { told = errors; return true; }, Stack(stack));
            Assert.AreSame(Stack(stack), transport.Stack);

            Assert.IsTrue((told & SslPolicyErrors.RemoteCertificateNameMismatch) != 0);
            Assert.IsTrue((told & SslPolicyErrors.RemoteCertificateChainErrors) != 0, "self-signed");
            using var client = new StunClient(transport);
            Assert.IsNotNull(await client.GetMappedAddressAsync());
        }

        [TestMethod]
        public void MatchesTheNamesOfACertificate()
        {
            using var exact = CreateCertificate("stun.example.org");
            Assert.IsTrue(DtlsCertificates.MatchesHost(exact.RawData, "stun.example.org"));
            Assert.IsTrue(DtlsCertificates.MatchesHost(exact.RawData, "STUN.example.org."));
            Assert.IsFalse(DtlsCertificates.MatchesHost(exact.RawData, "other.example.org"));

            using var wildcard = CreateCertificate("*.example.org");
            Assert.IsTrue(DtlsCertificates.MatchesHost(wildcard.RawData, "stun.example.org"));
            Assert.IsFalse(DtlsCertificates.MatchesHost(wildcard.RawData, "a.stun.example.org"), "of the leftmost label alone");
            Assert.IsFalse(DtlsCertificates.MatchesHost(wildcard.RawData, "example.org"));

            using var address = CreateCertificate(null, ipAddress: "192.0.2.7");
            Assert.IsTrue(DtlsCertificates.MatchesHost(address.RawData, "192.0.2.7"));
            Assert.IsFalse(DtlsCertificates.MatchesHost(address.RawData, "192.0.2.8"));
        }
    }
}
