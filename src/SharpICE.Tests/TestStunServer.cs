using SharpSTUN;
using SharpTURN;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// The STUN server: each of RFC 8489 9.2.4's checks of long-term credentials, in their order, of requests made by hand; and
    /// <see cref="StunClient"/> answered by it over UDP, TCP and TLS, of its credentials, a stale nonce and a redirection.
    /// </summary>
    [TestClass]
    public class TestStunServer
    {
        private const string Realm = "example.org";
        private const string User = "user";
        private const string Password = "secret";

        private static readonly IPEndPoint Client = new IPEndPoint(IPAddress.Parse("192.0.2.5"), 40000);

        private static StunServerOptions Credentials(params StunPasswordAlgorithm[] algorithms) => new StunServerOptions
        {
            Realm = Realm,
            Users = new Dictionary<string, string> { [User] = Password },
            PasswordAlgorithms = algorithms.ToList(),
        };

        private static StunMessage Ask(StunServer server, StunMessage request, byte[] key = null, StunIntegrity integrity = StunIntegrity.None, IPEndPoint from = null, bool fingerprint = true)
        {
            byte[] bytes = request.ToBytes(key, integrity, fingerprint);
            byte[] answer = server.Process(bytes, 0, bytes.Length, from ?? Client, false);
            return answer == null ? null : StunMessage.Parse(answer, 0, answer.Length);
        }

        private static StunMessage Binding() => new StunMessage(StunMethod.Binding, StunMessageClass.Request);

        // a request of the credentials of a challenge: of the algorithm the server listed first, and its list sent back
        private static StunMessage Authenticated(StunMessage challenge, string user = User, bool algorithms = true)
        {
            var request = Binding()
                .AddString(StunAttributeType.Username, user)
                .AddString(StunAttributeType.Realm, challenge.Realm)
                .AddString(StunAttributeType.Nonce, challenge.Nonce);
            if (algorithms && challenge.HasAttribute(StunAttributeType.PasswordAlgorithms))
            {
                request.AddAttribute(StunAttributeType.PasswordAlgorithms, challenge.GetAttribute(StunAttributeType.PasswordAlgorithms).Value);
                request.AddPasswordAlgorithm((StunPasswordAlgorithm)challenge.PasswordAlgorithms[0]);
            }
            return request;
        }

        [TestMethod]
        public void AnswersABindingRequestOfItsSource()
        {
            using var server = new StunServer();
            var response = Ask(server, Binding());

            Assert.AreEqual(StunMessageClass.SuccessResponse, response.Class);
            Assert.AreEqual(Client, response.GetXorAddress());
            Assert.AreEqual("SharpSTUNServer", response.GetString(StunAttributeType.Software));
            Assert.IsTrue(response.HasFingerprint && response.VerifyFingerprint());
            Assert.IsFalse(Ask(server, Binding(), fingerprint: false).HasFingerprint, "of a request of no FINGERPRINT, none");
        }

        [TestMethod]
        public void DiscardsWhatItDoesNotAnswer()
        {
            using var server = new StunServer();
            Assert.IsNull(Ask(server, new StunMessage(StunMethod.Binding, StunMessageClass.Indication)), "an indication");
            Assert.IsNull(Ask(server, new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse)), "a response");
            Assert.IsNull(Ask(server, new StunMessage(TurnMethod.Allocate, StunMessageClass.Request)), "a method it does not support");

            byte[] bytes = Binding().ToBytes();
            bytes[bytes.Length - 1] ^= 1;
            Assert.IsNull(server.Process(bytes, 0, bytes.Length, Client, false), "of a FINGERPRINT that is wrong");
        }

        [TestMethod]
        public void ChallengesARequestOfNoIntegrity()
        {
            using var server = new StunServer(new StunServerOptions
            {
                Realm = Realm,
                Users = new Dictionary<string, string> { [User] = Password },
                UsernameAnonymity = true,
            });
            var challenge = Ask(server, Binding());

            Assert.AreEqual(StunErrorCode.Unauthorized, challenge.Error.Value.Code);
            Assert.AreEqual(Realm, challenge.Realm);
            Assert.AreEqual(StunSecurityFeatures.PasswordAlgorithms | StunSecurityFeatures.UsernameAnonymity, StunCredentials.GetSecurityFeatures(challenge.Nonce));
            CollectionAssert.AreEqual(new[] { (ushort)2, (ushort)1 }, challenge.PasswordAlgorithms.ToArray());
            Assert.IsFalse(challenge.HasIntegrity || challenge.HasIntegritySha256);
            Assert.AreNotEqual(challenge.Nonce, Ask(server, Binding(), from: new IPEndPoint(Client.Address, 40001)).Nonce, "no two sources of one nonce");
        }

        [TestMethod]
        public void AnswersTheCredentialsOfSha256SignedAlike()
        {
            using var server = new StunServer(Credentials(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5));
            var challenge = Ask(server, Binding());
            byte[] key = StunCredentials.LongTermKey(User, Realm, Password, StunPasswordAlgorithm.Sha256);

            var response = Ask(server, Authenticated(challenge), key, StunIntegrity.Sha256);

            Assert.AreEqual(StunMessageClass.SuccessResponse, response.Class);
            Assert.IsTrue(response.HasIntegritySha256 && !response.HasIntegrity);
            Assert.IsTrue(response.VerifyIntegritySha256(key));
            Assert.AreEqual(Client, response.GetXorAddress());
        }

        [TestMethod]
        public void AnswersAUserhash()
        {
            var options = Credentials(StunPasswordAlgorithm.Sha256);
            options.UsernameAnonymity = true;
            using var server = new StunServer(options);
            var challenge = Ask(server, Binding());
            byte[] key = StunCredentials.LongTermKey(User, Realm, Password, StunPasswordAlgorithm.Sha256);

            var request = Authenticated(challenge);
            request.Attributes.RemoveAll(a => a.Type == StunAttributeType.Username);
            request.AddAttribute(StunAttributeType.Userhash, StunCredentials.UserHash(User, Realm));
            Assert.AreEqual(StunMessageClass.SuccessResponse, Ask(server, request, key, StunIntegrity.Sha256).Class);
        }

        [TestMethod]
        public void AnswersAClientOfRFC5389OfMd5AndMessageIntegrity()
        {
            // a server of no algorithms listed, as of RFC 5389; and one of them, of a request of neither attribute: MD5 of both
            foreach (var options in new[] { Credentials(), Credentials(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5) })
            {
                using var server = new StunServer(options);
                var challenge = Ask(server, Binding());
                byte[] key = StunCredentials.LongTermKey(User, Realm, Password);

                var response = Ask(server, Authenticated(challenge, algorithms: false), key, StunIntegrity.Sha1);

                Assert.AreEqual(StunMessageClass.SuccessResponse, response.Class);
                Assert.IsTrue(response.HasIntegrity && !response.HasIntegritySha256, "MESSAGE-INTEGRITY, as the request was signed");
                Assert.IsTrue(response.VerifyIntegrity(key));
            }
        }

        [TestMethod]
        public void RefusesWhatIsNotOfTheCredentials()
        {
            using var server = new StunServer(Credentials(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5));
            var challenge = Ask(server, Binding());
            byte[] key = StunCredentials.LongTermKey(User, Realm, Password, StunPasswordAlgorithm.Sha256);

            // of integrity, but of no username: 400
            var noUser = Binding().AddString(StunAttributeType.Realm, Realm).AddString(StunAttributeType.Nonce, challenge.Nonce);
            Assert.AreEqual(StunErrorCode.BadRequest, Ask(server, noUser, key, StunIntegrity.Sha256).Error.Value.Code);

            // a list of algorithms other than the one sent: 400
            var otherList = Authenticated(challenge);
            otherList.Attributes.RemoveAll(a => a.Type == StunAttributeType.PasswordAlgorithms);
            otherList.AddPasswordAlgorithms(StunPasswordAlgorithm.Md5);
            Assert.AreEqual(StunErrorCode.BadRequest, Ask(server, otherList, key, StunIntegrity.Sha256).Error.Value.Code);

            // a user it does not know, and a wrong password: 401, of a new challenge
            Assert.AreEqual(StunErrorCode.Unauthorized, Ask(server, Authenticated(challenge, "nobody"), key, StunIntegrity.Sha256).Error.Value.Code);
            byte[] wrong = StunCredentials.LongTermKey(User, Realm, "wrong", StunPasswordAlgorithm.Sha256);
            var refused = Ask(server, Authenticated(challenge), wrong, StunIntegrity.Sha256);
            Assert.AreEqual(StunErrorCode.Unauthorized, refused.Error.Value.Code);
            Assert.IsNotNull(refused.Nonce);

            // the nonce of another source: stale, of a new one
            var stale = Ask(server, Authenticated(challenge), key, StunIntegrity.Sha256, new IPEndPoint(Client.Address, 40001));
            Assert.AreEqual(StunErrorCode.StaleNonce, stale.Error.Value.Code);
            Assert.AreEqual(Realm, stale.Realm);
            Assert.IsTrue(stale.HasAttribute(StunAttributeType.PasswordAlgorithms));
        }

        [TestMethod]
        public async Task TellsAnOldNonceStale()
        {
            var options = Credentials(StunPasswordAlgorithm.Sha256);
            options.NonceLifetime = TimeSpan.FromMilliseconds(100);
            using var server = new StunServer(options);
            var challenge = Ask(server, Binding());
            byte[] key = StunCredentials.LongTermKey(User, Realm, Password, StunPasswordAlgorithm.Sha256);
            Assert.AreEqual(StunMessageClass.SuccessResponse, Ask(server, Authenticated(challenge), key, StunIntegrity.Sha256).Class);

            await Task.Delay(200);

            Assert.AreEqual(StunErrorCode.StaleNonce, Ask(server, Authenticated(challenge), key, StunIntegrity.Sha256).Error.Value.Code);
        }

        [TestMethod]
        public void AnswersAnUnknownAttributeWith420SignedOfTheCredentials()
        {
            using var open = new StunServer();
            var plain = Ask(open, Binding().AddAttribute(0x7FF0, new byte[4]).AddAttribute(0xC000, new byte[4]));
            Assert.AreEqual(StunErrorCode.UnknownAttribute, plain.Error.Value.Code);
            CollectionAssert.AreEqual(new[] { (ushort)0x7FF0 }, plain.UnknownAttributeTypes.ToArray(), "of the comprehension-required ones alone");

            using var server = new StunServer(Credentials(StunPasswordAlgorithm.Sha256));
            var challenge = Ask(server, Binding());
            byte[] key = StunCredentials.LongTermKey(User, Realm, Password, StunPasswordAlgorithm.Sha256);
            var signed = Ask(server, Authenticated(challenge).AddAttribute(0x7FF0, new byte[4]), key, StunIntegrity.Sha256);
            Assert.AreEqual(StunErrorCode.UnknownAttribute, signed.Error.Value.Code);
            Assert.IsTrue(signed.VerifyIntegritySha256(key), "checked after the credentials, and signed of them");
        }

        private static X509Certificate2 CreateCertificate(string host)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=" + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(host);
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
#pragma warning disable SYSLIB0057
            // of a key the default TLS stack, SharpDTLS's, can export
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        private static StunClientOptions ClientOptions(string password = Password) => new StunClientOptions
        {
            Username = User,
            Password = password,
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxTransmissions = 3,
            LastWaitMultiplier = 2,
            CertificateValidation = (s, c, ch, e) => true,
        };

        [TestMethod]
        public async Task AnswersTheClientOverEachTransport()
        {
            using var certificate = CreateCertificate("localhost");
            var options = Credentials(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5);
            options.UsernameAnonymity = true;
            options.Certificate = certificate;
            using var server = new StunServer(options);
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            var tcp = server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
            var tls = server.ListenTls(new IPEndPoint(IPAddress.Loopback, 0));

            using (var client = new StunClient(ClientOptions()))
            {
                await client.ConnectAsync("stun:127.0.0.1:" + udp.Port);
                Assert.AreEqual(client.Transport.LocalEndPoint.Port, (await client.GetMappedAddressAsync()).Port);
                Assert.IsTrue(client.IsAuthenticated);
                Assert.IsNotNull(await client.GetMappedAddressAsync(), "of the credentials at once");
            }
            using (var client = new StunClient(await StunStreamTransport.ConnectAsync(tcp), ClientOptions()))
            {
                Assert.AreEqual(client.Transport.LocalEndPoint, await client.GetMappedAddressAsync());
                Assert.IsTrue(client.IsAuthenticated);
            }
            using (var client = new StunClient(ClientOptions()))
            {
                await client.ConnectAsync("stuns:localhost:" + tls.Port);
                Assert.AreEqual(client.Transport.LocalEndPoint, await client.GetMappedAddressAsync());
                Assert.IsTrue(client.IsAuthenticated);
            }
            using (var client = new StunClient(ClientOptions("wrong")))
            {
                await client.ConnectAsync("stun:127.0.0.1:" + udp.Port);
                var response = await client.RequestAsync(StunClient.CreateBindingRequest());
                Assert.AreEqual(StunErrorCode.Unauthorized, response.Error.Value.Code);
            }
        }

        [TestMethod]
        public async Task AnswersAClientWhoseNonceWentStale()
        {
            var options = Credentials(StunPasswordAlgorithm.Sha256);
            options.NonceLifetime = TimeSpan.FromMilliseconds(300);
            using var server = new StunServer(options);
            var udp = server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var client = new StunClient(ClientOptions());
            await client.ConnectAsync("stun:127.0.0.1:" + udp.Port);
            Assert.IsNotNull(await client.GetMappedAddressAsync());

            await Task.Delay(400);

            Assert.IsNotNull(await client.GetMappedAddressAsync(), "sent again of the new nonce");
        }

        [TestMethod]
        public async Task RedirectsTheClientToAnAlternateServer()
        {
            using var alternate = new StunServer();
            var to = alternate.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));
            using var redirecting = new StunServer(new StunServerOptions { AlternateServer = from => to });
            var udp = redirecting.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0));

            using var client = new StunClient(ClientOptions());
            await client.ConnectAsync("stun:127.0.0.1:" + udp.Port);
            Assert.IsNotNull(await client.GetMappedAddressAsync());
            Assert.AreEqual(to, client.Transport.RemoteEndPoint);
        }
    }
}
