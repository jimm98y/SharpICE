// SharpStunCommon
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

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SharpStunCommon
{
    internal static class DtlsDefaults
    {
        // how long a client's handshake of DTLS is given
        public const int HandshakeTimeout = 10000;
    }

    /// <summary>A certificate of .NET's as SharpDTLS has it: its key pair, the certificate and those that issued it.</summary>
    internal sealed class DtlsCredentials
    {
        public AsymmetricCipherKeyPair KeyPair { get; set; }
        public BcX509Certificate Certificate { get; set; }
        public IList<BcX509Certificate> Intermediates { get; set; }
    }

    internal static class DtlsCertificates
    {
        /// <summary>The certificate and its private key, of a PKCS #12 export of it: its key is to be exportable.</summary>
        /// <exception cref="ArgumentException">Of no private key, or of one that is not exportable.</exception>
        public static DtlsCredentials Load(X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("A certificate of DTLS is of its private key.", nameof(certificate));
            byte[] pfx;
            const string Password = "dtls";
            try
            {
                pfx = certificate.Export(X509ContentType.Pkcs12, Password);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new ArgumentException("A certificate of DTLS is of an exportable private key: of X509KeyStorageFlags.Exportable.", nameof(certificate), ex);
            }

            var store = new Pkcs12StoreBuilder().Build();
            using (var stream = new MemoryStream(pfx))
                store.Load(stream, Password.ToCharArray());
            string alias = store.Aliases.First(a => store.IsKeyEntry(a));
            var key = store.GetKey(alias).Key;
            var chain = store.GetCertificateChain(alias).Select(e => e.Certificate).ToList();
            return new DtlsCredentials
            {
                KeyPair = new AsymmetricCipherKeyPair(chain[0].GetPublicKey(), key),
                Certificate = chain[0],
                Intermediates = chain.Skip(1).ToList(),
            };
        }

        /// <summary>
        /// A certificate of its own, self-signed, of a key of ECDSA of P-256 made for it: of a peer whose certificate nothing
        /// checks, as of ICE-TCP over TLS. Of ECDSA, as a key of RSA takes a while to make.
        /// </summary>
        public static DtlsCredentials CreateSelfSigned(string name)
        {
            var random = new Org.BouncyCastle.Security.SecureRandom();
            var generator = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();
            // of the curve's name, not its parameters (RFC 5480 2.1.1)
            generator.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, random));
            var keyPair = generator.GenerateKeyPair();

            var certificate = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
            byte[] serial = new byte[16];
            random.NextBytes(serial);
            serial[0] &= 0x7F;
            certificate.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serial));
            var subject = new X509Name("CN=" + name);
            certificate.SetIssuerDN(subject);
            certificate.SetSubjectDN(subject);
            certificate.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certificate.SetNotAfter(DateTime.UtcNow.AddDays(30));
            certificate.SetPublicKey(keyPair.Public);
            var signed = certificate.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private, random));
            return new DtlsCredentials { KeyPair = keyPair, Certificate = signed, Intermediates = new List<BcX509Certificate>() };
        }

        // a certificate of its DER: of .NET 9 and later of X509CertificateLoader, as the constructor of bytes is obsolete there
        //  (SYSLIB0057); before it, of the constructor, which is all there is
        private static X509Certificate2 LoadCertificate(byte[] der)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(der);
#else
            return new X509Certificate2(der);
#endif
        }

        /// <summary>
        /// Whether a server's certificate is to be taken, of its chain's DER, the leaf first: of the system's chain, and of the
        /// host name - of a DNS name of its subject alternative names, a wildcard the leftmost label, or of an IP address of
        /// them; or of its common name, of none - as SslStream checks one (RFC 6125); of a callback given, as it says, told of
        /// what failed.
        /// </summary>
        public static bool Validate(IReadOnlyList<byte[]> chain, string host, RemoteCertificateValidationCallback validation, object sender)
        {
            if (chain == null || chain.Count == 0)
                return false;
            var certificates = chain.Select(LoadCertificate).ToList();
            var leaf = certificates[0];
            var errors = SslPolicyErrors.None;
            using (var x509Chain = new X509Chain())
            {
                x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                foreach (var intermediate in certificates.Skip(1))
                    x509Chain.ChainPolicy.ExtraStore.Add(intermediate);
                if (!x509Chain.Build(leaf))
                    errors |= SslPolicyErrors.RemoteCertificateChainErrors;
                if (!MatchesHost(chain[0], host))
                    errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                return validation != null ? validation(sender, leaf, x509Chain, errors) : errors == SslPolicyErrors.None;
            }
        }

        internal static bool MatchesHost(byte[] encoded, string host)
        {
            var certificate = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(encoded);
            bool isAddress = IPAddress.TryParse(host, out IPAddress address);
            var names = certificate.GetSubjectAlternativeNames();
            bool anyDns = false;
            if (names != null)
            {
                foreach (var name in names)
                {
                    int type = Convert.ToInt32(name[0]);
                    string value = name[1] as string;
                    if (type == GeneralName.DnsName && value != null)
                    {
                        anyDns = true;
                        if (!isAddress && MatchesDnsName(value, host))
                            return true;
                    }
                    else if (type == GeneralName.IPAddress && value != null && isAddress && IPAddress.TryParse(value, out IPAddress named) && named.Equals(address))
                    {
                        return true;
                    }
                }
            }
            if (anyDns || isAddress)
                return false;
            // of no DNS name, its common name (RFC 6125 6.4.4)
            var commonNames = certificate.SubjectDN.GetValueList(X509Name.CN);
            return commonNames.Any(cn => MatchesDnsName(cn, host));
        }

        private static bool MatchesDnsName(string pattern, string host)
        {
            pattern = pattern.TrimEnd('.');
            host = host.TrimEnd('.');
            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                int dot = host.IndexOf('.');
                return dot > 0 && string.Equals(pattern.Substring(1), host.Substring(dot), StringComparison.OrdinalIgnoreCase);
            }
            return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
        }
    }
}
