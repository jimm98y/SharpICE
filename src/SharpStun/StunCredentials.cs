// SharpStun
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

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SharpStun
{
    /// <summary>The algorithms a long-term password is made a key of (RFC 8489 18.5).</summary>
    public enum StunPasswordAlgorithm : ushort
    {
        Md5 = 0x0001,
        Sha256 = 0x0002
    }

    /// <summary>
    /// The STUN Security Features of a nonce cookie (RFC 8489 9.2, 18.1): 24 bits, bit 0 the most significant of the first of
    /// their 3 bytes.
    /// </summary>
    [Flags]
    public enum StunSecurityFeatures
    {
        None = 0,

        /// <summary>The server lists the algorithms it takes in PASSWORD-ALGORITHMS: its requests signed with MESSAGE-INTEGRITY-SHA256.</summary>
        PasswordAlgorithms = 0x800000,

        /// <summary>The server takes a USERHASH in place of a USERNAME.</summary>
        UsernameAnonymity = 0x400000
    }

    /// <summary>
    /// The keys of STUN's credentials (RFC 8489 9): short-term ones, as ICE's, and long-term ones, as TURN's, their username,
    /// realm and password prepared by OpaqueString (RFC 8265 4.2).
    /// </summary>
    public static class StunCredentials
    {
        /// <summary>The start of a nonce whose next 4 characters are the Base64 of the server's security features (RFC 8489 9.2).</summary>
        public const string NonceCookie = "obMatJos2";

        /// <summary>
        /// A string prepared by the OpaqueString profile of PRECIS (RFC 8265 4.2): every space of Unicode a plain one, and the
        /// whole normalized to NFC. Of an empty one, or of one of control characters, which the profile disallows, an
        /// <see cref="ArgumentException"/>; the other code points the profile's FreeformClass disallows are not checked.
        /// </summary>
        public static string OpaqueString(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException("OpaqueString takes no empty string.", nameof(value));

            var mapped = new StringBuilder(value.Length);
            foreach (char c in value)
                mapped.Append(c != ' ' && CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator ? ' ' : c);
            string normalized = mapped.ToString().Normalize(NormalizationForm.FormC);
            foreach (char c in normalized)
            {
                if (char.IsControl(c))
                    throw new ArgumentException("OpaqueString takes no control characters.", nameof(value));
            }
            return normalized;
        }

        /// <summary>
        /// The key of long-term credentials (RFC 8489 9.2.2, 18.5.1): the MD5 - or SHA-256 - of
        /// "username:realm:password", each prepared by OpaqueString.
        /// </summary>
        public static byte[] LongTermKey(string username, string realm, string password, StunPasswordAlgorithm algorithm = StunPasswordAlgorithm.Md5)
        {
            byte[] text = Encoding.UTF8.GetBytes(OpaqueString(username) + ":" + OpaqueString(realm) + ":" + OpaqueString(password));
            switch (algorithm)
            {
                case StunPasswordAlgorithm.Md5:
                    using (var md5 = MD5.Create())
                        return md5.ComputeHash(text);
                case StunPasswordAlgorithm.Sha256:
                    using (var sha256 = SHA256.Create())
                        return sha256.ComputeHash(text);
                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

        /// <summary>The USERHASH of a username at a realm (RFC 8489 14.4): the SHA-256 of "username:realm".</summary>
        public static byte[] UserHash(string username, string realm)
        {
            using (var sha256 = SHA256.Create())
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(OpaqueString(username) + ":" + OpaqueString(realm)));
        }

        /// <summary>The security features of a nonce that starts with the nonce cookie; null of one that does not.</summary>
        public static StunSecurityFeatures? GetSecurityFeatures(string nonce)
        {
            if (nonce == null || nonce.Length < NonceCookie.Length + 4 || !nonce.StartsWith(NonceCookie, StringComparison.Ordinal))
                return null;
            try
            {
                // 4 characters of base64 of 3 bytes: of padding ("AA=="), fewer, which are no features
                byte[] bits = Convert.FromBase64String(nonce.Substring(NonceCookie.Length, 4));
                if (bits.Length != 3)
                    return null;
                return (StunSecurityFeatures)(bits[0] << 16 | bits[1] << 8 | bits[2]);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        /// <summary>A nonce of the cookie and the features given, then the server's own part.</summary>
        public static string CreateNonce(StunSecurityFeatures features, string rest)
        {
            int bits = (int)features;
            return NonceCookie + Convert.ToBase64String(new[] { (byte)(bits >> 16), (byte)(bits >> 8), (byte)bits }) + rest;
        }
    }
}
