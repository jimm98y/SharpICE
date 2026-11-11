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

using System;
using System.Globalization;
using System.Net;

namespace SharpStunCommon
{
    /// <summary>
    /// A STUN URI (RFC 7064) - "stun:host[:port]" or "stuns:host[:port]" - or a TURN URI (RFC 7065), of a "?transport=udp" or
    /// "?transport=tcp" too. A host of no scheme, "host[:port]", is taken as "stun:". An IPv6 address is in brackets.
    /// </summary>
    public sealed class StunUri
    {
        public const int DefaultPort = 3478;
        public const int DefaultSecurePort = 5349;

        /// <summary>"stun", "stuns", "turn" or "turns".</summary>
        public string Scheme { get; private set; }

        /// <summary>The host name, or the IP address, without brackets.</summary>
        public string Host { get; private set; }

        /// <summary>The port the URI gives; null of none, of which a server's is looked up of DNS SRV, or else the default.</summary>
        public int? Port { get; private set; }

        /// <summary>The transport of a TURN URI's "?transport="; null of none.</summary>
        public string Transport { get; private set; }

        /// <summary>Of TLS (or DTLS): "stuns", "turns".</summary>
        public bool IsSecure => Scheme == "stuns" || Scheme == "turns";

        public bool IsTurn => Scheme == "turn" || Scheme == "turns";

        /// <summary>
        /// "udp" or "tcp": the transport given, else UDP of "stun" and "turn", and TCP - TLS over it - of "stuns" and "turns",
        /// whose DTLS this library does not do.
        /// </summary>
        public string TransportProtocol => Transport ?? (IsSecure ? "tcp" : "udp");

        /// <summary>The port given, else the default one of the scheme (RFC 8489 18.6).</summary>
        public int EffectivePort => Port ?? (IsSecure ? DefaultSecurePort : DefaultPort);

        /// <summary>The address of a host that is one; null of a name.</summary>
        public IPAddress Address => IPAddress.TryParse(Host, out IPAddress address) ? address : null;

        public static StunUri Parse(string uri)
        {
            if (!TryParse(uri, out StunUri parsed, out string error))
                throw new FormatException(error);
            return parsed;
        }

        public static bool TryParse(string uri, out StunUri parsed) => TryParse(uri, out parsed, out _);

        private static bool TryParse(string uri, out StunUri parsed, out string error)
        {
            parsed = null;
            if (string.IsNullOrWhiteSpace(uri))
            {
                error = "A STUN URI is of a host.";
                return false;
            }

            string text = uri.Trim();
            string scheme = "stun";
            int colon = text.IndexOf(':');
            if (colon > 0)
            {
                string candidate = text.Substring(0, colon).ToLowerInvariant();
                if (candidate == "stun" || candidate == "stuns" || candidate == "turn" || candidate == "turns")
                {
                    scheme = candidate;
                    text = text.Substring(colon + 1);
                }
            }

            string transport = null;
            int query = text.IndexOf('?');
            if (query >= 0)
            {
                string parameter = text.Substring(query + 1);
                text = text.Substring(0, query);
                const string Key = "transport=";
                if (!parameter.StartsWith(Key, StringComparison.OrdinalIgnoreCase) || (scheme != "turn" && scheme != "turns"))
                {
                    error = $"Of {uri}, a query other than a TURN URI's transport.";
                    return false;
                }
                transport = parameter.Substring(Key.Length).ToLowerInvariant();
                if (transport != "udp" && transport != "tcp")
                {
                    error = $"Of {uri}, the transport {transport}: udp or tcp.";
                    return false;
                }
            }

            string host;
            string port = null;
            if (text.StartsWith("[", StringComparison.Ordinal))
            {
                int end = text.IndexOf(']');
                if (end < 0)
                {
                    error = $"Of {uri}, an IPv6 address of no closing bracket.";
                    return false;
                }
                host = text.Substring(1, end - 1);
                if (end + 1 < text.Length)
                {
                    if (text[end + 1] != ':')
                    {
                        error = $"Of {uri}, what follows the address.";
                        return false;
                    }
                    port = text.Substring(end + 2);
                }
                if (!IPAddress.TryParse(host, out _))
                {
                    error = $"Of {uri}, no IPv6 address in the brackets.";
                    return false;
                }
            }
            else
            {
                int portColon = text.LastIndexOf(':');
                if (portColon >= 0 && text.IndexOf(':') != portColon)
                {
                    error = $"Of {uri}, an IPv6 address not in brackets.";
                    return false;
                }
                host = portColon >= 0 ? text.Substring(0, portColon) : text;
                port = portColon >= 0 ? text.Substring(portColon + 1) : null;
            }

            int? number = null;
            if (port != null)
            {
                if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value < 1 || value > 65535)
                {
                    error = $"Of {uri}, the port {port}.";
                    return false;
                }
                number = value;
            }
            if (host.Length == 0 || host.IndexOf('/') >= 0)
            {
                error = $"Of {uri}, no host.";
                return false;
            }

            parsed = new StunUri { Scheme = scheme, Host = host, Port = number, Transport = transport };
            error = null;
            return true;
        }

        public override string ToString()
        {
            string host = Address?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + Host + "]" : Host;
            return Scheme + ":" + host + (Port.HasValue ? ":" + Port.Value.ToString(CultureInfo.InvariantCulture) : "")
                + (Transport != null ? "?transport=" + Transport : "");
        }
    }
}
