// SharpICE
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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace SharpICE
{
    /// <summary>The type of a candidate (RFC 8445 5.1.1).</summary>
    public enum IceCandidateType
    {
        Host,
        ServerReflexive,
        PeerReflexive,
        Relayed
    }

    /// <summary>
    /// An ICE candidate (RFC 8445 5.1), as SDP carries it in an "a=candidate" line (RFC 8839 5.1):
    /// <code>candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host</code>
    /// </summary>
    public sealed class IceCandidate
    {
        public const int RtpComponent = 1;

        public string Foundation { get; set; }
        public int Component { get; set; } = RtpComponent;
        public string Transport { get; set; } = "udp";
        public uint Priority { get; set; }

        /// <summary>The address: an IP address, or - of a browser that hides its own - a name of mDNS that ends in ".local".</summary>
        public string Address { get; set; }
        public int Port { get; set; }
        public IceCandidateType Type { get; set; }
        public string RelatedAddress { get; set; }
        public int RelatedPort { get; set; }

        /// <summary>What follows the fields above, name and value: "generation 0", "ufrag abcd", "network-id 1".</summary>
        public List<KeyValuePair<string, string>> Extensions { get; } = new List<KeyValuePair<string, string>>();

        /// <summary>The endpoint of a candidate of an IP address; null of one of a name, or of a port that is none.</summary>
        public IPEndPoint EndPoint => Port >= 0 && Port <= IPEndPoint.MaxPort && IPAddress.TryParse(Address, out IPAddress address) ? new IPEndPoint(address, Port) : null;

        public bool IsUdp => string.Equals(Transport, "udp", StringComparison.OrdinalIgnoreCase);

        public bool IsTcp => string.Equals(Transport, "tcp", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Of ICE-TCP over TLS: a candidate of TCP, as RFC 6544 has one - "tcptype" and RFC 4571's framing - each connection of
        /// it of TLS, the active side the TLS client. Its transport "tls" is no registered one: an agent that does not know it
        /// leaves it out (RFC 8839 5.1), rather than connecting to it without TLS.
        /// </summary>
        public bool IsTls => string.Equals(Transport, "tls", StringComparison.OrdinalIgnoreCase);

        /// <summary>Of TCP, or of TLS over it: of connections, rather than of datagrams.</summary>
        public bool IsStream => IsTcp || IsTls;

        /// <summary>Whether two candidates are of one transport - UDP, TCP or TLS - which those of a pair are to be.</summary>
        public static bool SameTransport(IceCandidate a, IceCandidate b) => a.IsUdp == b.IsUdp && a.IsTcp == b.IsTcp && a.IsTls == b.IsTls;

        public const string TcpActive = "active";
        public const string TcpPassive = "passive";
        public const string TcpSimultaneousOpen = "so";

        /// <summary>
        /// Of a TCP candidate (RFC 6544 4.5), or of TLS, its "tcptype": "active" - it connects, of port 9 - "passive" - it is connected
        /// to - or "so", simultaneous-open. Kept among <see cref="Extensions"/>, where SDP has it.
        /// </summary>
        public string TcpType
        {
            get
            {
                foreach (var extension in Extensions)
                {
                    if (extension.Key == "tcptype")
                        return extension.Value;
                }
                return null;
            }
            set
            {
                int index = Extensions.FindIndex(e => e.Key == "tcptype");
                if (index >= 0)
                    Extensions.RemoveAt(index);
                if (value != null)
                    Extensions.Insert(index >= 0 ? index : 0, new KeyValuePair<string, string>("tcptype", value));
            }
        }

        /// <summary>
        /// The preference of each type (RFC 8445 5.1.2.2): host first, relayed last; of TCP, each below every one of UDP but
        /// relayed ones, as Chrome has them, for UDP is to be preferred (RFC 6544 4.2).
        /// </summary>
        public static int TypePreference(IceCandidateType type, bool tcp = false) => type switch
        {
            IceCandidateType.Host => tcp ? 90 : 126,
            IceCandidateType.PeerReflexive => tcp ? 80 : 110,
            IceCandidateType.ServerReflexive => tcp ? 65 : 100,
            _ => 0
        };

        /// <summary>
        /// The preference of each type of a transport - "udp", "tcp" or "tls": of TLS, each below TCP's of the type, as TLS is
        /// of a peer that TCP alone does not reach either, past a firewall that lets TLS alone through.
        /// </summary>
        public static int TypePreference(IceCandidateType type, string transport)
        {
            if (string.Equals(transport, "tls", StringComparison.OrdinalIgnoreCase))
            {
                return type switch
                {
                    IceCandidateType.Host => 85,
                    IceCandidateType.PeerReflexive => 75,
                    IceCandidateType.ServerReflexive => 60,
                    _ => 0
                };
            }
            return TypePreference(type, string.Equals(transport, "tcp", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>The priority of a candidate (RFC 8445 5.1.2.1), of UDP, or of TCP.</summary>
        public static uint ComputePriority(IceCandidateType type, int localPreference, int component, bool tcp = false)
            => (uint)((TypePreference(type, tcp) << 24) + ((localPreference & 0xFFFF) << 8) + (256 - component));

        /// <summary>The priority of a candidate (RFC 8445 5.1.2.1) of a transport: "udp", "tcp" or "tls".</summary>
        public static uint ComputePriority(IceCandidateType type, int localPreference, int component, string transport)
            => (uint)((TypePreference(type, transport) << 24) + ((localPreference & 0xFFFF) << 8) + (256 - component));

        /// <summary>
        /// The local preference of a TCP candidate (RFC 6544 4.2): 2^13 times its direction's preference - of a host candidate,
        /// active 6, passive 4, simultaneous-open 2 - and the preference of its address, below 2^13.
        /// </summary>
        public static int TcpLocalPreference(string tcpType, int otherPreference)
        {
            int direction = tcpType == TcpActive ? 6 : tcpType == TcpPassive ? 4 : 2;
            return (direction << 13) + (otherPreference & 0x1FFF);
        }

        /// <summary>The local preference a candidate's priority is of: its bits 8 to 23.</summary>
        public int LocalPreference => (int)((Priority >> 8) & 0xFFFF);

        public static string TypeName(IceCandidateType type) => type switch
        {
            IceCandidateType.Host => "host",
            IceCandidateType.ServerReflexive => "srflx",
            IceCandidateType.PeerReflexive => "prflx",
            _ => "relay"
        };

        private static IceCandidateType ParseType(string name) => name switch
        {
            "host" => IceCandidateType.Host,
            "srflx" => IceCandidateType.ServerReflexive,
            "prflx" => IceCandidateType.PeerReflexive,
            "relay" => IceCandidateType.Relayed,
            _ => throw new FormatException($"Unknown candidate type '{name}'.")
        };

        /// <summary>
        /// A candidate of its SDP line: of "a=candidate:...", "candidate:..." or the attribute's value alone. Null of one that is
        /// not well formed.
        /// </summary>
        public static IceCandidate Parse(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;
            string text = line.Trim();
            if (text.StartsWith("a=", StringComparison.Ordinal))
                text = text.Substring(2);
            if (text.StartsWith("candidate:", StringComparison.OrdinalIgnoreCase))
                text = text.Substring("candidate:".Length);

            string[] parts = text.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 8 || parts[6] != "typ")
                return null;

            try
            {
                var candidate = new IceCandidate
                {
                    Foundation = parts[0],
                    Component = int.Parse(parts[1], CultureInfo.InvariantCulture),
                    Transport = parts[2],
                    Priority = uint.Parse(parts[3], CultureInfo.InvariantCulture),
                    Address = parts[4],
                    Port = int.Parse(parts[5], CultureInfo.InvariantCulture),
                    Type = ParseType(parts[7]),
                };

                for (int i = 8; i + 1 < parts.Length; i += 2)
                {
                    if (parts[i] == "raddr")
                        candidate.RelatedAddress = parts[i + 1];
                    else if (parts[i] == "rport")
                        candidate.RelatedPort = int.Parse(parts[i + 1], CultureInfo.InvariantCulture);
                    else
                        candidate.Extensions.Add(new KeyValuePair<string, string>(parts[i], parts[i + 1]));
                }
                return candidate;
            }
            catch (FormatException)
            {
                return null;
            }
            catch (OverflowException)
            {
                return null;
            }
        }

        /// <summary>The attribute's value, without "a=": "candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host".</summary>
        public override string ToString()
        {
            var sb = new StringBuilder("candidate:");
            sb.Append(Foundation).Append(' ')
                .Append(Component.ToString(CultureInfo.InvariantCulture)).Append(' ')
                .Append(Transport).Append(' ')
                .Append(Priority.ToString(CultureInfo.InvariantCulture)).Append(' ')
                .Append(Address).Append(' ')
                .Append(Port.ToString(CultureInfo.InvariantCulture))
                .Append(" typ ").Append(TypeName(Type));
            if (RelatedAddress != null)
            {
                sb.Append(" raddr ").Append(RelatedAddress)
                    .Append(" rport ").Append(RelatedPort.ToString(CultureInfo.InvariantCulture));
            }
            foreach (var extension in Extensions)
                sb.Append(' ').Append(extension.Key).Append(' ').Append(extension.Value);
            return sb.ToString();
        }
    }
}
