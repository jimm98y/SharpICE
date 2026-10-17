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

        /// <summary>The endpoint of a candidate of an IP address; null of one of a name.</summary>
        public IPEndPoint EndPoint => IPAddress.TryParse(Address, out IPAddress address) ? new IPEndPoint(address, Port) : null;

        public bool IsUdp => string.Equals(Transport, "udp", StringComparison.OrdinalIgnoreCase);

        /// <summary>The preference of each type (RFC 8445 5.1.2.2): host first, relayed last.</summary>
        public static int TypePreference(IceCandidateType type) => type switch
        {
            IceCandidateType.Host => 126,
            IceCandidateType.PeerReflexive => 110,
            IceCandidateType.ServerReflexive => 100,
            _ => 0
        };

        /// <summary>The priority of a candidate (RFC 8445 5.1.2.1).</summary>
        public static uint ComputePriority(IceCandidateType type, int localPreference, int component)
            => (uint)((TypePreference(type) << 24) + ((localPreference & 0xFFFF) << 8) + (256 - component));

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
