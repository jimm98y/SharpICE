// SharpICE
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
using System.Collections.Generic;
using System.Net;

namespace SharpICE
{
    /// <summary>The role of an agent (RFC 8445 6.1.1): the controlling agent nominates the pair both use.</summary>
    public enum IceRole
    {
        Controlling,
        Controlled
    }

    /// <summary>A TURN server of the agent's relayed candidates: its URI (RFC 7065), and the long-term credentials of it.</summary>
    public sealed class IceTurnServer
    {
        /// <summary>"turn:host[:port][?transport=udp|tcp]", or "turns:..." of TLS - of DTLS, of "?transport=udp".</summary>
        public string Uri { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public sealed class IceAgentOptions
    {
        /// <summary>
        /// Its role to begin with: of WebRTC, the offerer's agent is controlling, the answerer's controlled. A conflict - both
        /// controlling or both controlled - is resolved by their tie-breakers (RFC 8445 7.3.1.1).
        /// </summary>
        public IceRole Role { get; set; } = IceRole.Controlled;

        /// <summary>The STUN servers its server reflexive candidates are learnt of, as "host:port" or "stun:host:port".</summary>
        public List<string> StunServers { get; } = new List<string>();

        /// <summary>The TURN servers its relayed candidates are allocated of (RFC 8656), a relayed address of UDP of each.</summary>
        public List<IceTurnServer> TurnServers { get; } = new List<IceTurnServer>();

        /// <summary>
        /// Whether to gather relayed candidates alone, as WebRTC's iceTransportPolicy "relay" does: of no host, server
        /// reflexive or TCP one, the local addresses not told of.
        /// </summary>
        public bool RelayOnly { get; set; }

        /// <summary>How long to wait for a TURN server's allocation when gathering.</summary>
        public TimeSpan TurnServerTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>Checks a TURN server's certificate of TLS or DTLS in place of the system's checks; of none, the system's.</summary>
        public System.Net.Security.RemoteCertificateValidationCallback TurnCertificateValidation { get; set; }

        /// <summary>
        /// The DTLS implementation of a TURN server of DTLS ("turns:...?transport=udp"): of
        /// <see cref="SharpStunCommon.DtlsStacks.SharpDtls"/>, the default, DTLS 1.3 and 1.2; of
        /// <see cref="SharpStunCommon.DtlsStacks.BouncyCastle"/>, DTLS 1.2.
        /// </summary>
        public SharpStunCommon.IDtlsStack DtlsStack { get; set; } = SharpStunCommon.DtlsStacks.Default;

        /// <summary>
        /// The TLS implementation of a TURN server of TLS ("turns:..."), and of ICE-TCP over TLS (<see cref="IncludeTls"/>): of
        /// <see cref="SharpStunCommon.TlsStacks.SharpDtls"/>, the default, TLS 1.3 and 1.2; of
        /// <see cref="SharpStunCommon.TlsStacks.BouncyCastle"/>, TLS 1.2; of <see cref="SharpStunCommon.TlsStacks.System"/>,
        /// .NET's SslStream.
        /// </summary>
        public SharpStunCommon.ITlsStack TlsStack { get; set; } = SharpStunCommon.TlsStacks.Default;

        /// <summary>Whether to gather candidates of IPv6 addresses too, link-local ones left out.</summary>
        public bool IncludeIPv6 { get; set; } = true;

        /// <summary>
        /// Whether to gather candidates of the loopback addresses: always where there is no other address, else only if set -
        /// of a peer on the same machine.
        /// </summary>
        public bool IncludeLoopback { get; set; } = false;

        /// <summary>Which of the local addresses to gather candidates of; all, of none given.</summary>
        public Func<IPAddress, bool> AddressFilter { get; set; }

        /// <summary>Whether to gather candidates of UDP: a socket of each address, and the server reflexive ones of it.</summary>
        public bool IncludeUdp { get; set; } = true;

        /// <summary>
        /// Whether to gather candidates of TCP (RFC 6544): of each address, a passive one - a listener the peer connects to -
        /// and an active one, which connects to the peer's passive ones. Of a peer UDP does not reach, as behind a firewall that
        /// lets TCP alone through; UDP's are preferred over them.
        /// </summary>
        public bool IncludeTcp { get; set; } = false;

        /// <summary>
        /// Whether to gather candidates of ICE-TCP over TLS, of SharpDTLS: of each address, a passive and an active one as of
        /// <see cref="IncludeTcp"/>, each connection of them of TLS 1.3 or 1.2 - the active side its client - and of transport
        /// "tls" in SDP. Of a peer past a firewall that lets TLS alone through; TCP's are preferred over them. No other agent
        /// signals these, so both peers are to be of SharpICE.
        /// </summary>
        /// <remarks>
        /// The TLS of them hides the checks and the data from the network, and passes a firewall; it authenticates no one, for
        /// the peer's certificate is known of nothing signalled: what does is ICE's own MESSAGE-INTEGRITY of each check, and
        /// DTLS-SRTP's fingerprint of the media.
        /// </remarks>
        public bool IncludeTls { get; set; } = false;

        /// <summary>
        /// The certificate the passive candidates of TLS answer of, its private key exportable; of none, one of the agent's
        /// own, self-signed.
        /// </summary>
        public System.Security.Cryptography.X509Certificates.X509Certificate2 TlsCertificate { get; set; }

        /// <summary>
        /// Whether the agent is an ICE lite one (RFC 8445 2.5): of host candidates alone, it sends no checks and answers the
        /// peer's, controlled, the pair the peer nominates selected. Of a server of an address the peer reaches; its session
        /// description is to say "a=ice-lite".
        /// </summary>
        public bool Lite { get; set; } = false;

        /// <summary>
        /// Whether to resolve the peer's candidates of mDNS names (".local"), as browsers hide their addresses behind, of a query
        /// of multicast DNS (RFC 6762); else they are left out, and a peer reflexive candidate is learnt of the peer's checks.
        /// </summary>
        public bool ResolveMdns { get; set; } = true;

        /// <summary>How long to wait for the answer to an mDNS query.</summary>
        public TimeSpan MdnsTimeout { get; set; } = TimeSpan.FromSeconds(2);

        /// <summary>
        /// Whether to resolve the peer's candidates of host names of DNS (RFC 8839 5.1) - other than mDNS ones - which no browser
        /// sends: of false, the default, they are left out, as each would make the agent look up a name the peer chose.
        /// </summary>
        public bool ResolveHostNames { get; set; } = false;

        /// <summary>The peer's candidates the agent takes at most - those being resolved of mDNS too; more are left out.</summary>
        public int MaxRemoteCandidates { get; set; } = 100;

        /// <summary>The connections of ICE-TCP its passive candidates take at most at once; more are closed as they come.</summary>
        public int MaxTcpConnections { get; set; } = 32;

        /// <summary>
        /// How long a connection to a passive candidate has to make a pair of its checks: past it, one of none is closed, as
        /// anyone may connect.
        /// </summary>
        public TimeSpan TcpCheckTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Whether to hide the local addresses behind names of mDNS, as browsers do (draft-ietf-mmusic-mdns-ice-candidates): each
        /// host candidate of a random "&lt;uuid&gt;.local" rather than its address, which the agent answers queries of multicast
        /// DNS of; a server reflexive one of "raddr 0.0.0.0 rport 0". A peer on another link resolves none of them, and learns
        /// a peer reflexive candidate of the agent's checks instead.
        /// </summary>
        public bool MdnsCandidates { get; set; } = false;

        /// <summary>
        /// The public addresses of a host behind a NAT that maps each of its ports alike, one to one - a cloud host's, as its
        /// provider tells them: each told of of the port of each socket and TCP listener of its family, as the NAT maps it. Of
        /// a full agent, a server reflexive candidate of the socket's - of no STUN server to learn it of; of a lite one, a host
        /// candidate, as a lite agent has those alone (RFC 8445 2.5). The ports are the sockets' own: of a NAT that forwards a
        /// range, of <see cref="PortMin"/> and <see cref="PortMax"/>.
        /// </summary>
        public IList<IPAddress> PublicAddresses { get; set; } = new List<IPAddress>();

        /// <summary>The ports its sockets are bound to; any the system gives, of 0.</summary>
        public int PortMin { get; set; } = 0;
        public int PortMax { get; set; } = 0;

        /// <summary>The pacing of its checks: one every Ta (RFC 8445 14.2).</summary>
        public TimeSpan CheckInterval { get; set; } = TimeSpan.FromMilliseconds(20);

        /// <summary>The first retransmission timeout of a check, doubled at each retransmission (RFC 8489 6.2.1).</summary>
        public TimeSpan InitialRetransmissionTimeout { get; set; } = TimeSpan.FromMilliseconds(250);

        /// <summary>How many times a check is sent before its pair fails (Rc of RFC 8489 6.2.1).</summary>
        public int MaxTransmissions { get; set; } = 7;

        /// <summary>How long to wait for a STUN server's answer when gathering.</summary>
        public TimeSpan StunServerTimeout { get; set; } = TimeSpan.FromSeconds(1.5);

        /// <summary>How often its consent to send on the selected pair is checked: at random, of 0.8 to 1.2 times this (RFC 7675 5.1: 5 s on average).</summary>
        public TimeSpan ConsentInterval { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>After how long of no consent the connection is disconnected, then failed (RFC 7675 5.1: 30 s).</summary>
        public TimeSpan DisconnectedTimeout { get; set; } = TimeSpan.FromSeconds(10);
        public TimeSpan ConsentTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>The SOFTWARE of its messages; none, of null.</summary>
        public string Software { get; set; } = "SharpICE";

        /// <summary>What it does, a line at a time, of anything given.</summary>
        public Action<string> Trace { get; set; }
    }
}
