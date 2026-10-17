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
using System.Net;

namespace SharpICE
{
    /// <summary>The role of an agent (RFC 8445 6.1.1): the controlling agent nominates the pair both use.</summary>
    public enum IceRole
    {
        Controlling,
        Controlled
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

        /// <summary>Whether to gather candidates of IPv6 addresses too, link-local ones left out.</summary>
        public bool IncludeIPv6 { get; set; } = false;

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
