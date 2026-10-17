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
using System.Net;

namespace SharpICE
{
    /// <summary>The state of a candidate pair (RFC 8445 6.1.2.6).</summary>
    public enum IceCandidatePairState
    {
        Frozen,
        Waiting,
        InProgress,
        Succeeded,
        Failed
    }

    /// <summary>
    /// A pair of a local candidate - of the socket the checks are sent from - and a remote candidate (RFC 8445 6.1.2): what is
    /// checked, and of the pair selected, what the data goes by.
    /// </summary>
    public sealed class IceCandidatePair
    {
        internal IceCandidatePair(IceAgent.LocalBase local, IceCandidate remote, IPEndPoint remoteEndPoint)
        {
            Base = local;
            Remote = remote;
            RemoteEndPoint = remoteEndPoint;
        }

        internal IceAgent.LocalBase Base { get; }

        /// <summary>The local candidate whose socket the pair's checks and data are sent from.</summary>
        public IceCandidate Local => Base.Candidate;

        public IceCandidate Remote { get; }

        public IPEndPoint RemoteEndPoint { get; }

        public IPEndPoint LocalEndPoint => Base.EndPoint;

        public IceCandidatePairState State { get; internal set; } = IceCandidatePairState.Waiting;

        /// <summary>Whether the controlling agent nominated it (RFC 8445 8.1.1): of a check of USE-CANDIDATE that succeeded.</summary>
        public bool Nominated { get; internal set; }

        /// <summary>The pair's priority (RFC 8445 6.1.2.3): of the controlling agent's candidate first.</summary>
        public ulong Priority { get; internal set; }

        /// <summary>When the last check on it succeeded, or a check of the peer's on it came: its consent (RFC 7675).</summary>
        public DateTime LastConsent { get; internal set; } = DateTime.MinValue;

        /// <summary>When a check of ours on it last succeeded; <see cref="DateTime.MinValue"/> of none.</summary>
        public DateTime LastSucceeded { get; internal set; } = DateTime.MinValue;

        // the check in flight, and whether it is to nominate the pair
        internal byte[] Request;
        internal byte[] TransactionId;
        internal int Transmissions;
        internal TimeSpan Timeout;
        internal DateTime NextTransmission;
        internal bool Nominating;

        internal static ulong ComputePriority(uint controlling, uint controlled)
            => ((ulong)Math.Min(controlling, controlled) << 32) + 2UL * Math.Max(controlling, controlled) + (controlling > controlled ? 1UL : 0UL);

        public override string ToString() => $"{LocalEndPoint} -> {RemoteEndPoint} ({State}{(Nominated ? ", nominated" : "")})";
    }
}
