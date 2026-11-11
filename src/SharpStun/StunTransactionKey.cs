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
using System.Buffers.Binary;

namespace SharpStun
{
    /// <summary>A transaction ID as a dictionary's key: its 12 bytes as two numbers, of no string of them.</summary>
    internal readonly struct StunTransactionKey : IEquatable<StunTransactionKey>
    {
        private readonly ulong _high;
        private readonly uint _low;

        public StunTransactionKey(ReadOnlySpan<byte> transactionId)
        {
            _high = BinaryPrimitives.ReadUInt64LittleEndian(transactionId);
            _low = BinaryPrimitives.ReadUInt32LittleEndian(transactionId.Slice(8));
        }

        public bool Equals(StunTransactionKey other) => _high == other._high && _low == other._low;

        public override bool Equals(object obj) => obj is StunTransactionKey other && Equals(other);

        public override int GetHashCode() => unchecked((int)_high ^ (int)(_high >> 32) * 31 ^ (int)_low * 17);
    }
}
