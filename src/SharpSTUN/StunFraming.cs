// SharpSTUN
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

namespace SharpSTUN
{
    /// <summary>
    /// What else shares a transport of STUN, as RFC 7983 tells it of its first byte: ChannelData of TURN (RFC 8656 12.4) - of
    /// 0x40 to 0x4F - which a stream frames of its own length, padded to 4 bytes (RFC 8656 12.5).
    /// </summary>
    public static class StunFraming
    {
        /// <summary>The length of a ChannelData message's header: its channel number and its length.</summary>
        public const int ChannelDataHeaderLength = 4;

        /// <summary>Whether data is of a ChannelData message: of its first byte, of 0x40 to 0x4F (RFC 7983, RFC 8656 12).</summary>
        public static bool IsChannelData(byte first) => first >= 0x40 && first <= 0x4F;

        /// <summary>
        /// The bytes a ChannelData message of a length of data takes: over a stream, padded to 4 bytes (RFC 8656 12.5); over
        /// datagrams, as it is.
        /// </summary>
        public static int ChannelDataSize(int dataLength, bool padded)
        {
            int size = ChannelDataHeaderLength + dataLength;
            return padded ? (size + 3) & ~3 : size;
        }
    }
}
