using System.Buffers.Binary;
using System.Numerics;

namespace CupriWebRTC.Dtls13.Crypto;

/// <summary>
/// The raw ChaCha20 block function (RFC 8439 §2.3) — the <em>only</em> primitive this stack implements rather than
/// sources from a library, and only because it has to: DTLS 1.3's record-number mask for the ChaCha20-Poly1305 suite
/// is <c>ChaCha20(sn_key, counter, nonce)</c> at an arbitrary counter taken from the ciphertext (RFC 9147 §4.2.3),
/// and neither BouncyCastle nor the BCL exposes a keystream block at a caller-chosen counter — their stream ciphers
/// only ever start at zero and step forward.
///
/// <para>What makes this acceptable where hand-rolling AES or a curve would not: ChaCha20's core is a fixed public
/// permutation of add/xor/rotate over 16 words. It has no secret-dependent branch, no table lookup and no
/// variable-time arithmetic, so it is constant-time by construction, and RFC 8439 §2.3.2 gives a byte-exact
/// known-answer vector for it (see the unit tests).</para>
/// </summary>
internal static class ChaCha20Block
{
    /// <summary>"expand 32-byte k" — the ChaCha constants that occupy the first four state words.</summary>
    private static ReadOnlySpan<byte> Sigma => "expand 32-byte k"u8;

    /// <summary>One 64-byte keystream block for a 32-byte key, a 32-bit block counter and a 12-byte nonce.</summary>
    public static byte[] Generate(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != 32)
            throw new ArgumentException("ChaCha20 needs a 32-byte key", nameof(key));
        if (nonce.Length != 12)
            throw new ArgumentException("ChaCha20 needs a 12-byte nonce", nameof(nonce));

        Span<uint> state = stackalloc uint[16];
        for (var i = 0; i < 4; i++)
            state[i] = BinaryPrimitives.ReadUInt32LittleEndian(Sigma[(i * 4)..]);
        for (var i = 0; i < 8; i++)
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        state[12] = counter;
        for (var i = 0; i < 3; i++)
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(i * 4)..]);

        Span<uint> working = stackalloc uint[16];
        state.CopyTo(working);
        for (var round = 0; round < 10; round++) // 20 rounds = 10 column/diagonal double-rounds
        {
            QuarterRound(working, 0, 4, 8, 12);
            QuarterRound(working, 1, 5, 9, 13);
            QuarterRound(working, 2, 6, 10, 14);
            QuarterRound(working, 3, 7, 11, 15);
            QuarterRound(working, 0, 5, 10, 15);
            QuarterRound(working, 1, 6, 11, 12);
            QuarterRound(working, 2, 7, 8, 13);
            QuarterRound(working, 3, 4, 9, 14);
        }

        var block = new byte[64];
        for (var i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(i * 4), working[i] + state[i]);
        return block;
    }

    private static void QuarterRound(Span<uint> s, int a, int b, int c, int d)
    {
        s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 7);
    }
}
