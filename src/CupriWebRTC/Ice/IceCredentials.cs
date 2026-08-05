using System.Security.Cryptography;

namespace CupriWebRTC.Ice;

/// <summary>
/// A pair of ICE credentials (RFC 8445): a username fragment and a password. For an ICE-lite endpoint these are
/// <b>fixed</b> and can be published ahead of time (e.g. in a connection link), because they authenticate nothing on
/// their own — they only key the STUN connectivity-check integrity.
/// </summary>
public sealed record IceCredentials(string Ufrag, string Password)
{
    // RFC 8445 §5.3: ufrag 4–255 chars, password 22–255 chars, from the ICE-char set (ALPHA / DIGIT / '+' / '/').
    private const string IceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>Generates a fresh, spec-conformant ufrag (8 chars) and password (24 chars).</summary>
    public static IceCredentials Generate() => new(RandomToken(8), RandomToken(24));

    private static string RandomToken(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = IceChars[bytes[i] & 0x3F];
        return new string(chars);
    }
}
