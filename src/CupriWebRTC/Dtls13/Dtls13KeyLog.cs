namespace CupriWebRTC.Dtls13;

/// <summary>
/// Writes the handshake's traffic secrets in the NSS key-log format that Wireshark reads, when
/// <c>CUPRIWEBRTC_SSLKEYLOG</c> names a path. Point tshark at it with
/// <c>-o tls.keylog_file:&lt;path&gt;</c> alongside a capture from <see cref="Dtls.DtlsPcapTap"/> and the encrypted
/// half of the handshake — EncryptedExtensions, Certificate, CertificateVerify, Finished — becomes readable.
///
/// <para>That is the difference between "the browser rejected something" and knowing which byte of which message it
/// rejected, and it is the only practical way to see a DTLS 1.3 flight the way the peer sees it.</para>
///
/// <para><b>These are the session's live keys.</b> Anything written here deprotects the whole connection, so this is
/// off unless the environment variable is set, and it should never be set anywhere but a developer's machine.</para>
/// </summary>
internal static class Dtls13KeyLog
{
    private static readonly Lock Gate = new();
    private static readonly string? Path = Environment.GetEnvironmentVariable("CUPRIWEBRTC_SSLKEYLOG");

    /// <summary>True when key logging is switched on, so callers can skip the work entirely.</summary>
    public static bool IsEnabled => !string.IsNullOrWhiteSpace(Path);

    /// <summary>Appends one <c>LABEL client_random secret</c> line.</summary>
    public static void Write(string label, ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> secret)
    {
        if (!IsEnabled)
            return;
        var line = $"{label} {Convert.ToHexStringLower(clientRandom)} {Convert.ToHexStringLower(secret)}";
        try
        {
            lock (Gate)
                File.AppendAllText(Path!, line + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Diagnostics must never break the connection they are diagnosing.
        }
    }
}
