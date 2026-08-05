namespace CupriWebRTC;

/// <summary>
/// The static parameters a peer needs to open a WebRTC DataChannel to a <see cref="WebRtcListener"/> with no
/// signalling server: the fixed ICE credentials, the DTLS certificate fingerprint, and the UDP port. Publish these
/// (e.g. in a signed link) so a browser can preload them as the remote description and dial the endpoint directly.
/// </summary>
public sealed record WebRtcEndpointParameters(
    string IceUfrag,
    string IcePassword,
    string FingerprintAlgorithm,
    byte[] Fingerprint,
    int Port);
