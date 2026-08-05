using System.Net;
using System.Text;
using CupriWebRTC.Stun;

namespace CupriWebRTC.Ice;

/// <summary>
/// The ICE-lite server side of connectivity (RFC 8445 §7.3). It validates incoming STUN <b>Binding Requests</b>
/// against our fixed credentials and produces <b>Binding Success</b> responses carrying the peer's reflexive
/// address. It never initiates checks (ICE-lite), so it needs none of the peer's credentials in advance — it learns
/// the peer's address from the datagram source (a peer-reflexive candidate). This class is pure logic; the UDP
/// socket loop and STUN/DTLS demultiplexing live above it.
/// </summary>
public sealed class IceLiteResponder
{
    private readonly byte[] _passwordKey;
    private readonly byte[] _usernamePrefix; // "<ourUfrag>:"

    public IceLiteResponder(IceCredentials local)
    {
        ArgumentNullException.ThrowIfNull(local);
        LocalCredentials = local;
        _passwordKey = Encoding.UTF8.GetBytes(local.Password);
        _usernamePrefix = Encoding.UTF8.GetBytes(local.Ufrag + ":");
    }

    public IceCredentials LocalCredentials { get; }

    public enum Outcome
    {
        /// <summary>Not a STUN Binding Request addressed here — ignore silently.</summary>
        Ignored,

        /// <summary>A Binding Request, but malformed or not addressed to our ufrag.</summary>
        BadRequest,

        /// <summary>MESSAGE-INTEGRITY (or FINGERPRINT) failed — the sender doesn't hold our password.</summary>
        Unauthenticated,

        /// <summary>Valid check — a Binding Success response was produced.</summary>
        Responded,
    }

    /// <summary>
    /// Handles one inbound datagram from <paramref name="remote"/>. Returns the response bytes to send back to that
    /// same address, or <c>null</c> (with <paramref name="outcome"/> explaining why).
    /// </summary>
    public byte[]? Handle(ReadOnlySpan<byte> datagram, IPEndPoint remote, out Outcome outcome)
    {
        ArgumentNullException.ThrowIfNull(remote);

        if (!StunMessage.TryParse(datagram, out var request) || request.MessageType != StunMessageTypes.BindingRequest)
        {
            outcome = Outcome.Ignored;
            return null;
        }

        // USERNAME is "<ourUfrag>:<theirUfrag>" (RFC 8445 §7.2.2); it must be addressed to our ufrag.
        var username = request.Find(StunAttributes.Username);
        if (username is null || !StartsWith(username, _usernamePrefix))
        {
            outcome = Outcome.BadRequest;
            return null;
        }

        // A request sent to us is integrity-protected with OUR password. If a FINGERPRINT is present it must be valid.
        if (!request.VerifyMessageIntegrity(_passwordKey) ||
            (request.Find(StunAttributes.Fingerprint) is not null && !request.VerifyFingerprint()))
        {
            outcome = Outcome.Unauthenticated;
            return null;
        }

        var response = new StunMessage(StunMessageTypes.BindingSuccessResponse, request.TransactionId);
        response.AddXorMappedAddress(remote); // tell the peer the reflexive address we saw it from
        response.AddMessageIntegrity(_passwordKey);
        response.AddFingerprint();

        outcome = Outcome.Responded;
        return response.Encode();
    }

    private static bool StartsWith(byte[] value, byte[] prefix)
        => value.Length >= prefix.Length && value.AsSpan(0, prefix.Length).SequenceEqual(prefix);
}
