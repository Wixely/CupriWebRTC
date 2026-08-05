using System.Net;
using System.Text;
using CupriWebRTC.Ice;
using CupriWebRTC.Stun;
using Xunit;

namespace CupriWebRTC.Tests;

public class IceLiteResponderTests
{
    private static readonly IceCredentials Local = new("svr0ufrag", "server-password-1234567890");
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("203.0.113.7"), 51820);

    private static byte[] BindingRequest(string username, byte[] integrityKey, bool fingerprint = true)
    {
        var request = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
        request.Add(StunAttributes.Username, Encoding.UTF8.GetBytes(username));
        request.AddMessageIntegrity(integrityKey);
        if (fingerprint)
            request.AddFingerprint();
        return request.Encode();
    }

    [Fact]
    public void ValidCheck_ProducesVerifiableBindingSuccess()
    {
        var responder = new IceLiteResponder(Local);
        var key = Encoding.UTF8.GetBytes(Local.Password);
        // A controlling agent (browser) sends the check with USERNAME "< our ufrag>:<their ufrag>" and MESSAGE-INTEGRITY
        // keyed with OUR password (the peer being tested).
        var request = BindingRequest($"{Local.Ufrag}:browserUfrag", key);

        var response = responder.Handle(request, Remote, out var outcome, out var remoteUfrag);

        Assert.Equal(IceLiteResponder.Outcome.Responded, outcome);
        Assert.Equal("browserUfrag", remoteUfrag);             // the peer's own ufrag, extracted for session keying
        Assert.True(StunMessage.TryParse(response!, out var parsed));
        Assert.Equal(StunMessageTypes.BindingSuccessResponse, parsed.MessageType);
        Assert.Equal(Remote, parsed.GetXorMappedAddress());   // reflexive address echoed back
        Assert.True(parsed.VerifyMessageIntegrity(key));       // response signed with our password
        Assert.True(parsed.VerifyFingerprint());
    }

    [Fact]
    public void WrongPassword_IsUnauthenticated()
    {
        var responder = new IceLiteResponder(Local);
        var request = BindingRequest($"{Local.Ufrag}:browserUfrag", Encoding.UTF8.GetBytes("not-our-password"));
        Assert.Null(responder.Handle(request, Remote, out var outcome, out _));
        Assert.Equal(IceLiteResponder.Outcome.Unauthenticated, outcome);
    }

    [Fact]
    public void UsernameNotAddressedToUs_IsBadRequest()
    {
        var responder = new IceLiteResponder(Local);
        var request = BindingRequest("someoneElse:browserUfrag", Encoding.UTF8.GetBytes(Local.Password));
        Assert.Null(responder.Handle(request, Remote, out var outcome, out _));
        Assert.Equal(IceLiteResponder.Outcome.BadRequest, outcome);
    }

    [Fact]
    public void NonBindingRequest_IsIgnored()
    {
        var responder = new IceLiteResponder(Local);
        Assert.Null(responder.Handle([1, 2, 3], Remote, out var outcome, out _));
        Assert.Equal(IceLiteResponder.Outcome.Ignored, outcome);
    }

    [Fact]
    public void Generated_Credentials_AreSpecConformantLength()
    {
        var creds = IceCredentials.Generate();
        Assert.True(creds.Ufrag.Length is >= 4 and <= 255);
        Assert.True(creds.Password.Length is >= 22 and <= 255);
    }
}
