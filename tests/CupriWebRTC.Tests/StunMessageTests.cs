using System.Net;
using System.Text;
using CupriWebRTC.Stun;
using Xunit;

namespace CupriWebRTC.Tests;

public class StunMessageTests
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("VOkJxbRl1RmTxUk/WvJxBt"); // arbitrary ICE-style pwd

    [Fact]
    public void Rfc5769_SampleRequest_IntegrityAndFingerprintVerify()
    {
        // RFC 5769 §2.1 "Sample Request" (short-term credentials). If our code verifies the RFC's own real
        // HMAC-SHA1 MESSAGE-INTEGRITY and CRC-32 FINGERPRINT, our framing (the length-field patching) is proven
        // correct against the authoritative vector — and FINGERPRINT verifying first proves the bytes are exact.
        const string hex =
            "00010058" + "2112a442" + "b7e7a701" + "bc34d686" + "fa87dfae" + // header (type, len, cookie, txn id)
            "80220010" + "5354554e20746573" + "7420636c69656e74" +           // SOFTWARE "STUN test client"
            "00240004" + "6e0001ff" +                                        // PRIORITY
            "80290008" + "932ff9b151263b36" +                               // ICE-CONTROLLED
            "00060009" + "6576746a3a683676" + "59202020" +                  // USERNAME "evtj:h6vY" (+padding)
            "00080014" + "9aeaa70cbfd8cb56" + "781ef2b5b2d3f249" + "c1b571a2" + // MESSAGE-INTEGRITY (HMAC-SHA1)
            "80280004" + "e57a3bcf";                                         // FINGERPRINT (CRC-32)

        var bytes = Convert.FromHexString(hex);
        Assert.True(StunMessage.TryParse(bytes, out var message));
        Assert.Equal(StunMessageTypes.BindingRequest, message.MessageType);
        Assert.Equal("evtj:h6vY", Encoding.UTF8.GetString(message.Find(StunAttributes.Username)!));
        Assert.True(message.VerifyFingerprint());               // exact bytes + correct CRC framing
        Assert.True(message.VerifyMessageIntegrity(Password));  // correct HMAC framing vs. the RFC
    }

    [Fact]
    public void Crc32_MatchesStandardCheckValue()
    {
        // The canonical CRC-32 (IEEE) check value for the ASCII string "123456789" is 0xCBF43926.
        Assert.Equal(0xCBF43926u, Crc32.Compute("123456789"u8));
    }

    [Fact]
    public void BindingRequest_WithIntegrityAndFingerprint_RoundTripsAndVerifies()
    {
        var request = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
        request.Add(StunAttributes.Software, "CupriWebRTC test"u8);
        request.Add(StunAttributes.Username, "evtj:h6vY"u8);
        request.AddMessageIntegrity(Password);
        request.AddFingerprint();

        Assert.True(StunMessage.TryParse(request.Encode(), out var parsed));
        Assert.Equal(StunMessageTypes.BindingRequest, parsed.MessageType);
        Assert.Equal(request.TransactionId, parsed.TransactionId);
        Assert.Equal("evtj:h6vY", Encoding.UTF8.GetString(parsed.Find(StunAttributes.Username)!));

        Assert.True(parsed.VerifyMessageIntegrity(Password));
        Assert.False(parsed.VerifyMessageIntegrity("wrong-password"u8));
        Assert.True(parsed.VerifyFingerprint());
    }

    [Fact]
    public void Fingerprint_IsLastAttribute_AndFailsOnTamper()
    {
        var msg = new StunMessage(StunMessageTypes.BindingSuccessResponse, StunMessage.NewTransactionId());
        msg.Add(StunAttributes.Software, "x"u8);
        msg.AddMessageIntegrity(Password);
        msg.AddFingerprint();
        Assert.Equal(StunAttributes.Fingerprint, msg.Attributes[^1].Type);

        var wire = msg.Encode();
        wire[24] ^= 0xFF; // flip a byte inside the attributes region
        Assert.True(StunMessage.TryParse(wire, out var tampered));
        Assert.False(tampered.VerifyFingerprint());
    }

    [Theory]
    [InlineData("203.0.113.7", 51820)]
    [InlineData("192.168.1.20", 43820)]
    public void XorMappedAddress_IPv4_RoundTrips(string ip, int port)
    {
        var endpoint = new IPEndPoint(IPAddress.Parse(ip), port);
        var response = new StunMessage(StunMessageTypes.BindingSuccessResponse, StunMessage.NewTransactionId());
        response.AddXorMappedAddress(endpoint);

        Assert.True(StunMessage.TryParse(response.Encode(), out var parsed));
        Assert.Equal(endpoint, parsed.GetXorMappedAddress());
    }

    [Fact]
    public void XorMappedAddress_IPv6_RoundTrips()
    {
        var endpoint = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 60000);
        var response = new StunMessage(StunMessageTypes.BindingSuccessResponse, StunMessage.NewTransactionId());
        response.AddXorMappedAddress(endpoint);

        Assert.True(StunMessage.TryParse(response.Encode(), out var parsed));
        Assert.Equal(endpoint, parsed.GetXorMappedAddress());
    }

    [Fact]
    public void TryParse_RejectsWrongMagicCookie()
    {
        var wire = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId()).Encode();
        wire[4] ^= 0xFF; // corrupt the magic cookie
        Assert.False(StunMessage.TryParse(wire, out _));
    }
}
