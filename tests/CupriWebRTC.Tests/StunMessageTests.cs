using System.Net;
using System.Text;
using CupriWebRTC.Stun;
using Xunit;

namespace CupriWebRTC.Tests;

public class StunMessageTests
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("VOkJxbRl1RmTxUk/WvJxBt"); // arbitrary ICE-style pwd

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
