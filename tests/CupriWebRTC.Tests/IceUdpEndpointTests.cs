using System.Net;
using System.Net.Sockets;
using System.Text;
using CupriWebRTC.Ice;
using CupriWebRTC.Stun;
using Xunit;

namespace CupriWebRTC.Tests;

public class IceUdpEndpointTests
{
    [Fact]
    public async Task RespondsToStunBindingCheck_OverRealUdp_AndLearnsPeer()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ct = cts.Token;

        var local = new IceCredentials("svr0ufrag", "server-password-1234567890");
        await using var endpoint = new IceUdpEndpoint(local, new IPEndPoint(IPAddress.Loopback, 0));
        var run = endpoint.RunAsync(ct);

        using var client = new UdpClient();
        var key = Encoding.UTF8.GetBytes(local.Password);
        var request = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
        request.Add(StunAttributes.Username, Encoding.UTF8.GetBytes($"{local.Ufrag}:browser"));
        request.AddMessageIntegrity(key);
        request.AddFingerprint();

        await client.SendAsync(request.Encode(), endpoint.LocalEndPoint, ct);
        var reply = await client.ReceiveAsync(ct);

        Assert.True(StunMessage.TryParse(reply.Buffer, out var response));
        Assert.Equal(StunMessageTypes.BindingSuccessResponse, response.MessageType);
        Assert.Equal(request.TransactionId, response.TransactionId);
        Assert.True(response.VerifyMessageIntegrity(key));
        Assert.NotNull(endpoint.SelectedRemote);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task ForwardsDtlsDatagram_ToSubscriber()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ct = cts.Token;

        var local = IceCredentials.Generate();
        await using var endpoint = new IceUdpEndpoint(local, new IPEndPoint(IPAddress.Loopback, 0));

        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        endpoint.DtlsDatagramReceived += (data, _) => received.TrySetResult(data.ToArray());
        var run = endpoint.RunAsync(ct);

        using var client = new UdpClient();
        // First byte 22 (0x16) = DTLS handshake record per RFC 7983 demux.
        await client.SendAsync(new byte[] { 22, 0xfe, 0xff, 0, 0 }, endpoint.LocalEndPoint, ct);

        var got = await received.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
        Assert.Equal(22, got[0]);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }
}
