using System.Text;
using CupriWebRTC.Sctp;
using Xunit;

namespace CupriWebRTC.Tests;

public class SctpTransportTests
{
    [Fact]
    public void TwoTransports_OverDatagramPair_HandshakeAndMessage()
    {
        var (a, b) = InMemoryDatagramTransport.CreatePair();
        using var initiator = new SctpTransport(a, new SctpAssociation());
        using var responder = new SctpTransport(b, new SctpAssociation());

        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        responder.MessageReceived += (_, _, data) => received.TrySetResult(data);

        responder.Start();
        initiator.Start();
        initiator.Associate();

        // The four-way handshake runs on the background loops; wait for it to settle.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!initiator.IsEstablished && DateTime.UtcNow < deadline)
            Thread.Sleep(10);
        Assert.True(initiator.IsEstablished, "handshake did not complete");

        initiator.SendMessage(0, Dcep.PpidString, "over-the-wire"u8.ToArray());

        Assert.True(received.Task.Wait(TimeSpan.FromSeconds(5)), "message not received");
        Assert.Equal("over-the-wire", Encoding.UTF8.GetString(received.Task.Result));
    }
}
