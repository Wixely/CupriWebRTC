using System.Linq;
using System.Text;
using CupriWebRTC.Sctp;
using Xunit;

namespace CupriWebRTC.Tests;

public class SctpAssociationTests
{
    private const uint PeerTag = 0xA1B2C3D4;
    private const uint PeerInitialTsn = 1000;

    private static byte[] Packet(uint verificationTag, SctpChunk chunk)
    {
        var packet = new SctpPacket { SourcePort = 5000, DestinationPort = 5000, VerificationTag = verificationTag };
        packet.Chunks.Add(chunk);
        return packet.Encode();
    }

    private static SctpPacket Parse(byte[] bytes)
    {
        Assert.True(SctpPacket.TryParse(bytes, out var packet));
        return packet;
    }

    [Fact]
    public void FullResponderFlow_Handshake_Dcep_DataBothWays()
    {
        var association = new SctpAssociation();

        // 1. INIT -> INIT-ACK (with a state cookie), carrying the peer's verification tag.
        var initChunk = new SctpChunk { Type = SctpChunkType.Init, Value = new InitData(PeerTag, 65536, 1024, 1024, PeerInitialTsn).Encode() };
        var afterInit = association.HandlePacket(Packet(0, initChunk));
        var initAckPacket = Parse(Assert.Single(afterInit));
        Assert.Equal(PeerTag, initAckPacket.VerificationTag);
        var initAckChunk = Assert.Single(initAckPacket.Chunks);
        Assert.Equal(SctpChunkType.InitAck, initAckChunk.Type);
        var initAck = InitData.Decode(initAckChunk.Value);
        var localTag = initAck.InitiateTag;
        Assert.NotNull(initAck.StateCookie);

        // 2. COOKIE-ECHO -> COOKIE-ACK; association established.
        var cookieEcho = new SctpChunk { Type = SctpChunkType.CookieEcho, Value = initAck.StateCookie! };
        var afterCookie = association.HandlePacket(Packet(localTag, cookieEcho));
        Assert.Equal(SctpChunkType.CookieAck, Assert.Single(Parse(Assert.Single(afterCookie)).Chunks).Type);
        Assert.True(association.IsEstablished);

        // 3. DATA (DCEP DATA_CHANNEL_OPEN) -> DATA_CHANNEL_ACK + SACK, and ChannelOpened fires.
        SctpDataChannel? opened = null;
        association.ChannelOpened += channel => opened = channel;
        var openBody = Dcep.BuildOpen(new Dcep.Open(ChannelType: 0, Priority: 0, Reliability: 0, Label: "chat", Protocol: ""));
        var openChunk = new SctpChunk
        {
            Type = SctpChunkType.Data,
            Flags = DataChunk.FlagBeginning | DataChunk.FlagEnding,
            Value = new DataChunk(PeerInitialTsn, StreamId: 0, StreamSequence: 0, Dcep.Ppid, openBody).Encode(),
        };
        var afterOpen = association.HandlePacket(Packet(localTag, openChunk));

        Assert.NotNull(opened);
        Assert.Equal("chat", opened!.Label);
        Assert.Contains(afterOpen, p => Parse(p).Chunks.Any(c => c.Type == SctpChunkType.Sack));
        var ackPacket = Parse(afterOpen.Single(p => Parse(p).Chunks.Any(c => c.Type == SctpChunkType.Data)));
        Assert.Equal(PeerTag, ackPacket.VerificationTag);
        var ackData = DataChunk.Decode(ackPacket.Chunks.Single(c => c.Type == SctpChunkType.Data).Value);
        Assert.Equal(Dcep.Ppid, ackData.Ppid);
        Assert.Equal(Dcep.MessageAck, ackData.UserData[0]);

        // 4. DATA (application string) -> SACK, and MessageReceived fires.
        (ushort Stream, uint Ppid, byte[] Data)? received = null;
        association.MessageReceived += (stream, ppid, data) => received = (stream, ppid, data);
        var messageChunk = new SctpChunk
        {
            Type = SctpChunkType.Data,
            Flags = DataChunk.FlagBeginning | DataChunk.FlagEnding,
            Value = new DataChunk(PeerInitialTsn + 1, StreamId: 0, StreamSequence: 1, Dcep.PpidString, "hello"u8.ToArray()).Encode(),
        };
        var afterMessage = association.HandlePacket(Packet(localTag, messageChunk));

        Assert.NotNull(received);
        Assert.Equal("hello", Encoding.UTF8.GetString(received!.Value.Data));
        Assert.Contains(afterMessage, p => Parse(p).Chunks.Any(c => c.Type == SctpChunkType.Sack));

        // 5. Send a message the other way — a DATA chunk carrying the peer's verification tag.
        var outbound = association.SendMessage(streamId: 0, Dcep.PpidString, "hi there"u8.ToArray());
        var outboundPacket = Parse(Assert.Single(outbound));
        Assert.Equal(PeerTag, outboundPacket.VerificationTag);
        var outboundData = DataChunk.Decode(outboundPacket.Chunks.Single(c => c.Type == SctpChunkType.Data).Value);
        Assert.Equal(Dcep.PpidString, outboundData.Ppid);
        Assert.Equal("hi there", Encoding.UTF8.GetString(outboundData.UserData));
    }

    [Fact]
    public void TwoAssociations_Handshake_AndExchangeMessagesBothWays()
    {
        var initiator = new SctpAssociation();
        var responder = new SctpAssociation();

        // Four-way handshake, pumping one packet at a time between the two associations.
        var init = initiator.Associate();
        var initAck = responder.HandlePacket(Assert.Single(init));
        var cookieEcho = initiator.HandlePacket(Assert.Single(initAck));
        var cookieAck = responder.HandlePacket(Assert.Single(cookieEcho));
        initiator.HandlePacket(Assert.Single(cookieAck));

        Assert.True(initiator.IsEstablished);
        Assert.True(responder.IsEstablished);

        // initiator -> responder
        byte[]? atResponder = null;
        responder.MessageReceived += (_, _, data) => atResponder = data;
        var toResponder = initiator.SendMessage(0, Dcep.PpidString, "ping"u8.ToArray());
        var responderAcks = responder.HandlePacket(Assert.Single(toResponder));
        Assert.Equal("ping", Encoding.UTF8.GetString(atResponder!));
        initiator.HandlePacket(responderAcks.Single(p => Parse(p).Chunks.Any(c => c.Type == SctpChunkType.Sack)));

        // responder -> initiator
        byte[]? atInitiator = null;
        initiator.MessageReceived += (_, _, data) => atInitiator = data;
        var toInitiator = responder.SendMessage(0, Dcep.PpidString, "pong"u8.ToArray());
        initiator.HandlePacket(Assert.Single(toInitiator));
        Assert.Equal("pong", Encoding.UTF8.GetString(atInitiator!));
    }

    [Fact]
    public void Data_BeforeHandshake_IsIgnored()
    {
        var association = new SctpAssociation();
        var dataChunk = new SctpChunk { Type = SctpChunkType.Data, Value = new DataChunk(1, 0, 0, Dcep.PpidString, "x"u8.ToArray()).Encode() };
        Assert.Empty(association.HandlePacket(Packet(1234, dataChunk)));
        Assert.False(association.IsEstablished);
    }
}
