namespace SnmpSharpNet.Unit.Tests
{
    using SnmpSharpNet.Types;
    using Xunit;

    public class SnmpPacketUnitTests
    {
        private static readonly byte[] Packet1 =
        {
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
            0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x05, 0x00,
        };

        [Fact]
        public void ParseSnmpGet1()
        {
            var packetVersion = SnmpPacket.GetProtocolVersion(Packet1, Packet1.Length);

            Assert.Equal(ESnmpVersion.Ver1, packetVersion);

            var packet = new SnmpV1Packet();
            packet.Decode(Packet1, Packet1.Length);

            Assert.Equal("public", packet.Community.ToString());

            Assert.True(packet.IsRequest);
            Assert.False(packet.IsResponse);

            Assert.Equal(38, packet.Pdu.RequestId);
            Assert.Equal(EPduErrorStatus.NoError, packet.Pdu.ErrorStatus);
            Assert.Equal(0, packet.Pdu.ErrorIndex);

            Assert.Equal(1, packet.Pdu.VbCount);

            var vb = packet.Pdu.GetVb(0);
            Assert.NotNull(vb);

            Assert.Equal(new Oid("1.3.6.1.2.1.1.2.0"), vb.Oid);
        }

        private static readonly byte[] Packet2 =
        {
            0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02,
            0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12,
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x51, 0x01,
            0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b, 0x02,
            0x02, 0x01,
        };

        [Fact]
        public void ParseSnmResponse2()
        {
            var packetVersion = SnmpPacket.GetProtocolVersion(Packet2, Packet2.Length);

            Assert.Equal(ESnmpVersion.Ver1, packetVersion);

            var packet = new SnmpV1Packet();
            packet.Decode(Packet2, Packet2.Length);

            Assert.Equal("public", packet.Community.ToString());

            Assert.False(packet.IsRequest);
            Assert.True(packet.IsResponse);

            Assert.Equal(38, packet.Pdu.RequestId);
            Assert.Equal(EPduErrorStatus.NoError, packet.Pdu.ErrorStatus);
            Assert.Equal(0, packet.Pdu.ErrorIndex);

            Assert.Equal(1, packet.Pdu.VbCount);

            var vb = packet.Pdu.GetVb(0);
            Assert.NotNull(vb);

            Assert.Equal(new Oid("1.3.6.1.2.1.1.2.0"), vb.Oid);
            Assert.Equal((byte)(EAsnType.Cosntructor | EAsnType.Sequence), vb.Type);
            Assert.Equal((byte)EAsnType.ObjectId, vb.Value.Type);
            Assert.Equal(new Oid("1.3.6.1.4.1.2001.1.1.1.297.93.1.27.2.2.1"), vb.Value);
        }

        private static readonly byte[] Packet7 =
        {
            0x30, 0x60, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x53, 0x02,
            0x01, 0x29, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x48, 0x30, 0x16, 0x06, 0x12, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x81, 0x7d, 0x08, 0x40, 0x04,
            0x02, 0x01, 0x07, 0x0a, 0x86, 0xde, 0xb7, 0x38,
            0x05, 0x00, 0x30, 0x16, 0x06, 0x12, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x81, 0x7d, 0x08, 0x40, 0x04,
            0x02, 0x01, 0x07, 0x0a, 0x86, 0xde, 0xb7, 0x36,
            0x05, 0x00, 0x30, 0x16, 0x06, 0x12, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x81, 0x7d, 0x08, 0x40, 0x04,
            0x02, 0x01, 0x05, 0x0a, 0x86, 0xde, 0xb9, 0x60,
            0x05, 0x00,
        };

        [Fact]
        public void ParseSnmpGet7()
        {
            var packetVersion = SnmpPacket.GetProtocolVersion(Packet7, Packet7.Length);

            Assert.Equal(ESnmpVersion.Ver1, packetVersion);

            var packet = new SnmpV1Packet();
            packet.Decode(Packet7, Packet7.Length);

            Assert.Equal("public", packet.Community.ToString());

            Assert.True(packet.IsRequest);
            Assert.False(packet.IsResponse);

            Assert.Equal(41, packet.Pdu.RequestId);
            Assert.Equal(EPduErrorStatus.NoError, packet.Pdu.ErrorStatus);
            Assert.Equal(0, packet.Pdu.ErrorIndex);

            Assert.Equal(3, packet.Pdu.VbCount);

            var vb = packet.Pdu.GetVb(0);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.7.10.14130104"), vb.Oid);

            vb = packet.Pdu.GetVb(1);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.7.10.14130102"), vb.Oid);

            vb = packet.Pdu.GetVb(2);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.5.10.14130400"), vb.Oid);
        }

        private static readonly byte[] Packet8 =
        {
            0x30, 0x79, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x6c, 0x02,
            0x01, 0x29, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x61, 0x30, 0x21, 0x06, 0x12, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x81, 0x7d, 0x08, 0x40, 0x04,
            0x02, 0x01, 0x07, 0x0a, 0x86, 0xde, 0xb7, 0x38,
            0x04, 0x0b, 0x31, 0x37, 0x32, 0x2e, 0x33, 0x31,
            0x2e, 0x31, 0x39, 0x2e, 0x32, 0x30, 0x23, 0x06,
            0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x7d,
            0x08, 0x40, 0x04, 0x02, 0x01, 0x07, 0x0a, 0x86,
            0xde, 0xb7, 0x36, 0x04, 0x0d, 0x32, 0x35, 0x35,
            0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35,
            0x2e, 0x30, 0x30, 0x17, 0x06, 0x12, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x81, 0x7d, 0x08, 0x40, 0x04,
            0x02, 0x01, 0x05, 0x0a, 0x86, 0xde, 0xb9, 0x60,
            0x02, 0x01, 0x01,
        };

        [Fact]
        public void ParseSnmpResponse8()
        {
            var packetVersion = SnmpPacket.GetProtocolVersion(Packet8, Packet8.Length);

            Assert.Equal(ESnmpVersion.Ver1, packetVersion);

            var packet = new SnmpV1Packet();
            packet.Decode(Packet8, Packet8.Length);

            Assert.Equal("public", packet.Community.ToString());

            Assert.False(packet.IsRequest);
            Assert.True(packet.IsResponse);

            Assert.Equal(41, packet.Pdu.RequestId);
            Assert.Equal(EPduErrorStatus.NoError, packet.Pdu.ErrorStatus);
            Assert.Equal(0, packet.Pdu.ErrorIndex);

            Assert.Equal(3, packet.Pdu.VbCount);

            var vb = packet.Pdu.GetVb(0);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.7.10.14130104"), vb.Oid);
            Assert.Equal((byte)EAsnType.OctetString, vb.Value.Type);
            Assert.Equal(new byte[] { 0x31, 0x37, 0x32, 0x2e, 0x33, 0x31, 0x2e, 0x31, 0x39, 0x2e, 0x32 }, vb.Value as OctetString);

            vb = packet.Pdu.GetVb(1);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.7.10.14130102"), vb.Oid);
            Assert.Equal((byte)EAsnType.OctetString, vb.Value.Type);
            Assert.Equal(new byte[] { 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x30 }, vb.Value as OctetString);

            vb = packet.Pdu.GetVb(2);
            Assert.NotNull(vb);
            Assert.Equal(new Oid("1.3.6.1.4.1.253.8.64.4.2.1.5.10.14130400"), vb.Oid);
            Assert.Equal((byte)EAsnType.Integer, vb.Value.Type);
            Assert.Equal(1, vb.Value as Integer32);
        }
    }
}
