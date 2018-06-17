namespace SnmpSharpNet.Unit.Tests.Types
{
    using System;
    using SnmpSharpNet.Types;
    using Xunit;

    public class EndOfMibViewTests
    {
        [Fact]
        public void Constructors()
        {
            var eom = new EndOfMibView();
            Assert.NotNull(eom);
            Assert.Equal(SnmpConstants.SmiEndOfMIBView, eom.Type);

            var copy = new EndOfMibView(eom);
            Assert.Equal(SnmpConstants.SmiEndOfMIBView, copy.Type);

            var clone = (EndOfMibView)copy.Clone();
            Assert.Equal(SnmpConstants.SmiEndOfMIBView, clone.Type);
        }

        public static readonly byte[] EoMPacket =
        {
            SnmpConstants.SmiEndOfMIBView,  // Type
            0,                              // Length
        };

        [Fact]
        public void ParseWellFormed()
        {
            var eom = new EndOfMibView();
            var result = eom.Decode(EoMPacket, 0);

            Assert.Equal(2, result);
            Assert.Equal(SnmpConstants.SmiEndOfMIBView, eom.Type);
        }

        public static readonly byte[] BadEoMPacketRange =
        {
            SnmpConstants.SmiEndOfMIBView,  // Type
            1,                              // Length
        };

        [Fact]
        public void ParsePoorlyFormedRange()
        {
            var eom = new EndOfMibView();
            Assert.Throws<SnmpSharpNet.Exception.SnmpException>(() => { eom.Decode(BadEoMPacketRange, 0); });
        }

        public static readonly byte[] BadEoMPacketPadding =
        {
            SnmpConstants.SmiEndOfMIBView,  // Type
            1,                              // Length
            0,                              // Padding
        };

        [Fact]
        public void ParsePoorlyFormedPadding()
        {
            var eom = new EndOfMibView();
            Assert.Throws<SnmpSharpNet.Exception.SnmpException>(() => { eom.Decode(BadEoMPacketPadding, 0); });
        }

        [Fact]
        public void TestToString()
        {
            var eom = new EndOfMibView();
            Assert.Equal("SNMP End-of-MIB-View", eom.ToString());
        }
    }
}
