namespace SnmpSharpNet.Unit.Tests.Types
{
    using SnmpSharpNet.Types;
    using Xunit;

    public class Counter32Tests
    {
        [Fact]
        public void Constructors()
        {
            var a = new Counter32();
            Assert.Equal(SnmpConstants.SmiCounter32, a.Type);
            Assert.Equal(0U, a.Value);

            var b = new Counter32(10);
            Assert.Equal(10U, b.Value);

            var c = new Counter32(10);
            Assert.Equal(10U, c.Value);
            b.Value = 12;
            Assert.Equal(10U, c.Value);

            var d = new Counter32("15");
            Assert.Equal(15U, d.Value);

            var e = (Counter32)d.Clone();
            d.Value = 20;
            Assert.Equal(15U, e.Value);
        }

        [Fact]
        public void Diff()
        {
            var a = new Counter32(15);
            Assert.Equal(15U, a.Value);

            var b = new Counter32(10);
            Assert.Equal(10U, b.Value);

            // TODO : Is this correct?
            Assert.Equal(4U, Counter32.Diff(b, a));

            // TODO : Is this correct?
            Assert.Equal(4294967291U, Counter32.Diff(a, b));
        }

        [Fact]
        public void ConvertToString()
        {
            var i1 = new Counter32(10);

            Assert.Equal("10", i1.ToString());
        }

        public static readonly byte[] CounterExample1 =
        {
            SnmpConstants.SmiCounter32, // ASN.1 Type
            0x01,                       // Length
            0x03,                       // 3
        };

        [Fact]
        public void TestParseExample1()
        {
            var i = new Counter32();
            var result = i.Decode(CounterExample1, 0);

            Assert.Equal(3, result);
            Assert.Equal(3U, i.Value);
        }

        [Fact]
        public void Generate()
        {
            var i = new Counter32(300);
            var buffer = new MutableByte();
            i.Encode(buffer);

            var expected = new byte[]
            {
                SnmpConstants.SmiCounter32, // ASN.1 Type
                0x02,                       // Length
                0x01, 0x2C,                 // 300 in big endian
            };

            Assert.Equal(expected, buffer);
        }
    }
}
