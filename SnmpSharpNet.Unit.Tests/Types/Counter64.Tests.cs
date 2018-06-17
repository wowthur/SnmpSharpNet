namespace SnmpSharpNet.Unit.Tests.Types
{
    using SnmpSharpNet.Types;
    using Xunit;

    public class Counter64Tests
    {
        [Fact]
        public void Constructors()
        {
            var a = new Counter64();
            Assert.Equal(SnmpConstants.SmiCounter64, a.Type);
            Assert.Equal(0U, a.Value);

            var b = new Counter64(10);
            Assert.Equal(10U, b.Value);

            var c = new Counter64(10);
            Assert.Equal(10U, c.Value);
            b.Value = 12;
            Assert.Equal(10U, c.Value);

            var d = new Counter64("15");
            Assert.Equal(15U, d.Value);

            var e = (Counter64)d.Clone();
            d.Value = 20;
            Assert.Equal(15U, e.Value);
        }

        [Fact]
        public void Diff()
        {
            var a = new Counter64(15);
            Assert.Equal(15U, a.Value);

            var b = new Counter64(10);
            Assert.Equal(10U, b.Value);

            // TODO : Is this correct?
            Assert.Equal(4U, Counter64.Diff(b, a));

            // TODO : Is this correct?
            Assert.Equal(18446744073709551611U, Counter64.Diff(a, b));
        }

        [Fact]
        public void ConvertToString()
        {
            var i1 = new Counter64(10);

            Assert.Equal("10", i1.ToString());
        }

        public static readonly byte[] CounterExample1 =
        {
            SnmpConstants.SmiCounter64, // ASN.1 Type
            0x01,                       // Length
            0x03,                       // 3
        };

        [Fact]
        public void TestParseExample1()
        {
            var i = new Counter64();
            var result = i.Decode(CounterExample1, 0);

            Assert.Equal(3, result);
            Assert.Equal(3U, i.Value);
        }

        [Fact]
        public void Generate()
        {
            var i = new Counter64(300);
            var buffer = new MutableByte();
            i.Encode(buffer);

            var expected = new byte[]
            {
                SnmpConstants.SmiCounter64, // ASN.1 Type
                0x02,                       // Length
                0x01, 0x2C,                 // 300 in big endian
            };

            Assert.Equal(expected, buffer);
        }
    }
}
