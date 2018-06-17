namespace SnmpSharpNet.Unit.Tests.Types
{
    using System;
    using SnmpSharpNet.Types;
    using Xunit;

    public class Integer32Tests
    {
        [Fact]
        public void Constructors()
        {
            var a = new Integer32();
            Assert.Equal(SnmpConstants.SmiInteger, a.Type);
            Assert.Equal(0, a.Value);

            var b = new Integer32(10);
            Assert.Equal(10, b.Value);

            var c = new Integer32(10);
            Assert.Equal(10, c.Value);
            b.Value = 12;
            Assert.Equal(10, c.Value);

            var d = new Integer32("15");
            Assert.Equal(15, d.Value);

            var e = (Integer32)d.Clone();
            d.Value = 20;
            Assert.Equal(15, e.Value);
        }

        [Fact]
        public void SetGood()
        {
            var i1 = new Integer32(10);
            var i2 = new Integer32(20);

            Assert.Equal(10, i1);

            i1.Set(i2);

            i2.Value = 30;

            Assert.Equal(20, i1.Value);
            Assert.Equal(30, i2.Value);
        }

        [Fact]
        public void SetBad()
        {
            var i1 = new Integer32(10);
            var i2 = new UInteger32(20);

            Assert.Throws<ArgumentException>(() => { i1.Set(i2); });
        }

        [Fact]
        public void SetStringGood()
        {
            var i1 = new Integer32(10);

            i1.Set("20");

            Assert.Equal(20, i1.Value);
        }

        [Fact]
        public void SetStringEmpty()
        {
            var i1 = new Integer32(10);

            Assert.Throws<ArgumentOutOfRangeException>(() => { i1.Set(string.Empty); });
        }

        [Fact]
        public void SetStringBad()
        {
            var i1 = new Integer32(10);

            Assert.Throws<ArgumentException>(() => { i1.Set("Bad"); });
        }

        [Fact]
        public void ConvertToString()
        {
            var i1 = new Integer32(10);

            Assert.Equal("10", i1.ToString());
        }

        public static readonly byte[] IntegerExample1 =
        {
            SnmpConstants.SmiInteger,    // ASN.1 Type
            0x01,                       // Length
            0x03,                       // 3
        };

        [Fact]
        public void TestParseExample1()
        {
            var i = new Integer32();
            var result = i.Decode(IntegerExample1, 0);

            Assert.Equal(3, result);
            Assert.Equal(3, i.Value);
        }

        [Fact]
        public void Generate()
        {
            var i = new Integer32(300);
            var buffer = new MutableByte();
            i.Encode(buffer);

            var expected = new byte[]
            {
                SnmpConstants.SmiInteger,    // ASN.1 Type
                0x02,                       // Length
                0x01, 0x2C,                 // 300 in big endian
            };

            Assert.Equal(expected, buffer);
        }
    }
}
