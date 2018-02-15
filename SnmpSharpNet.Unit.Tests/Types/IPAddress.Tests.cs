namespace SnmpSharpNet.Unit.Tests.Types
{
    using Xunit;

    public class IPAddressTests
    {
        [Fact]
        public void GetClass()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.1.1").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.A, addr.GetClass());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("172.24.24.24").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.B, addr.GetClass());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("192.168.255.255").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.C, addr.GetClass());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("224.0.0.5").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.D, addr.GetClass());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("245.244.243.242").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.E, addr.GetClass());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.255.255").GetAddressBytes());
            Assert.Equal(SnmpSharpNet.Types.IpAddress.Class.Invalid, addr.GetClass());
        }

        [Fact]
        public void ToUInt32()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.1.1").GetAddressBytes());
            Assert.Equal(0x0101640AU, addr.ToUInt32());
        }

        [Fact]
        public void ToUInt32Host()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.1.1").GetAddressBytes());
            Assert.Equal(0x0A640101U, addr.ToUInt32Host());
        }

        [Fact]
        public void GetSubnetAddress()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.17.1").GetAddressBytes());
            var mask = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.240.0").GetAddressBytes());
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.16.0").GetAddressBytes());
            Assert.Equal(expected, addr.GetSubnetAddress(mask));
        }

        [Fact]
        public void Invert()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("0.0.15.255").GetAddressBytes());
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.240.0").GetAddressBytes());
            Assert.Equal(expected, addr.Invert());
        }

        [Fact]
        public void GetBroadcastAddress()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.17.1").GetAddressBytes());
            var mask = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.240.0").GetAddressBytes());
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.31.255").GetAddressBytes());
            Assert.Equal(expected, addr.GetBroadcastAddress(mask));
        }

        [Fact]
        public void GetNetworkMask()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("10.100.1.1").GetAddressBytes());
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.0.0.0").GetAddressBytes());
            Assert.Equal(expected, addr.NetworkMask());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("172.24.24.24").GetAddressBytes());
            expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.0.0").GetAddressBytes());
            Assert.Equal(expected, addr.NetworkMask());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("192.168.255.255").GetAddressBytes());
            expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.255.0").GetAddressBytes());
            Assert.Equal(expected, addr.NetworkMask());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("224.0.0.5").GetAddressBytes());
            Assert.Null(addr.NetworkMask());
        }

        [Fact]
        public void IsValidMask()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.224.0").GetAddressBytes());
            Assert.True(addr.IsValidMask());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.225.0").GetAddressBytes());
            Assert.False(addr.IsValidMask());
        }

        [Fact]
        public void GetMaskBits()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.224.0").GetAddressBytes());
            Assert.Equal(19, addr.GetMaskBits());

            addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.225.0").GetAddressBytes());
            Assert.Equal(0, addr.GetMaskBits());
        }

        [Fact]
        public void BuildMaskFromBits()
        {
            var addr = SnmpSharpNet.Types.IpAddress.BuildMaskFromBits(19);
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("255.255.224.0").GetAddressBytes());
            Assert.Equal(addr, expected);
        }

        [Fact]
        public void ReverseByteOrder()
        {
            var x = 0xFFEEDDCC;
            var expected = 0xCCDDEEFF;
            Assert.Equal(expected, SnmpSharpNet.Types.IpAddress.ReverseByteOrder(x));
        }

        [Fact]
        public void Increment()
        {
            var addr = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("192.168.1.1"));
            var expected = new SnmpSharpNet.Types.IpAddress(System.Net.IPAddress.Parse("192.168.2.3"));
            Assert.Equal(expected, addr.Increment(258));
        }

        [Fact]
        public void IsIP()
        {
            Assert.True(SnmpSharpNet.Types.IpAddress.IsIP("100.1.244.2"));
            Assert.False(SnmpSharpNet.Types.IpAddress.IsIP("345.1.1.1"));
            Assert.True(SnmpSharpNet.Types.IpAddress.IsIP("1.1.1.1"));
            Assert.False(SnmpSharpNet.Types.IpAddress.IsIP("1.1.1.256"));
        }
    }
}
