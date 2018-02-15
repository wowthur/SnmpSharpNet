namespace SnmpSharpNet
{
    using System;
    using System.Net;
    using SnmpSharpNet.Exception;
    using SnmpSharpNet.Types;

    /// <summary>
    /// Community based SNMP target. Used for SNMP version 1 and version 2c.
    /// </summary>
    public class CTarget : ITarget
    {
        /// <summary>Target IP address</summary>
        protected IpAddress address;

        /// <summary>Target port number</summary>
        protected int port;

        /// <summary>Target SNMP version number</summary>
        protected ESnmpVersion version;

        /// <summary>Target request timeout period in milliseconds</summary>
        private int timeout1;

        /// <summary>Target maximum retry count</summary>
        protected int retry;

        /// <summary>SNMP community name</summary>
        protected string community;

        /// <summary>Constructor</summary>
        public CTarget()
        {
            address = new IpAddress(IPAddress.Loopback);
            port = 161;
            version = ESnmpVersion.Ver2;
            Timeout1 = 2000;
            retry = 1;
            community = "public";
        }

        /// <summary>Constructor</summary>
        /// <param name="addr">Target address</param>
        public CTarget(IPAddress addr)
            : this()
        {
            address.Set(addr);
        }

        /// <summary>Constructor</summary>
        /// <param name="address">Target address</param>
        /// <param name="community">SNMP community name to use with the target</param>
        public CTarget(IPAddress address, string community)
            : this(address)
        {
            this.community = community;
        }

        /// <summary>Constructor</summary>
        /// <param name="addr">Target address</param>
        /// <param name="port">Taret UDP port number</param>
        /// <param name="community">SNMP community name to use with the target</param>
        public CTarget(IPAddress addr, int port, string community)
            : this(addr, community)
        {
            this.port = port;
        }

        /// <summary>SNMP community name for the target</summary>
        public string Community
        {
            get { return community; }
            set { community = value; }
        }

        /// <summary>Prepare packet for transmission by filling target specific information in the packet.</summary>
        /// <param name="packet">SNMP packet class for the required version</param>
        /// <returns>True if packet values are correctly set, otherwise false.</returns>
        public bool PreparePacketForTransmission(SnmpPacket packet)
        {
            if (packet.Version != version)
                return false;

            if (version == ESnmpVersion.Ver1)
            {
                SnmpV1Packet pkt = packet as SnmpV1Packet;
                pkt.Community.Set(community);
                return true;
            }

            if (version == ESnmpVersion.Ver2)
            {
                SnmpV2Packet pkt = packet as SnmpV2Packet;
                pkt.Community.Set(community);
                return true;
            }

            return false;
        }

        /// <summary>Validate received reply</summary>
        /// <param name="packet">Received SNMP packet</param>
        /// <returns>True if packet is validated, otherwise false</returns>
        public bool ValidateReceivedPacket(SnmpPacket packet)
        {
            if (packet.Version != version)
                return false;

            if (version == ESnmpVersion.Ver1)
            {
                SnmpV1Packet pkt = packet as SnmpV1Packet;
                if (pkt.Community.Equals(community))
                    return true;
            }

            if (version == ESnmpVersion.Ver2)
            {
                SnmpV2Packet pkt = packet as SnmpV2Packet;
                if (pkt.Community.Equals(community))
                    return true;
            }

            return false;
        }

        /// <summary>Get version of SNMP protocol this target supports</summary>
        /// <exception cref="SnmpInvalidVersionException">Thrown when SNMP version other then 1 or 2c is set</exception>
        public ESnmpVersion Version
        {
            get { return version; }

            set
            {
                if (value != ESnmpVersion.Ver1 && value != ESnmpVersion.Ver2)
                    throw new SnmpInvalidVersionException("CTarget is only suitable for use with SNMP v1 and v2c protocol versions.");

                version = value;
            }
        }

        /// <summary>Timeout in milliseconds for the target. Valid timeout values are between 100 and 10000 milliseconds.</summary>
        public int Timeout
        {
            get { return Timeout1; }

            set
            {
                if (value < 100 || value > 10000)
                    throw new OverflowException("Valid timeout value is between 100 milliseconds and 10000 milliseconds");

                Timeout1 = value;
            }
        }

        /// <summary>Number of retries for the target. Valid values are 0-5.</summary>
        public int Retry
        {
            get { return retry; }

            set
            {
                if (value < 0 || value > 5)
                    throw new OverflowException("Valid retry value is between 0 and 5");
                retry = value;
            }
        }

        /// <summary>Target IP address</summary>
        public IpAddress Address
        {
            get { return address; }
        }

        /// <summary>Target port number</summary>
        public int Port
        {
            get { return port; }
            set { port = value; }
        }

        protected int Timeout1 { get => timeout1; set => timeout1 = value; }

        /// <summary>Check validity of the target information.</summary>
        /// <returns>True if valid, otherwise false.</returns>
        public bool Valid()
        {
            if (community == null || community.Length == 0)
                return false;

            if (address == null || !address.Valid)
                return false;

            return port != 0;
        }
    }
}
