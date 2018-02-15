// This file is part of SNMP#NET.
//
// SNMP#NET is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SNMP#NET is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with SNMP#NET.  If not, see <http://www.gnu.org/licenses/>.
//
namespace SnmpSharpNet
{
    using System;
    using System.Text;
    using SnmpSharpNet.Exception;
    using SnmpSharpNet.Types;

    /// <summary>SNMP version 2 packet class.</summary>
    ///
    /// <remarks>
    /// Available packet classes are:
    /// <ul>
    /// <li><see cref="SnmpV1Packet"/></li>
    /// <li><see cref="SnmpV1TrapPacket"/></li>
    /// <li><see cref="SnmpV2Packet"/></li>
    /// <li><see cref="SnmpV3Packet"/></li>
    /// </ul>
    ///
    /// This class is provided to simplify encoding and decoding of packets and to provide consistent interface
    /// for users who wish to handle transport part of protocol on their own without using the <see cref="UdpTarget"/>
    /// class.
    ///
    /// <see cref="SnmpPacket"/> and derived classes have been developed to implement SNMP version 1, 2 and 3 packet
    /// support.
    ///
    /// For SNMP version 1 and 2 packet, <see cref="SnmpV1Packet"/> and <see cref="SnmpV2Packet"/> classes
    /// provides  sufficient support for encoding and decoding data to/from BER buffers to satisfy requirements
    /// of most applications.
    ///
    /// SNMP version 3 on the other hand requires a lot more information to be passed to the encoder method and
    /// returned by the decode method. While using SnmpV3Packet class for full packet handling is possible, transport
    /// specific class <see cref="UdpTarget"/> uses <see cref="SecureAgentParameters"/> class to store protocol
    /// version 3 specific information that carries over from request to request when used on the same SNMP agent
    /// and therefore simplifies both initial definition of agents configuration (mostly security) as well as
    /// removes the need for repeated initialization of the packet class for subsequent requests.
    ///
    /// If you decide not to use transport helper class(es) like <see cref="UdpTarget"/>, BER encoding and
    /// decoding and packets is easily done with SnmpPacket derived classes.
    ///
    /// Example, SNMP version 2 packet encoding:
    /// <code>
    /// SnmpV2Packet packetv2 = new SnmpV2Packet();
    /// packetv2.Community.Set("public");
    /// packetv2.Pdu.Set(mypdu);
    /// byte[] berpacket = packetv2.encode();
    /// </code>
    ///
    /// Example, SNMP version 2 packet decoding:
    /// <code>
    /// SnmpV2Packet packetv2 = new SnmpV2Packet();
    /// packetv2.decode(inbuffer,inlen);
    /// </code>
    /// </remarks>
    public class SnmpV2Packet : SnmpPacket
    {
        /// <summary>SNMP community name</summary>
        protected OctetString snmpCommunity;

        /// <summary>Get SNMP community value used by SNMP version 1 and version 2 protocols.</summary>
        public OctetString Community
        {
            get { return snmpCommunity; }
        }

        /// <summary>SNMP Protocol Data Unit</summary>
        private Pdu pdu;

        /// <summary>
        /// Access to the packet <see cref="Pdu"/>.
        /// </summary>
        public override Pdu Pdu
        {
            get { return pdu; }
        }

        /// <summary>Standard constructor.</summary>
        public SnmpV2Packet()
            : base(ESnmpVersion.Ver2)
        {
            protocolVersion.Value = (int)ESnmpVersion.Ver2;
            pdu = new Pdu();
            snmpCommunity = new OctetString();
        }

        /// <summary>Standard constructor.</summary>
        /// <param name="snmpCommunity">SNMP community name for the packet</param>
        public SnmpV2Packet(string snmpCommunity)
            : this()
        {
            this.snmpCommunity.Set(snmpCommunity);
        }

        /// <summary>Decode received SNMP packet.</summary>
        /// <param name="buffer">BER encoded packet buffer</param>
        /// <param name="length">BER encoded packet buffer length</param>
        /// <exception cref="SnmpException">Thrown when invalid encoding has been found in the packet</exception>
        /// <exception cref="OverflowException">Thrown when parsed header points to more data then is available in the packet</exception>
        /// <exception cref="SnmpInvalidVersionException">Thrown when parsed packet is not SNMP version 1</exception>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when received PDU is of a type not supported by SNMP version 1</exception>
        /// <returns>Returns the length of the decoded data</returns>
        public override int Decode(byte[] buffer, int length)
        {
            int offset = 0;

            offset = base.Decode(buffer, buffer.Length);

            if (Version != ESnmpVersion.Ver2)
                throw new SnmpInvalidVersionException("Invalid protocol version");

            MutableByte buf = new MutableByte(buffer, length);
            offset = snmpCommunity.Decode(buf, offset);

            int tmpOffset = offset;
            byte asnType = AsnType.ParseHeader(buf, ref tmpOffset, out int headerLength);

            // Check packet length
            if (headerLength + offset > buf.Length)
                throw new OverflowException("Insufficient data in packet");

            if (asnType != (byte)EPduType.Get && asnType != (byte)EPduType.GetNext && asnType != (byte)EPduType.Set &&
                asnType != (byte)EPduType.GetBulk && asnType != (byte)EPduType.Response && asnType != (byte)EPduType.V2Trap &&
                asnType != (byte)EPduType.Inform)
                throw new SnmpInvalidPduTypeException("Invalid SNMP operation received: " + string.Format("0x{0:x2}", asnType));

            // Now process the Protocol Data Unit
            offset = Pdu.Decode(buf, offset);
            return length;
        }

        /// <summary>Encode SNMP packet for sending.</summary>
        /// <returns>BER encoded SNMP packet.</returns>
        public override byte[] Encode()
        {
            MutableByte buf = new MutableByte();

            if (Pdu.Type != EPduType.Get && Pdu.Type != EPduType.GetNext &&
                Pdu.Type != EPduType.Set && Pdu.Type != EPduType.V2Trap &&
                Pdu.Type != EPduType.Response && Pdu.Type != EPduType.GetBulk &&
                Pdu.Type != EPduType.Inform)
                throw new SnmpInvalidPduTypeException("Invalid SNMP PDU type while attempting to encode PDU: " + string.Format("0x{0:x2}", Pdu.Type));

            // snmp version
            protocolVersion.Encode(buf);

            // community string
            snmpCommunity.Encode(buf);

            // pdu
            pdu.Encode(buf);

            // wrap the packet into a sequence
            MutableByte tmpBuf = new MutableByte();
            AsnType.BuildHeader(tmpBuf, SnmpConstants.SmiSequence, buf.Length);

            buf.Prepend(tmpBuf);

            return buf;
        }

        /// <summary>Build SNMP RESPONSE packet for the received INFORM packet.</summary>
        /// <returns>SNMP version 2 packet containing RESPONSE to the INFORM packet contained in the class instance.</returns>
        public SnmpV2Packet BuildInformResponse()
        {
            return SnmpV2Packet.BuildInformResponse(this);
        }

        /// <summary>Build SNMP RESPONSE packet for the INFORM packet class.</summary>
        /// <param name="informPacket">SNMP INFORM packet</param>
        /// <returns>SNMP version 2 packet containing RESPONSE to the INFORM packet contained in the parameter.</returns>
        /// <exception cref="SnmpInvalidPduTypeException">Parameter is not an INFORM SNMP version 2 packet class</exception>
        /// <exception cref="SnmpInvalidVersionException">Parameter is not a SNMP version 2 packet</exception>
        public static SnmpV2Packet BuildInformResponse(SnmpV2Packet informPacket)
        {
            if (informPacket.Version != ESnmpVersion.Ver2)
                throw new SnmpInvalidVersionException("INFORM packet can only be parsed from an SNMP version 2 packet.");

            if (informPacket.Pdu.Type != EPduType.Inform)
                throw new SnmpInvalidPduTypeException("Inform response can only be built for INFORM packets.");

            SnmpV2Packet response = new SnmpV2Packet(informPacket.Community.ToString());
            response.Pdu.Type = EPduType.Response;
            response.Pdu.TrapObjectID.Set(informPacket.Pdu.TrapObjectID);
            response.Pdu.TrapSysUpTime.Value = informPacket.Pdu.TrapSysUpTime.Value;

            foreach (Vb v in informPacket.Pdu.VbList)
                response.Pdu.VbList.Add(v.Oid, v.Value);

            response.Pdu.RequestId = informPacket.Pdu.RequestId;

            return response;
        }

        /// <summary>String representation of the SNMP v1 Packet contents.</summary>
        /// <returns>String representation of the class.</returns>
        public override string ToString()
        {
            StringBuilder str = new StringBuilder();
            str.AppendFormat("SnmpV2Packet:\nCommunity: {0}\n{1}\n", Community.ToString(), Pdu.ToString());

            return str.ToString();
        }
    }
}
