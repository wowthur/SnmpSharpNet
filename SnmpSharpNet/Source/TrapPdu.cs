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
    using SnmpSharpNet.Exception;
    using SnmpSharpNet.Types;

    /// <summary>SNMP version 1 TRAP Protocol Data Unit</summary>
    /// <remarks>
    /// Trap PDU for SNMP version 1 is a PDU with a unique layout requiring a dedicated class. SNMP versions
    /// 2 and 3 use standard PDU type for V2TRAP notifications.
    /// </remarks>
    public class TrapPdu :
        AsnType,
        ICloneable
    {
        /// <summary>Trap enterprise Oid</summary>
        protected Oid enterprise;

        /// <summary>The IP Address of the remote agent sending the trap.</summary>
        protected IpAddress agentAddr;

        /// <summary>Generic trap code</summary>
        protected Integer32 generic;

        /// <summary>Specific trap code.</summary>
        protected Integer32 specific;

        /// <summary>sysUpTime timestamp of the trap event</summary>
        protected TimeTicks timeStamp;

        /// <summary>Variable binding list</summary>
        private VbCollection variables;

        /// <summary>Get remote agent's IP address.</summary>
        public virtual IpAddress AgentAddress
        {
            get { return agentAddr; }
        }

        /// <summary>Get/Set generic code trap value object</summary>
        public virtual int Generic
        {
            get { return generic.Value; }
            set { generic.Value = value; }
        }

        /// <summary>Get/Set specific code trap value object</summary>
        public virtual int Specific
        {
            get { return specific.Value; }
            set { specific.Value = value; }
        }

        /// <summary>Get timeticks trap value object</summary>
        public virtual uint TimeStamp
        {
            get { return timeStamp.Value; }
            set { timeStamp.Value = value; }
        }

        /// <summary> Returns the number oid/value pairs in the variable binding contained in the PDU</summary>
        public virtual int Count
        {
            get { return variables.Count; }
        }

        /// <summary>Constructor</summary>
        public TrapPdu()
        {
            base.Type = (byte)EPduType.Trap;

            enterprise = new Oid();
            agentAddr = new IpAddress();
            generic = new Integer32();
            specific = new Integer32();
            timeStamp = new TimeTicks();
            variables = new VbCollection();
        }

        /// <summary>Constructs a new trap pdu that is identical to the passed pdu.</summary>
        /// <param name="second">The object to copy.
        /// </param>
        public TrapPdu(TrapPdu second)
            : this()
        {
            enterprise.Set(second.enterprise);
            agentAddr.Set(second.agentAddr);
            generic.Value = second.Generic;
            specific.Value = second.Specific;
            timeStamp.Value = second.TimeStamp;

            for (int x = 0; x < second.variables.Count; x++)
                variables = (VbCollection)second.VbList.Clone();
        }

        /// <summary>Not implemented. Throws NotImplementedException.</summary>
        /// <param name="value">Irrelevant</param>
#pragma warning disable RECS0154
        public void Set(string value)
        {
            throw new NotImplementedException();
        }
#pragma warning restore RECS0154

        /// <summary>Get PDU type.</summary>
        /// <remarks>Always returns PduType.Trap</remarks>
        public new EPduType Type
        {
            get { return (EPduType)base.Type; }
        }

        /// <summary>Initialize the class with values from another <see cref="TrapPdu"/> class.</summary>
        /// <param name="second">TrapPdu class whose values are used to initialize this class.</param>
        public void Set(TrapPdu second)
        {
            if (second != null)
            {
                enterprise.Set(second.enterprise);
                agentAddr.Set(second.agentAddr);
                generic.Value = second.Generic;
                specific.Value = second.Specific;
                timeStamp.Value = second.TimeStamp;

                variables.Clear();

                for (int x = 0; x < second.variables.Count; x++)
                    variables = (VbCollection)second.VbList.Clone();
            }
            else
                throw new ArgumentException("Invalid argument type.", nameof(second));
        }

        /// <summary>Get trap enterprise identifier</summary>
        public Oid Enterprise
        {
            get { return enterprise; }
        }

        /// <summary>
        /// Get <see cref="VbCollection"/> variable binding list.
        /// </summary>
        public VbCollection VbList
        {
            get { return variables; }
        }

        /// <summary>
        /// Return number of entries in the VbList
        /// </summary>
        public int VbCount
        {
            get { return variables.Count; }
        }

        /// <summary>ASN.1 encode SNMP version 1 trap</summary>
        /// <param name="buffer"><see cref="MutableByte"/> buffer to the end of which encoded values are appended.</param>
        public override void Encode(MutableByte buffer)
        {
            MutableByte trapBuffer = new MutableByte();

            // encode the enterprise id & address
            enterprise.Encode(trapBuffer);

            agentAddr.Encode(trapBuffer);

            generic.Encode(trapBuffer);

            specific.Encode(trapBuffer);

            timeStamp.Encode(trapBuffer);

            variables.Encode(trapBuffer);

            MutableByte tmpBuffer = new MutableByte();

            BuildHeader(tmpBuffer, (byte)EPduType.Trap, trapBuffer.Length);
            trapBuffer.Prepend(tmpBuffer);
            buffer.Append(trapBuffer);
        }

        /// <summary>Decode BER encoded SNMP version 1 trap packet</summary>
        /// <param name="buffer">BER encoded buffer</param>
        /// <param name="offset">Offset in the packet to start decoding from</param>
        /// <returns>Buffer position after the decoded value.</returns>
        /// <exception cref="SnmpException">Invalid SNMP Pdu type received. Not an SNMP version 1 Trap PDU.</exception>
        /// <exception cref="SnmpException">Invalid Variable Binding list encoding.</exception>
        public override int Decode(byte[] buffer, int offset)
        {
            byte asnType = ParseHeader(buffer, ref offset, out int headerLength);

            if (asnType != (byte)EPduType.Trap)
                throw new SnmpException("Invalid PDU type.");

            if (headerLength > buffer.Length - offset)
                throw new OverflowException("Packet is too short.");

            offset = enterprise.Decode(buffer, offset);

            offset = agentAddr.Decode(buffer, offset);

            offset = generic.Decode(buffer, offset);

            offset = specific.Decode(buffer, offset);

            offset = timeStamp.Decode(buffer, offset);

            // clean out the current variables
            variables.Clear();

            offset = variables.Decode(buffer, offset);

            return offset;
        }

        /// <summary>Clone object</summary>
        /// <returns>Cloned copy of this object.</returns>
        public override object Clone()
        {
            return new TrapPdu(this);
        }
    }
}