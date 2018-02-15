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
    using System.Collections.Generic;
    using System.Text;
    using SnmpSharpNet.Exception;
    using SnmpSharpNet.Types;

    /// <summary>SNMP Protocol Data Unit</summary>
    /// <remarks>
    /// SNMP PDU class that is the bases for all SNMP requests and replies. It is capable of processing
    /// SNMPv1 GET, GET-NEXT, REPLY and SNMPv2 GET, GET-NEXT, GET-BULK, REPLY, V2TRAP, INFORM and REPORT PDUs.
    /// <code>
    /// Pdu pdu = new Pdu();
    /// pdu.Type = PduType.Get;
    /// pdu.VbList.AddVb("1.3.6.1.2.1.1.1.0");
    /// pdu.VbList.AddVb("1.3.6.1.2.1.1.2.0");
    /// </code>
    ///
    /// By default, Pdu class initializes the RequestId (unique identifier of each SNMP request made by the manager)
    /// with a random value. User can force a new, random request id generation at the time packet is encoding by
    /// changing RequestId to 0. If you wish to set a specific RequestId, you can do it this way:
    ///
    /// <code>
    /// Pdu pdu = new Pdu();
    /// pdu.Type = PduType.GetNext;
    /// pdu.RequestId = 11; // Set a custom request id
    /// pdu.VbList.AddVb("1.3.6.1.2.1.1");
    /// </code>
    ///
    /// Pdu types with special options are notification PDUs, V2TRAP and INFORM, and Get-Bulk requests.
    ///
    /// Get-Bulk request is available in version 2c and 3 of the SNMP. Two special options can be set for these
    /// requests, NonRepeaters and MaxRepetitions.
    ///
    /// NonRepeaters is a value telling the agent how many OIDs in the VbList are to be treated as a single
    /// GetNext request.
    ///
    /// MaxRepeaters tells the agent how many variable bindings to return in a single Pdu for each requested Oid.
    /// </remarks>
    public class Pdu : AsnType, ICloneable, IEnumerable<Vb>
    {
        /// <summary>SNMPv2 trap second Vb is the trap object ID.</summary>
        /// <remarks>
        /// This variable should be set to the trap OID and will be inserted
        /// into the encoded packet.
        /// </remarks>
        protected Oid trapObjectID;

        /// <summary>Constructor.</summary>
        /// <remarks>Initializes all values to NULL and PDU type to GET</remarks>
        public Pdu()
        {
            errorIndex = new Integer32();
            errorStatus = new Integer32();
            requestId = new Integer32();
            requestId.SetRandom();
            base.Type = (byte)EPduType.Get;
            VbList = new VbCollection();
            TrapSysUpTime = new TimeTicks();
            trapObjectID = new Oid();
        }

        /// <summary>Constructor.</summary>
        /// <remarks>Create Pdu of specific type.</remarks>
        /// <param name="pduType">Pdu type. For available values see <see cref="EPduType"/></param>
        public Pdu(EPduType pduType)
            : this()
        {
            base.Type = (byte)pduType;

            if (base.Type == (byte)EPduType.GetBulk)
            {
                errorStatus.Value = 0;
                errorIndex.Value = 100;
            }
        }

        /// <summary>Constructor.</summary>
        /// <remarks>Sets the VarBind list to the Clone copy of the supplied list.</remarks>
        /// <param name="vbs">VarBind list to initialize the internal VbList to.</param>
        public Pdu(VbCollection vbs)
            : this()
        {
            VbList = (VbCollection)vbs.Clone();
        }

        /// <summary>Constructor.</summary>
        /// <remarks>Initializes PDU class with supplied values.</remarks>
        /// <param name="vbs">VarBind list</param>
        /// <param name="type">PDU type</param>
        /// <param name="requestId">Request id</param>
        public Pdu(VbCollection vbs, EPduType type, int requestId)
            : this(vbs)
        {
            this.requestId.Value = requestId;
            base.Type = (byte)type;
        }

        /// <summary>Constructor</summary>
        /// <remarks>Initialize class from the passed pdu class.</remarks>
        /// <param name="pdu">Pdu class to use as source of information to initilize this class.</param>
        public Pdu(Pdu pdu)
            : this(pdu.VbList, pdu.Type, pdu.RequestId)
        {
            if (pdu.Type == EPduType.GetBulk)
            {
                NonRepeaters = pdu.NonRepeaters;
                MaxRepetitions = pdu.MaxRepetitions;
            }
            else
            {
                ErrorStatus = pdu.ErrorStatus;
                ErrorIndex = pdu.ErrorIndex;
            }
        }

        /// <summary>Copy values from another Pdu class.</summary>
        /// <param name="value"><see cref="Pdu"/> cast as AsnType</param>
        /// <exception cref="ArgumentNullException">Thrown when received argument is null</exception>
        public void Set(AsnType value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            if (value is Pdu pdu)
            {
                Type = pdu.Type;
                requestId.Value = pdu.RequestId;

                if (Type == EPduType.GetBulk)
                {
                    NonRepeaters = pdu.NonRepeaters;
                    MaxRepetitions = pdu.MaxRepetitions;
                }
                else
                {
                    ErrorStatus = pdu.ErrorStatus;
                    ErrorIndex = pdu.ErrorIndex;
                }

                VbList.Clear();

                foreach (Vb v in pdu.VbList)
                    VbList.Add((Vb)v.Clone());
            }
            else
                throw new ArgumentNullException(nameof(value), "Argument is not an Oid class");
        }

        /// <summary>Set VbList</summary>
        /// <remarks>
        /// Copy variable bindings from argument <see cref="VbCollection"/> into this classes variable
        /// binding collection
        /// </remarks>
        /// <param name="value"><see cref="VbCollection"/> to copy variable bindings from</param>
        public void SetVbList(VbCollection value)
        {
            VbList.Clear();

            foreach (Vb v in value)
                VbList.Add(v);
        }

        /// <summary>Reset VbList.</summary>
        /// <remarks>Remove all entries in the VbList collections.</remarks>
        public void Reset()
        {
            VbList.Clear();
            errorStatus.Value = 0;
            errorIndex.Value = 0;

            if (requestId.Value == int.MaxValue)
                requestId.Value = 1;
            else
                requestId.Value = requestId.Value + 1;

            trapObjectID.Reset();
            TrapSysUpTime.Value = 0;
        }

        /// <summary>Create SNMP-GET Pdu from VbList</summary>
        /// <remarks>
        /// Helper static function to create GET PDU from the supplied VarBind list. Don't forget to set
        /// request id for the PDU.
        /// </remarks>
        /// <param name="vbs">VarBind list</param>
        /// <returns>Newly constructed GET PDU</returns>
        public static Pdu GetPdu(VbCollection vbs)
        {
            Pdu p = new Pdu(vbs)
            {
                Type = EPduType.Get,
                ErrorIndex = 0,
                ErrorStatus = 0,
            };

            return p;
        }

        /// <summary>Create Get Pdu with empty VarBind array</summary>
        /// <returns>Instance of Get Pdu</returns>
        public static Pdu GetPdu()
        {
            return new Pdu(EPduType.Get);
        }

        /// <summary>Create SNMP-SET Pdu</summary>
        /// <remarks>
        /// Helper static function to create SET PDU from the supplied VarBind list. Don't forget to set
        /// request id for the PDU.
        /// </remarks>
        /// <param name="vbs">VarBind list</param>
        /// <returns>Newly constructed SET PDU</returns>
        public static Pdu SetPdu(VbCollection vbs)
        {
            Pdu p = new Pdu(vbs)
            {
                Type = EPduType.Set,
                ErrorIndex = 0,
                ErrorStatus = 0,
            };

            return p;
        }

        /// <summary>Create Set Pdu with empty VarBind array</summary>
        /// <returns>Instance of Set Pdu</returns>
        public static Pdu SetPdu()
        {
            return new Pdu(EPduType.Set);
        }

        /// <summary>Create SNMP-GetNext Pdu</summary>
        /// <remarks>
        /// Helper static function to create GETNEXT PDU from the supplied VarBind list. Don't forget to set
        /// request id for the PDU.
        /// </remarks>
        /// <param name="vbs">VarBind list</param>
        /// <returns>Newly constructed GETNEXT PDU</returns>
        public static Pdu GetNextPdu(VbCollection vbs)
        {
            Pdu p = new Pdu(vbs)
            {
                Type = EPduType.GetNext,
                ErrorIndex = 0,
                ErrorStatus = 0,
            };

            return p;
        }

        /// <summary>Create GetNext Pdu with empty VarBind array</summary>
        /// <returns>Instance of GetNext Pdu</returns>
        public static Pdu GetNextPdu()
        {
            return new Pdu(EPduType.GetNext);
        }

        /// <summary>Create SNMP-GetBulk Pdu</summary>
        /// <remarks>
        /// Helper static function to create GETBULK PDU from the supplied VarBind list. MaxRepetitions are set to
        /// 256 and nonRepeaters are set to 0.
        /// </remarks>
        /// <param name="vbs">VarBind list</param>
        /// <returns>Newly constructed GETBULK PDU</returns>
        public static Pdu GetBulkPdu(VbCollection vbs)
        {
            Pdu p = new Pdu(vbs)
            {
                Type = EPduType.GetBulk,
                MaxRepetitions = 100,
                NonRepeaters = 0,
            };

            return p;
        }

        /// <summary>Create GetBulk Pdu with empty VarBind array. By default initializes NonRepeaters to 0 and MaxRepetitions to 100</summary>
        /// <returns>Instance of GetBulk Pdu</returns>
        public static Pdu GetBulkPdu()
        {
            return new Pdu(EPduType.GetBulk);
        }

        protected Integer32 errorStatus;

        /// <summary>ErrorStatus Pdu value</summary>
        /// <remarks>
        /// Stores error status returned by the SNMP agent. Value 0 represents no error. Valid for all
        /// Pdu types except GetBulk requests.
        /// </remarks>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when property is access for GetBulk Pdu</exception>
        public EPduErrorStatus ErrorStatus
        {
            get
            {
                if (Type == EPduType.GetBulk)
                    throw new SnmpInvalidPduTypeException("ErrorStatus property is not valid for GetBulk packets.");

                return (EPduErrorStatus)errorStatus.Value;
            }

            set
            {
                errorStatus.Value = (int)value;
            }
        }

        private Integer32 errorIndex;

        /// <summary>ErrorIndex Pdu value</summary>
        /// <remarks>
        /// Error index points to the VbList entry that ErrorStatus error code refers to. Valid for all Pdu types
        /// except GetBulk requests.
        /// </remarks>
        /// <see cref="ErrorStatus"/>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when property is access for GetBulk Pdu</exception>
        public int ErrorIndex
        {
            get
            {
                if (Type == EPduType.GetBulk)
                    throw new SnmpInvalidPduTypeException("ErrorStatus property is not valid for GetBulk packets.");

                return errorIndex.Value;
            }

            set
            {
                errorIndex.Value = value;
            }
        }

        private Integer32 requestId;

        /// <summary>SNMP packet request id that is sent to the SNMP agent. SET this value before making SNMP requests.</summary>
        public int RequestId
        {
            get { return requestId.Value; }
            set { requestId.Value = value; }
        }

        /// <summary>Get or SET the PDU type. Available types are GET, GETNEXT, SET, GETBULK. PDU types are defined in Pdu class.</summary>
        /// <seealso cref="EPduType.Get"/>
        /// <seealso cref="EPduType.GetNext"/>
        /// <seealso cref="EPduType.Set"/>
        /// <seealso cref="EPduType.Response"/>"/>
        /// * version 2 specific:
        /// <seealso cref="EPduType.GetBulk"/>
        public new EPduType Type
        {
            get
            {
                return (EPduType)base.Type;
            }

            set
            {
                // If nothing has changed
                // If type changes from GETBULK make sure errorIndex and errorStatus are set to 0
                // otherwise you'll send error messages to the receiver
                if (base.Type == (byte)value)
                    return;

                if (value != EPduType.GetBulk)
                {
                    errorIndex.Value = 0;
                    errorStatus.Value = 0;
                }
                else
                {
                    errorStatus.Value = 0;
                    errorIndex.Value = 100;
                }

                base.Type = (byte)value;
            }
        }

        /// <summary>Tells SNMP Agent how many VBs to include in a single request. Only valid on GETBULK requests.</summary>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when PDU type is not GET-BULK</exception>
        public int MaxRepetitions
        {
            get
            {
                if (Type == EPduType.GetBulk)
                    return errorIndex.Value;

                throw new SnmpInvalidPduTypeException("NonRepeaters property is only available in GET-BULK PDU type.");
            }

            set
            {
                if (Type == EPduType.GetBulk)
                    errorIndex.Value = value;
                else
                    throw new SnmpInvalidPduTypeException("NonRepeaters property is only available in GET-BULK PDU type.");
            }
        }

        /// <summary>Get/Set GET-BULK NonRepeaters value</summary>
        /// <remarks>
        /// Non repeaters variable tells the SNMP Agent how many GETNEXT like variables to retrieve (single Vb returned
        /// per request) before MaxRepetitions value takes affect. If you wish to retrieve as many values as you can
        /// in a single request, set this value to 0.
        /// </remarks>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when PDU type is not GET-BULK</exception>
        public int NonRepeaters
        {
            get
            {
                if (Type == EPduType.GetBulk)
                    return errorStatus.Value;
                throw new SnmpInvalidPduTypeException("NonRepeaters property is only available in GET-BULK PDU type.");
            }

            set
            {
                if (base.Type == (byte)EPduType.GetBulk)
                    errorStatus.Value = value;
                else
                    throw new SnmpInvalidPduTypeException("NonRepeaters property is only available in GET-BULK PDU type.");
            }
        }

        /// <summary>VarBind list</summary>
        public VbCollection VbList { get; private set; }

        /// <summary>Get TRAP TimeStamp class from SNMPv2 TRAP and INFORM PDUs</summary>
        public TimeTicks TrapSysUpTime { get; private set; }

        /// <summary>Get TRAP ObjectID class from SNMPv2 TRAP and INFORM PDUs</summary>
        /// <exception cref="SnmpInvalidPduTypeException">Thrown when property is access for a Pdu of a type other then V2TRAP, INFORM or RESPONSE</exception>
        public Oid TrapObjectID
        {
            get
            {
                if (Type != EPduType.V2Trap && Type != EPduType.Inform && Type != EPduType.Response)
                    throw new SnmpInvalidPduTypeException("TrapObjectID value can only be accessed in V2TRAP, INFORM and RESPONSE PDUs");

                return trapObjectID;
            }

            set { trapObjectID.Set(value); }
        }

        /// <summary>Get VB from VarBind list at the specified index</summary>
        /// <param name="index">Index position of the Vb in the array. Zero based.</param>
        /// <returns>Vb at the specified location in the array</returns>
        public Vb GetVb(int index)
        {
            return VbList[index];
        }

        /// <summary>Return the number of VB entries in the VarBind list</summary>
        public int VbCount
        {
            get { return VbList.Count; }
        }

        /// <summary>Delete VB from the specified location in the VarBind list</summary>
        /// <param name="pos">0 based VB location</param>
        public void DeleteVb(int pos)
        {
            if (pos >= 0 && pos <= VbList.Count)
                VbList.RemoveAt(pos);
        }

        /// <summary>Encode Pdu class to BER byte buffer</summary>
        /// <remarks>
        /// Encodes the protocol data unit using the passed encoder and stores
        /// the results in the passed buffer. An exception is thrown if an
        /// error occurs with the encoding of the information.
        /// </remarks>
        /// <param name="buffer">The buffer to write the encoded information.</param>
        public override void Encode(MutableByte buffer)
        {
            MutableByte tmpBuffer = new MutableByte();

            // if request id is 0, get a random value
            if (requestId.Value == 0)
                requestId.SetRandom();

            requestId.Encode(tmpBuffer);
            errorStatus.Encode(tmpBuffer);
            errorIndex.Encode(tmpBuffer);

            // if V2TRAP PDU type, add sysUpTime and trapObjectID OIDs before encoding VarBind
            if (Type == EPduType.V2Trap || Type == EPduType.Inform)
            {
                if (VbList.Count == 0)
                {
                    // add sysUpTime and trapObjectID to the VbList
                    VbList.Add(SnmpConstants.SysUpTime, TrapSysUpTime);
                    VbList.Add(SnmpConstants.TrapObjectId, trapObjectID);
                }
                else
                {
                    // Make sure user didn't manually add sysUpTime and trapObjectID values
                    // to the pdu

                    // if we have more then one item in the VarBinds array check for sysUpTime
                    if (VbList.Count > 0)
                    {
                        // if the first Vb in the VarBinds array is not sysUpTime append it in the
                        // encoded byte array
                        if (!VbList[0].Oid.Equals(SnmpConstants.SysUpTime))
                        {
                            Vb sysUpTimeVb = new Vb(SnmpConstants.SysUpTime, TrapSysUpTime);
                            VbList.Insert(0, sysUpTimeVb);
                        }
                    }

                    // if we have 2 or more Vbs in the VarBinds array check for trapObjectID Vb
                    if (VbList.Count > 1)
                    {
                        // if second Vb in the VarBinds array is not trapObjectId encode the value
                        if (!VbList[1].Oid.Equals(SnmpConstants.TrapObjectId))
                        {
                            Vb trapObjectIdVb = new Vb(SnmpConstants.TrapObjectId, trapObjectID);
                            VbList.Insert(1, trapObjectIdVb);
                        }
                    }
                }
            }

            // encode variable bindings
            VbList.Encode(tmpBuffer);

            // Now encode the header for the PDU
            BuildHeader(buffer, (byte)Type, tmpBuffer.Length);
            buffer.Append(tmpBuffer);
        }

        /// <summary>Decode BER encoded Pdu</summary>
        /// <remarks>
        /// Decodes the protocol data unit from the passed buffer. If an error
        /// occurs during the decoding sequence then an AsnDecodingException is
        /// thrown by the method. The value is decoded using the AsnEncoder
        /// passed to the object.
        /// </remarks>
        /// <param name="buffer">BER encoded buffer</param>
        /// <param name="offset">The offset byte to begin decoding</param>
        /// <returns>Buffer position after the decoded value</returns>
        /// <exception cref="OverflowException">Thrown when header points to more data then is available.</exception>
        public override int Decode(byte[] buffer, int offset)
        {
            byte asnType = ParseHeader(buffer, ref offset, out int headerLength);
            if (offset + headerLength > buffer.Length)
                throw new OverflowException("Insufficient data in packet");

            base.Type = asnType;

            // request id
            offset = requestId.Decode(buffer, offset);

            // error status
            offset = errorStatus.Decode(buffer, offset);

            // error index
            offset = errorIndex.Decode(buffer, offset);

            // clean out the current variables
            VbList.Clear();

            // decode the Variable binding collection
            offset = VbList.Decode(buffer, offset);

            // if Pdu is an SNMP version 2 TRAP, remove sysUpTime and trapObjectID from the VarBinds array
            if (Type == EPduType.V2Trap || Type == EPduType.Inform)
            {
                if (VbList.Count > 0)
                {
                    if (VbList[0].Oid.Equals(SnmpConstants.SysUpTime))
                    {
                        TrapSysUpTime.Set(VbList[0].Value);
                        VbList.RemoveAt(0); // remove sysUpTime
                    }
                }

                if (VbList.Count > 0)
                {
                    if (VbList[0].Oid.Equals(SnmpConstants.TrapObjectId))
                    {
                        trapObjectID.Set((Oid)VbList[0].Value);
                        VbList.RemoveAt(0); // remove sysUpTime
                    }
                }
            }

            return offset;
        }

        /// <summary>Return string dump of the Pdu class.</summary>
        /// <returns>String content of the Pdu class.</returns>
        public override string ToString()
        {
            StringBuilder str = new StringBuilder();
            str.Append("PDU-");
            switch (base.Type)
            {
                case (byte)EPduType.Get:
                    str.Append("Get");
                    break;

                case (byte)EPduType.GetNext:
                    str.Append("GetNext");
                    break;

                case (byte)EPduType.GetBulk:
                    str.Append("GetBulk");
                    break;

                case (byte)EPduType.V2Trap:
                    str.Append("V2Trap");
                    break;

                case (byte)EPduType.Response:
                    str.Append("Response");
                    break;

                case (byte)EPduType.Inform:
                    str.Append("Inform");
                    break;

                default:
                    str.Append("Unknown");
                    break;
            }

            str.Append("\n");
            str.AppendFormat("RequestId: {0}\n", RequestId);

            if (Type != EPduType.GetBulk)
                str.AppendFormat("ErrorStatus: {0}\nError Index: {1}\n", ErrorStatus, ErrorIndex);
            else
                str.AppendFormat("MaxRepeaters: {0}\nNonRepeaters: {1}\n", MaxRepetitions, NonRepeaters);

            if (Type == EPduType.V2Trap || Type == EPduType.Inform)
                str.AppendFormat("TimeStamp: {0}\nTrapOID: {1}\n", TrapSysUpTime.ToString(), TrapObjectID.ToString());

            str.AppendFormat("VbList entries: {0}\n", VbCount);

            if (VbCount > 0)
            {
                foreach (Vb v in VbList)
                    str.AppendFormat("Vb: {0}\n", v.ToString());
            }

            return str.ToString();
        }

        /// <summary>Clone this object</summary>
        /// <returns>Copy of this object cast as type System.Object</returns>
        public override object Clone()
        {
            Pdu p = new Pdu(VbList, Type, requestId);
            if (Type == EPduType.GetBulk)
            {
                p.NonRepeaters = errorStatus;
                p.MaxRepetitions = errorIndex;
            }
            else
            {
                p.ErrorIndex = ErrorIndex;
                p.ErrorStatus = ErrorStatus;
            }

            if (Type == EPduType.V2Trap)
            {
                p.TrapObjectID.Set(TrapObjectID);
                p.TrapSysUpTime.Value = TrapSysUpTime.Value;
            }

            return p;
        }

        /// <summary>
        /// Check class equality with argument.
        ///
        /// Accepted argument types are:
        /// * Integer32 - compared against the request id
        /// * Pdu - compared against PduType, request id and contents of VarBind list
        /// </summary>
        /// <param name="obj">Integer32 or Pdu to compare</param>
        /// <returns>True if equal, otherwise false</returns>
        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;

            if (obj is Integer32)
                return ((Integer32)obj) == requestId;

            if (obj is Pdu p)
            {
                if (p.Type != Type)
                    return false;

                if (p.RequestId != RequestId)
                    return false;

                if (p.VbCount != VbCount)
                    return false;

                foreach (var v in VbList)
                {
                    if (!p.VbList.ContainsOid(v.Oid))
                        return false;
                }

                foreach (var v in p.VbList)
                {
                    if (!VbList.ContainsOid(v.Oid))
                        return false;
                }

                return true;
            }

            return false;
        }

        /// <summary>Returns hash code representing class value.</summary>
        /// <returns>Class value hash code</returns>
        public override int GetHashCode()
        {
            return (byte)Type | RequestId;
        }

        /// <summary>Indexed access to VarBind collection of the Pdu.</summary>
        /// <param name="index">Index position of the VarBind entry</param>
        /// <returns>VarBind entry at the specified index</returns>
        /// <exception cref="IndexOutOfRangeException">Thrown when index is outside the bounds of the collection</exception>
        public Vb this[int index]
        {
            get { return VbList[index]; }
        }

        /// <summary>Access variable bindings using Vb Oid value</summary>
        /// <param name="oid">Required Oid value</param>
        /// <returns>Variable binding with the Oid matching the parameter, otherwise null</returns>
        public Vb this[Oid oid]
        {
            get
            {
                if (!VbList.ContainsOid(oid))
                    return null;

                foreach (Vb v in VbList)
                {
                    if (v.Oid.Equals(oid))
                        return v;
                }

                return null;
            }
        }

        /// <summary>Access variable bindings using Vb Oid value in the string format</summary>
        /// <param name="oid">Oid value in string representation</param>
        /// <returns>Variable binding with the Oid matching the parameter, otherwise null</returns>
        public Vb this[string oid]
        {
            get
            {
                foreach (Vb v in VbList)
                {
                    if (v.Oid.Equals(oid))
                        return v;
                }

                return null;
            }
        }

        /// <summary>Get VarBind collection enumerator.</summary>
        /// <returns>Enumerator</returns>
        public IEnumerator<Vb> GetEnumerator()
        {
            return VbList.GetEnumerator();
        }

        /// <summary>Get VarBind collection enumerator.</summary>
        /// <returns>Enumerator</returns>
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return ((System.Collections.IEnumerable)VbList).GetEnumerator();
        }
    }
}
