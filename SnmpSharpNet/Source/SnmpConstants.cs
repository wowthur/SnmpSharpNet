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
    using SnmpSharpNet.Types;

    /// <summary>SNMP SMI version 1, version 2c and version 3 constants.</summary>
    public static class SnmpConstants
    {
        /// <summary>No error</summary>
        public const int ErrNoError = 0;

        /// <summary>Request too big</summary>
        public const int ErrTooBig = 1;

        /// <summary>Object identifier does not exist</summary>
        public const int ErrNoSuchName = 2;

        /// <summary>Invalid value</summary>
        public const int ErrBadValue = 3;

        /// <summary>Requested invalid operation on a read only table</summary>
        public const int ErrReadOnly = 4;

        /// <summary>Generic error</summary>
        public const int ErrGenError = 5;

        /// <summary>Enterprise specific error</summary>
        public const int EnterpriseSpecific = 6;

        /// <summary>Access denied</summary>
        public const int ErrNoAccess = 6;

        /// <summary>Incorrect type</summary>
        public const int ErrWrongType = 7;

        /// <summary>Incorrect length</summary>
        public const int ErrWrongLength = 8;

        /// <summary>Invalid encoding</summary>
        public const int ErrWrongEncoding = 9;

        /// <summary>Object does not have correct value</summary>
        public const int ErrWrongValue = 10;

        /// <summary>Insufficient rights to perform create operation</summary>
        public const int ErrNoCreation = 11;

        /// <summary>Inconsistent value</summary>
        public const int ErrInconsistentValue = 12;

        /// <summary>Requested resource is not available</summary>
        public const int ErrResourceUnavailable = 13;

        /// <summary>Unable to commit values</summary>
        public const int ErrCommitFailed = 14;

        /// <summary>Undo request failed</summary>
        public const int ErrUndoFailed = 15;

        /// <summary>Authorization failed</summary>
        public const int ErrAuthorizationError = 16;

        /// <summary>Instance not writable</summary>
        public const int ErrNotWritable = 17;

        /// <summary>Inconsistent object identifier</summary>
        public const int ErrInconsistentName = 18;

        /// <summary>Cold start trap</summary>
        public const int ColdStart = 0;

        /// <summary>Warm start trap</summary>
        public const int WarmStart = 1;

        /// <summary>Link down trap</summary>
        public const int LinkDown = 2;

        /// <summary>Link up trap</summary>
        public const int LinkUp = 3;

        /// <summary>Authentication-failure trap</summary>
        public const int AuthenticationFailure = 4;

        /// <summary>EGP Neighbor Loss trap</summary>
        public const int EgpNeighborLoss = 5;

        /// <summary>Signed 32-bit integer ASN.1 data type. For implementation, see <see cref="Integer32"/></summary>
        public const byte SmiInteger = (byte)(EAsnType.Universal | EAsnType.Integer);

        /// <summary>String representation of the AsnType.INTEGER type.</summary>
        public const string SmiIntegerString = "Integer32";

        /// <summary>Data type representing a sequence of zero or more 8-bit byte values. For implementation, see <see cref="OctetString"/></summary>
        public const byte SmiString = (byte)(EAsnType.Universal | EAsnType.OctetString);

        /// <summary>String representation of the AsnType.OCTETSTRING type.</summary>
        public const string SmiStringString = "OctetString";

        /// <summary>Object id ASN.1 type. For implementation, see <see cref="Oid"/></summary>
        public const byte SmiObjectId = (byte)(EAsnType.Universal | EAsnType.ObjectId);

        /// <summary>String representation of the SMI_OBJECTID type.</summary>
        public const string SmiObjectIdString = "ObjectId";

        /// <summary>Null ASN.1 value type. For implementation, see <see cref="Null"/>.</summary>
        public const byte SmiNull = (byte)(EAsnType.Universal | EAsnType.Null);

        /// <summary>String representation of the SMI_NULL type.</summary>
        public const string SmiNullString = "NULL";

        /// <summary>
        /// An application string is a sequence of octets
        /// defined at the application level. Although the SMI
        /// does not define an Application String, it does define
        /// an IP Address which is an Application String of length
        /// four.
        /// </summary>
        public const byte SmiApplicationString = (byte)EAsnType.Application;

        /// <summary>String representation of the SMI_APPSTRING type.</summary>
        public const string SmiApplicationStringString = "AppString";

        /// <summary>
        /// An IP Address is an application string of length four
        /// and is indistinguishable from the SMI_APPSTRING value.
        /// The address is a 32-bit quantity stored in network byte order.
        /// </summary>
        public const byte SmiIpAddress = (byte)EAsnType.Application;

        /// <summary>String representation of the SMI_IPADDRESS type.</summary>
        public const string SmiIpAddressString = "IPAddress";

        /// <summary>
        /// A non-negative integer that may be incremented, but not
        /// decremented. The value is a 32-bit unsigned quantity representing
        /// the range of zero to 2^32-1 (4,294,967,295). When the counter
        /// reaches its maximum value it wraps back to zero and starts again.
        /// </summary>
        public const byte SmiCounter32 = (byte)EAsnType.Application | 0x01;

        /// <summary>String representation of the SMI_COUNTER32 type.</summary>
        public const string SmiCounter32String = "Counter32";

        /// <summary>
        /// Represents a non-negative integer that may increase or
        /// decrease with a maximum value of 2^32-1. If the maximum
        /// value is reached the gauge stays latched until reset.
        /// </summary>
        public const byte SmiGauge32 = (byte)EAsnType.Application | 0x02;

        /// <summary>String representation of the SMI_GAUGE32 type.</summary>
        public const string SmiGauge32String = "Gauge32";

        /// <summary>
        /// Used to represent the integers in the range of 0 to 2^32-1.
        /// This type is identical to the SMI_COUNTER32 and are
        /// indistinguishable in ASN.1
        /// </summary>
        public const byte SmiUnsigned32 = (byte)EAsnType.Application | 0x02; // same as gauge

        /// <summary>String representation of the SMI_UNSIGNED32 type.</summary>
        public const string SmiUnsigned32String = "Unsigned32";

        /// <summary>
        /// This represents a non-negative integer that counts time, modulo 2^32.
        /// The time is represented in hundredths (1/100th) of a second.
        /// </summary>
        public const byte SmiTimeTicks = (byte)EAsnType.Application | 0x03;

        /// <summary>String representation of the SMI_TIMETICKS type.</summary>
        public const string SmiTimeTicksString = "TimeTicks";

        /// <summary>
        /// Used to support the transport of arbitrary data. The
        /// data itself is encoded as an octet string, but may be in
        /// any format defined by ASN.1 or another standard.
        /// </summary>
        public const byte SmiOpaque = (byte)EAsnType.Application | 0x04;

        /// <summary>String representation of the SMI_OPAQUE type.</summary>
        public const string SmiOpaqueString = "Opaque";

        /// <summary>
        /// Defines a 64-bit unsigned counter. A counter is an integer that
        /// can be incremented, but cannot be decremented. A maximum value
        /// of 2^64 - 1 (18,446,744,073,709,551,615) can be represented.
        /// When the counter reaches it's maximum it wraps back to zero and
        /// starts again.
        /// </summary>
        public const byte SmiCounter64 = (byte)EAsnType.Application | 0x06;

        // SMIv2 only
        /// <summary>String representation of the SMI_COUNTER64 type.</summary>
        public const string SmiCounter64String = "Counter64";

        /// <summary>String representation of the unknown SMI data type.</summary>
        public const string SmiUnknownString = "Unknown";

        /// <summary>
        /// The SNMPv2 error representing that there is No-Such-Object
        /// for a particular object identifier. This error is the result
        /// of a requested object identifier that does not exist in the
        /// agent's tables
        /// </summary>
        public const byte SmiNoSuchObject = (byte)EAsnType.Context | (byte)EAsnType.Primitive;

        /// <summary>
        /// The SNMPv2 error representing that there is No-Such-Instance
        /// for a particular object identifier. This error is the result
        /// of a requested object identifier instance does not exist in the
        /// agent's tables.
        /// </summary>
        public const byte SmiNoSuchInstance = (byte)EAsnType.Context | (byte)EAsnType.Primitive | 0x01;

        /// <summary>
        /// The SNMPv2 error representing the End-Of-Mib-View.
        /// This error variable will be returned by a SNMPv2 agent
        /// if the requested object identifier has reached the
        /// end of the agent's mib table and there is no lexicographic
        /// successor.
        /// </summary>
        public const byte SmiEndOfMIBView = (byte)EAsnType.Context | (byte)EAsnType.Primitive | 0x02;

        /// <summary>SEQUENCE Variable Binding code. Hex value: 0x30</summary>
        public const byte SmiSequence = (byte)(EAsnType.Sequence | EAsnType.Cosntructor);

        /// <summary>
        /// Defines an SNMPv2 Party Clock. The Party Clock is currently
        /// Obsolete, but included for backwards compatibility. Obsoleted in RFC 1902.
        /// </summary>
        public const byte SmiPartyClock = (byte)EAsnType.Application | 0x07;

        /// <summary>sysUpTime.0 OID is the first value in the VarBind array of SNMP version 2 TRAP packets</summary>
        public static Oid SysUpTime = new Oid(new uint[] { 1, 3, 6, 1, 2, 1, 1, 3, 0 });

        /// <summary>trapObjectID.0 OID is the second value in the VarBind array of SNMP version 2 TRAP packets</summary>
        public static Oid TrapObjectId = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsUnsupportedSecLevels = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsNotInTimeWindows = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsUnknownSecurityNames = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsUnknownEngineIDs = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsWrongDigests = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid UsmStatsDecryptionErrors = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid SnmpUnknownSecurityModels = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid SnmpInvalidMsgs = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0 });

        /// <summary>SNMP version 3, USM error</summary>
        public static Oid SnmpUnknownPDUHandlers = new Oid(new uint[] { 1, 3, 6, 1, 6, 3, 11, 2, 1, 3, 0 });

        /// <summary>Array of all SNMP version 3 REPORT packet error OIDs</summary>
        public static Oid[] Version3ErrorOids = {
            UsmStatsUnsupportedSecLevels,
            UsmStatsNotInTimeWindows,
            UsmStatsUnknownSecurityNames,
            UsmStatsUnknownEngineIDs,
            UsmStatsWrongDigests,
            UsmStatsDecryptionErrors,
            SnmpUnknownSecurityModels,
            SnmpUnknownPDUHandlers,
        };

        /// <summary>Used to create correct variable type object for the specified encoded type</summary>
        /// <param name="asnType">ASN.1 type code</param>
        /// <returns>A new object matching type supplied or null if type was not recognized.</returns>
        public static AsnType GetSyntaxObject(byte asnType)
        {
            switch (asnType)
            {
                case SmiInteger:
                    return new Integer32();
                case SmiCounter32:
                    return new Counter32();
                case SmiGauge32:
                    return new Gauge32();
                case SmiCounter64:
                    return new Counter64();
                case SmiTimeTicks:
                    return new TimeTicks();
                case SmiString:
                    return new OctetString();
                case SmiOpaque:
                    return new Opaque();
                case SmiIpAddress:
                    return new IpAddress();
                case SmiObjectId:
                    return new Oid();
                case SmiPartyClock:
                    return new V2PartyClock();
                case SmiNoSuchInstance:
                    return new NoSuchInstance();
                case SmiNoSuchObject:
                    return new NoSuchObject();
                case SmiEndOfMIBView:
                    return new EndOfMibView();
                case SmiNull:
                    return new Null();
            }

            throw new ArgumentException("Invalid value asnType");
        }

        /// <summary>
        /// Return SNMP type object of the type specified by name. Supported variable types are:
        /// * <see cref="Integer32"/>
        /// * <see cref="Counter32"/>
        /// * <see cref="Gauge32"/>
        /// * <see cref="Counter64"/>
        /// * <see cref="TimeTicks"/>
        /// * <see cref="OctetString"/>
        /// * <see cref="IpAddress"/>
        /// * <see cref="Oid"/>
        /// * <see cref="Null"/>
        /// </summary>
        /// <param name="name">Name of the object type</param>
        /// <returns>New <see cref="AsnType"/> object.</returns>
        public static AsnType GetSyntaxObject(string name)
        {
            switch (name)
            {
                case "Integer32":
                    return new Integer32();
                case "Counter32":
                    return new Counter32();
                case "Gauge32":
                    return new Gauge32();
                case "Counter64":
                    return new Counter64();
                case "TimeTicks":
                    return new TimeTicks();
                case "OctetString":
                    return new OctetString();
                case "IpAddress":
                    return new IpAddress();
                case "Oid":
                    return new Oid();
                case "Null":
                    return new Null();
            }

            throw new ArgumentException("Invalid value type name");
        }

        /// <summary>Return string representation of the SMI value type.</summary>
        /// <param name="type">AsnType class Type member function value.</param>
        /// <returns>String formatted name of the SMI type.</returns>
        public static string GetTypeName(byte type)
        {
            switch (type)
            {
                case SmiIpAddress:
                    return SmiIpAddressString;

#pragma warning disable SA1005
#pragma warning disable SA1515
                //case SMI_APPSTRING:
                //    return SMI_APPSTRING_STR;
#pragma warning restore SA1515
#pragma warning restore SA1005

                case SmiCounter32:
                    return SmiCounter32String;
                case SmiCounter64:
                    return SmiCounter64String;

#pragma warning disable SA1005
#pragma warning disable SA1515
                //case SMI_GAUGE32:
                //    return SMI_GAUGE32_STR;
#pragma warning restore SA1515
#pragma warning restore SA1005

                case SmiInteger:
                    return SmiIntegerString;
                case SmiNull:
                    return SmiNullString;
                case SmiObjectId:
                    return SmiObjectIdString;
                case SmiOpaque:
                    return SmiOpaqueString;
                case SmiString:
                    return SmiStringString;
                case SmiTimeTicks:
                    return SmiTimeTicksString;
                case SmiUnsigned32:
                    return SmiUnsigned32String;
            }

            return SmiUnknownString;
        }

        /// <summary>Debugging function used to dump on the console supplied byte array in a format suitable for console output.</summary>
        /// <param name="data">Byte array data</param>
        public static void DumpHex(byte[] data)
        {
            int val = 0;

            for (int i = 0; i < data.Length; i++)
            {
                if (val == 0)
                    Console.Write("{0:d04} ", i);

                Console.Write("{0:x2}", data[i]);
                val += 1;
                if (val == 16)
                {
                    val = 0;
                    Console.Write("\n");
                }
                else
                    Console.Write(" ");
            }

            if (val != 0)
                Console.WriteLine("\n");
        }

        /// <summary>Check if SNMP version value is correct</summary>
        /// <param name="version">SNMP version value</param>
        /// <returns>true if valid SNMP version, otherwise false</returns>
        public static bool IsValidVersion(int version)
        {
            if (version == (int)ESnmpVersion.Ver1 || version == (int)ESnmpVersion.Ver2 || version == (int)ESnmpVersion.Ver3)
                return true;

            return false;
        }
    }
}