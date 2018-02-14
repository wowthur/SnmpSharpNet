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
using SnmpSharpNet.Types;
using System;

namespace SnmpSharpNet
{
    /// <summary>Collection of static helper methods making operations with SMI data types simpler and easier.</summary>
    public sealed class SMIDataType
    {

        private SMIDataType()
        {
        }

        /// <summary>Get class instance for the SMI value type with the specific TLV encoding type code.</summary>
        /// <param name="asnType">SMI type code</param>
        /// <returns>Correct SMI type class instance for the data type or null if type is not recognized</returns>
        public static AsnType GetSyntaxObject(byte asnType)
        {
            if (!IsValidType(asnType))
                return null;

            return GetSyntaxObject((ESMIDataTypeCode)asnType);
        }

        /// <summary>Used to create correct variable type object for the specified encoded type</summary>
        /// <param name="asnType">ASN.1 type code</param>
        /// <returns>A new object matching type supplied or null if type was not recognized.</returns>
        public static AsnType GetSyntaxObject(ESMIDataTypeCode asnType)
        {
            AsnType obj = null;

            if (asnType == ESMIDataTypeCode.Integer)
                obj = new Integer32();
            else if (asnType == ESMIDataTypeCode.Counter32)
                obj = new Counter32();
            else if (asnType == ESMIDataTypeCode.Gauge32)
                obj = new Gauge32();
            else if (asnType == ESMIDataTypeCode.Counter64)
                obj = new Counter64();
            else if (asnType == ESMIDataTypeCode.TimeTicks)
                obj = new TimeTicks();
            else if (asnType == ESMIDataTypeCode.OctetString)
                obj = new OctetString();
            else if (asnType == ESMIDataTypeCode.Opaque)
                obj = new Opaque();
            else if (asnType == ESMIDataTypeCode.IPAddress)
                obj = new IpAddress();
            else if (asnType == ESMIDataTypeCode.ObjectId)
                obj = new Oid();
            else if (asnType == ESMIDataTypeCode.PartyClock)
                obj = new V2PartyClock();
            else if (asnType == ESMIDataTypeCode.NoSuchInstance)
                obj = new NoSuchInstance();
            else if (asnType == ESMIDataTypeCode.NoSuchObject)
                obj = new NoSuchObject();
            else if (asnType == ESMIDataTypeCode.EndOfMibView)
                obj = new EndOfMibView();
            else if (asnType == ESMIDataTypeCode.Null)
                obj = new Null();

            return obj;
        }

        /// <summary>
        /// Return SNMP type object of the type specified by name. Supported variable types are:
        /// <see cref="Integer32"/>, <see cref="Counter32"/>, <see cref="Gauge32"/>, <see cref="Counter64"/>,
        /// <see cref="TimeTicks"/>, <see cref="OctetString"/>, <see cref="IpAddress"/>, <see cref="Oid"/>, and
        /// <see cref="Null"/>.
        /// 
        /// Type names are the same as support class names compared without case sensitivity (e.g. Integer == INTEGER).
        /// </summary>
        /// <param name="name">Name of the object type (not case sensitive)</param>
        /// <returns>New <see cref="AsnType"/> object.</returns>
        public static AsnType GetSyntaxObject(string name)
        {
            AsnType obj = null;
            if (name.ToUpper().Equals("INTEGER32") || name.ToUpper().Equals("INTEGER"))
                obj = new Integer32();
            else if (name.ToUpper().Equals("COUNTER32"))
                obj = new Counter32();
            else if (name.ToUpper().Equals("GAUGE32"))
                obj = new Gauge32();
            else if (name.ToUpper().Equals("COUNTER64"))
                obj = new Counter64();
            else if (name.ToUpper().Equals("TIMETICKS"))
                obj = new TimeTicks();
            else if (name.ToUpper().Equals("OCTETSTRING"))
                obj = new OctetString();
            else if (name.ToUpper().Equals("IPADDRESS"))
                obj = new IpAddress();
            else if (name.ToUpper().Equals("OID"))
                obj = new Oid();
            else if (name.ToUpper().Equals("NULL"))
                obj = new Null();
            else
                throw new ArgumentException("Invalid value type name");

            return obj;
        }

        /// <summary>Return string representation of the SMI value type.</summary>
        /// <param name="type">AsnType class Type member function value.</param>
        /// <returns>String formatted name of the SMI type.</returns>
        public static string GetTypeName(ESMIDataTypeCode type)
        {
            return Enum.GetName(typeof(ESMIDataTypeCode), type);
        }

        /// <summary>Check if byte code is a valid SMI data type code</summary>
        /// <param name="smiType">SMI data type code to test</param>
        /// <returns>true if valid SMI data type, otherwise false</returns>
        public static bool IsValidType(byte smiType)
        {
            byte[] validSMITypes = (byte[])Enum.GetValues(typeof(ESMIDataTypeCode));

            foreach (int type in validSMITypes)
            {
                if (type == smiType)
                    return true;
            }

            return false;
        }
    }
}
