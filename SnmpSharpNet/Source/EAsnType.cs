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
    public enum EAsnType
    {
        /// <summary>Bool true/false value type</summary>
        Boolean = 0x01,

        /// <summary>Signed 32-bit integer type</summary>
        Integer = 0x02,

        /// <summary>Bit sequence type</summary>
        BitString = 0x03,

        /// <summary>Octet (byte) value type</summary>
        OctetString = 0x04,

        /// <summary>Null (no value) type</summary>
        Null = 0x05,

        /// <summary>Object id type</summary>
        ObjectId = 0x06,

        /// <summary>Arbitrary data type</summary>
        Sequence = 0x10,

        /// <summary>
        /// Defined by referencing a fixed, unordered list of types,
        /// some of which may be declared optional. Each value is an
        /// unordered list of values, one from each component type.
        /// </summary>
        Set = 0x11,

        /// <summary>
        /// Generally useful, application-independent types and
        /// construction mechanisms.
        /// </summary>
        Universal = 0x00,

        /// <summary>
        /// Relevant to a particular application. These are defined
        /// in standards other than ASN.1.
        /// </summary>
        Application = 0x40,

        /// <summary>Also relevant to a particular application, but limited by context</summary>
        Context = 0x80,

        /// <summary>These are types not covered by any standard but instead defined by users.</summary>
        Private = 0xC0,

        /// <summary>A primitive data object.</summary>
        Primitive = 0x00,

        /// <summary> A constructed data object such as a set or sequence.</summary>
        Constructor = 0x20,
    }
}
