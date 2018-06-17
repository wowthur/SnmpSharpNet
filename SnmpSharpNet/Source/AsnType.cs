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

    /// <summary>Base class for all ASN.1 value classes</summary>
    public abstract class AsnType : ICloneable
    {
        /// <summary> Defines the "high bit" that is the sign extension bit for a 8-bit signed value.</summary>
        protected const byte HighBit = 0x80;

        /// <summary> Defines the BER extension "value" that is used to mark an extension type.</summary>
        protected const byte ExtensionId = 0x1F;

        /// <summary>Get ASN.1 value type stored in this class.</summary>
        public byte Type { get; set; }

        /// <summary>Encodes the data object in the specified buffer</summary>
        /// <param name="buffer">The buffer to write the encoded information</param>
        public abstract void Encode(MutableByte buffer);

        /// <summary>Decodes the ASN.1 buffer and sets the values in the AsnType object.</summary>
        /// <param name="buffer">The encoded data buffer</param>
        /// <param name="offset">The offset of the first valid byte.</param>
        /// <returns>New offset pointing to the byte after the last decoded position
        /// </returns>
        public abstract int Decode(byte[] buffer, int offset);

        /// <summary>Append BER encoded length to the <see cref="MutableByte"/></summary>
        /// <param name="mb">MutableArray to append BER encoded length to</param>
        /// <param name="asnLength">Length value to encode.</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when length value to encode is less then 0</exception>
        internal static void BuildLength(MutableByte mb, int asnLength)
        {
            if (asnLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(asnLength), "Length cannot be less then 0.");
            }

            byte[] len = BitConverter.GetBytes(asnLength);
            MutableByte buf = new MutableByte();

            for (int i = 3; i >= 0; i--)
            {
                if (len[i] != 0 || buf.Length > 0)
                    buf.Append(len[i]);
            }

            if (buf.Length == 0)
            {
                // we are encoding a 0 value. Can't have a 0 byte length encoding
                buf.Append(0);
            }

            // check for short form encoding
            if (buf.Length == 1 && (buf[0] & HighBit) == 0)
                mb.Append(buf); // done
            else
            {
                // long form encoding
                byte encHeader = (byte)buf.Length;
                encHeader = (byte)(encHeader | HighBit);
                mb.Append(encHeader);
                mb.Append(buf);
            }
        }

        /// <summary>MutableByte version of ParseLength. Retrieve BER encoded length from a byte array at supplied offset</summary>
        /// <param name="mb">BER encoded data</param>
        /// <param name="offset">Offset to start parsing length from</param>
        /// <returns>Length value</returns>
        /// <exception cref="OverflowException">Thrown when buffer is too short</exception>
        internal static int ParseLength(byte[] mb, ref int offset)
        {
            if (offset >= mb.Length)
                throw new OverflowException("Buffer is too short.");

            int dataLen = 0;
            if ((mb[offset] & HighBit) == 0)
            {
                // short form encoding
                dataLen = mb[offset++];
                return dataLen; // we are done
            }

            dataLen = mb[offset++] & ~HighBit; // store byte length of the encoded length value

            int value = 0;
            for (int i = 0; i < dataLen; i++)
            {
                value <<= 8;
                value |= mb[offset++];
                if (offset > mb.Length || (i < (dataLen - 1) && offset == mb.Length))
                    throw new OverflowException("Buffer is too short.");
            }

            return value;
        }

        /// <summary>Build ASN.1 header in the MutableByte array.</summary>
        /// <remarks>
        /// Header is the TL part of the TLV (type, length, value) BER encoded data representation.
        ///
        /// Each value is encoded as a Type byte, length of the data field and the actual, encoded
        /// data. This method will encode the type and length fields.
        /// </remarks>
        /// <param name="mb">MurableByte array</param>
        /// <param name="asnType">ASN.1 header type</param>
        /// <param name="asnLength">Length of the data contained in the header</param>
        internal static void BuildHeader(MutableByte mb, byte asnType, int asnLength)
        {
            mb.Append(asnType);
            BuildLength(mb, asnLength);
        }

        /// <summary>Parse ASN.1 header.</summary>
        /// <param name="mb">BER encoded data</param>
        /// <param name="offset">Offset in the packet to start parsing the header from</param>
        /// <param name="length">Length of the data in the section starting with parsed header</param>
        /// <returns>ASN.1 type of the header</returns>
        /// <exception cref="OverflowException">Thrown when buffer is too short</exception>
        /// <exception cref="SnmpException">Thrown when invalid type is encountered in the header</exception>
        internal static byte ParseHeader(byte[] mb, ref int offset, out int length)
        {
            if ((mb.Length - offset) < 1)
                throw new OverflowException("Buffer is too short.");

            // ASN.1 type
            byte asnType = mb[offset++];
            if ((asnType & ExtensionId) == ExtensionId)
                throw new SnmpException("Invalid SNMP header type");

            // length
            length = ParseLength(mb, ref offset);
            return asnType;
        }

        /// <summary>Abstract Clone() member function</summary>
        /// <returns>Duplicated current object cast as Object</returns>
        public abstract object Clone();
    }
}
