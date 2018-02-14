using SnmpSharpNet.Exception;
using System;
using System.Linq;

namespace SnmpSharpNet.Types
{
    /// <summary>Represents SNMP sequence</summary>
    [Serializable]
    public class Sequence :
        AsnType,
        ICloneable
    {
        /// <summary>data buffer</summary>
        protected byte[] _data;

        /// <summary>Constructor</summary>
        public Sequence() :
            base()
        {
            Type = SnmpConstants.SMI_SEQUENCE;
            _data = null;
        }

        /// <summary>Constructor.</summary>
        /// <param name="value">Sequence data</param>
        public Sequence(byte[] value)
            : this()
        {
            if (value != null && value.Length > 0)
                _data = value.ToArray();
        }

        /// <summary>Set sequence data</summary>
        /// <param name="value">Byte array containing BER encoded sequence data</param>
        public void Set(byte[] value)
        {
            if (value == null || value.Length <= 0)
                _data = null;
            else
                _data = value.ToArray();
        }

        /// <summary>BER encode sequence</summary>
        /// <param name="buffer">Target buffer</param>
        public override void Encode(MutableByte buffer)
        {
            int dataLen = 0;
            if (_data != null && _data.Length > 0)
                dataLen = _data.Length;

            BuildHeader(buffer, Type, dataLen);

            if (dataLen > 0)
                buffer.Append(_data);
        }

        /// <summary>Decode sequence from the byte array. Returned offset value is advanced by the size of the sequence header.</summary>
        /// <param name="buffer">Source data buffer</param>
        /// <param name="offset">Offset within the buffer to start parsing from</param>
        /// <returns>Returns offset position after the sequence header</returns>
        public override int Decode(byte[] buffer, int offset)
        {
            _data = null;

            int asnType = ParseHeader(buffer, ref offset, out int dataLen);

            if (asnType != Type)
                throw new SnmpException("Invalid ASN.1 type.");

            if (offset + dataLen > buffer.Length)
                throw new OverflowException("Sequence longer then packet.");

            if (dataLen > 0)
                _data = buffer.Skip(offset).Take(dataLen).ToArray();

            return offset;
        }

        /// <summary>Get sequence data</summary>
        public byte[] Value
        {
            get { return _data; }
        }

        /// <summary>Clone sequence</summary>
        /// <returns>Cloned sequence cast as object</returns>
        public override object Clone()
        {
            return new Sequence(_data);
        }
    }
}
