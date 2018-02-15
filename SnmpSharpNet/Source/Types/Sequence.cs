namespace SnmpSharpNet.Types
{
    using System;
    using System.Linq;
    using SnmpSharpNet.Exception;

    /// <summary>Represents SNMP sequence</summary>
    [Serializable]
    public class Sequence :
        AsnType,
        ICloneable
    {
        /// <summary>data buffer</summary>
        protected byte[] data;

        /// <summary>Constructor</summary>
        public Sequence()
            : base()
        {
            Type = SnmpConstants.SmiSequence;
            data = null;
        }

        /// <summary>Constructor.</summary>
        /// <param name="value">Sequence data</param>
        public Sequence(byte[] value)
            : this()
        {
            if (value != null && value.Length > 0)
                data = value.ToArray();
        }

        /// <summary>Set sequence data</summary>
        /// <param name="value">Byte array containing BER encoded sequence data</param>
        public void Set(byte[] value)
        {
            if (value == null || value.Length <= 0)
                data = null;
            else
                data = value.ToArray();
        }

        /// <summary>BER encode sequence</summary>
        /// <param name="buffer">Target buffer</param>
        public override void Encode(MutableByte buffer)
        {
            int dataLen = 0;
            if (data != null && data.Length > 0)
                dataLen = data.Length;

            BuildHeader(buffer, Type, dataLen);

            if (dataLen > 0)
                buffer.Append(data);
        }

        /// <summary>Decode sequence from the byte array. Returned offset value is advanced by the size of the sequence header.</summary>
        /// <param name="buffer">Source data buffer</param>
        /// <param name="offset">Offset within the buffer to start parsing from</param>
        /// <returns>Returns offset position after the sequence header</returns>
        public override int Decode(byte[] buffer, int offset)
        {
            data = null;

            int asnType = ParseHeader(buffer, ref offset, out int dataLen);

            if (asnType != Type)
                throw new SnmpException("Invalid ASN.1 type.");

            if (offset + dataLen > buffer.Length)
                throw new OverflowException("Sequence longer then packet.");

            if (dataLen > 0)
                data = buffer.Skip(offset).Take(dataLen).ToArray();

            return offset;
        }

        /// <summary>Get sequence data</summary>
        public byte[] Value
        {
            get { return data; }
        }

        /// <summary>Clone sequence</summary>
        /// <returns>Cloned sequence cast as object</returns>
        public override object Clone()
        {
            return new Sequence(data);
        }
    }
}
