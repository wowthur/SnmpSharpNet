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
using System;
using System.Linq;
using System.Text;

namespace SnmpSharpNet
{
    /// <summary>Mutable byte implementation class</summary>
    /// <remarks>
    /// Mutable byte class allows for manipulation of a byte array with
    /// operations like append, prepend.
    /// 
    /// Functionality is implemented through temporary buffer creation
    /// and data duplication.
    ///
    /// <code>
    /// MutableByte buffer = new MutableByte();
    /// buffer += "test data";
    /// buffer.Append(". More test data");
    /// buffer.Prepend("This is ");
    /// Console.WriteLine(buffer.ToString()); // Prints out "This is test data. More test data"
    /// buffer.RemoveBeginning(8); // The buffer now holds "test data. More test data"
    /// buffer.Prepend("It could be "); // buffer is "It could be test data. More test data"
    /// buffer.RemoveEnd(" More test data".Length); // buffer: "It could be test data."
    /// buffer.Remove(12,5); // buffer: "It could be data"
    /// Console.WriteLine("{0}",Convert.ToChar(buffer[1])); // Output: "t"
    /// byte[] tmpBuffer = buffer; // Implicit conversion to byte[]
    /// buffer.Reset(); // Erase all the data from the buffer
    /// </code>
    /// </remarks>
    public class MutableByte : Object, ICloneable, IComparable<MutableByte>, IComparable<byte[]>
    {
        /// <summary>Internal byte buffer</summary>
        byte[] _buffer;

        /// <summary>Standard constructor. Initializes the internal buffer to null.</summary>
        public MutableByte()
        {
        }

        /// <summary>Constructor. Initialize internal buffer with supplied value.</summary>
        /// <param name="buf">Byte array to copy into internal buffer</param>
        public MutableByte(byte[] buf)
        {
            if (buf != null)
                _buffer = buf.ToArray();
        }

        /// <summary>
        /// Create new <see cref="MutableByte"/> class initialized by adding two byte buffers together. If
        /// one of the supplied byte arrays is value null then <see cref="ArgumentNullException"/> is thrown.
        /// </summary>
        /// <param name="buf1">First byte array</param>
        /// <param name="buf2">Second byte array</param>
        /// <exception cref="ArgumentNullException">If one or both arguments are null or length 0</exception>
        public MutableByte(byte[] buf1, byte[] buf2)
        {
            if (buf1 == null || buf1.Length == 0)
                throw new ArgumentNullException(nameof(buf1));

            if (buf2 == null || buf2.Length == 0)
                throw new ArgumentNullException(nameof(buf2));

            _buffer = buf1.Concat(buf2).ToArray();
        }

        /// <summary>
        /// Create new <see cref="MutableByte"/> class initialized with data from the supplied array up to length of buflen. Internaly,
        /// a call is made to MutableByte.Set(buf[],int) to initialize the new class data buffer.
        /// </summary>
        /// <param name="buf">Array used to initialize the class data</param>
        /// <param name="buflen">Number of bytes to use from the argument array to initialize the class.</param>
        public MutableByte(byte[] buf, int buflen)
        {
            Set(buf, buflen);
        }

        /// <summary>Get byte[] buffer value. This property is internal because it exposes the internal byte array.</summary>
        internal byte[] Value
        {
            get { return _buffer; }
        }

        /// <summary>Byte buffer current length</summary>
        public int Length
        {
            get
            {
                if (_buffer == null)
                    return 0;

                return _buffer.Length;
            }
        }

        /// <summary>Set internal buffer to supplied value. Overwrites existing data.</summary>
        /// <param name="buf">Value to copy into internal buffer</param>
        public void Set(byte[] buf)
        {
            _buffer = null;

            if (buf == null || buf.Length == 0)
                return;

            _buffer = buf.ToArray();
        }

        /// <summary>Copy source buffer array up to length into the class.</summary>
        /// <param name="buf">Source byte array</param>
        /// <param name="length">Number of items to copy</param>
        /// <exception cref="ArgumentNullException">Thrown if buf argument is null or length of zero</exception>
        public void Set(byte[] buf, int length)
        {
            _buffer = null;
            if (buf == null || buf.Length == 0)
                throw new ArgumentNullException(nameof(buf), "Byte array is null.");

            _buffer = buf.Take(length).ToArray();
        }

        /// <summary>
        /// Set internal buffer to size 1 and copy supplied byte value into it
        /// </summary>
        /// <param name="buf">Byte value to copy into internal byte array of size 1</param>
        public void Set(byte buf)
        {
            _buffer = new byte[1] { buf };
        }

        /// <summary>Set value at specified position to the supplied value</summary>
        /// <param name="position">Zero based offset from the beginning of the buffer</param>
        /// <param name="value">Value to set</param>
        public void Set(int position, byte value)
        {
            if (position < 0 || position >= Length)
                return;

            _buffer[position] = value;
        }

        /// <summary>Set class value to the contents of the supplied array starting from offset with specified length</summary>
        /// <param name="value">Value to set the class to</param>
        /// <param name="offset">From the value start copying data from this offset</param>
        /// <param name="length">Byte count to copy</param>
        public void Set(byte[] value, int offset, int length)
        {
            if (
                offset < 0 ||
                length < 0 ||
                (offset + length) > value.Length
                )
                throw new ArgumentOutOfRangeException();

            _buffer = value.Skip(offset).Take(length).ToArray();
        }

        /// <summary>Set class value with bytes from the string. UTF8 encoding is assumed.</summary>
        /// <param name="value">String value</param>
        public void Set(string value)
        {
            if (value == null || value.Length <= 0)
                _buffer = null;
            else
                Set(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>Append data to the internal buffer</summary>
        /// <param name="buf">Byte array to append to the internal byte array</param>
        /// <exception cref="ArgumentNullException">Thrown when argument buf is null or length of zero</exception>
        public void Append(byte[] buf)
        {
            if (buf == null || buf.Length == 0)
                return; // null value received. nothing to append

            if (_buffer == null)
                Set(buf);
            else
                _buffer = _buffer.Concat(buf).ToArray();
        }

        /// <summary>Append a single byte value to the internal buffer</summary>
        /// <param name="buf">Byte value to append to the internal buffer</param>
        public void Append(byte buf)
        {
            if (_buffer == null)
                Set(buf);
            else
            {
                Array.Resize(ref _buffer, _buffer.Length + 1);
                _buffer[_buffer.Length - 1] = buf;
            }
        }

        /// <summary>Insert byte array at position</summary>
        /// <param name="position">Insert position</param>
        /// <param name="buf">Byte array to insert at specified position</param>
        public void Insert(int position, byte[] buf)
        {
            if (position < 0 || position >= Length)
                throw new ArgumentOutOfRangeException(nameof(position), "Index outside of the buffer scope");

            if (buf == null)
                throw new ArgumentNullException(nameof(buf));

            if (position == 0)
            {
                Prepend(buf);
                return;
            }

            _buffer = _buffer.Take(position).Concat(buf).Concat(_buffer.Skip(position)).ToArray();
        }

        /// <summary>Insert single byte at specified location</summary>
        /// <param name="position">Location to perform insert (0 based)</param>
        /// <param name="buf">Byte value to insert</param>
        public void Insert(int position, byte buf)
        {
            if (position < 0 || position >= Length)
                throw new ArgumentOutOfRangeException(nameof(position), "Index outside of the buffer scope");

            if (position == 0)
            {
                Prepend(buf);
                return;
            }

            _buffer = _buffer.Take(position).Concat(new byte[] { buf }).Concat(_buffer.Skip(position)).ToArray();
        }

        /// <summary>Prepend (insert at beginning) a byte array</summary>
        /// <param name="buf">Byte array to prepend</param>
        public void Prepend(byte[] buf)
        {
            if (Length <= 0)
                Set(buf);
            else
                _buffer = buf.Concat(_buffer).ToArray();
        }

        /// <summary>Prepend (add at the beginning) a single byte value</summary>
        /// <param name="buf">Byte value to prepend</param>
        public void Prepend(byte buf)
        {
            if (Length <= 0)
                Set(buf);
            else
                _buffer = (new byte[] { buf }).Concat(_buffer).ToArray();
        }

        /// <summary>Remove bytes from the beginning of the array</summary>
        /// <param name="count">Number of bytes to remove</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when count points beyond the bounds of the internal byte array</exception>
        public void RemoveBeginning(int count)
        {
            if (Length == 0)
                throw new ArgumentOutOfRangeException(nameof(count), "Buffer is length 0. Unable to remove members.");

            if (count > _buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Byte count is greater then the length of the array");

            if (count == Length)
            {
                // Remove all values
                Reset();
                return;
            }

            _buffer = _buffer.Skip(count).ToArray();
        }

        /// <summary>Remove number of byte values from the end of the internal buffer</summary>
        /// <param name="count">Number of bytes to remove</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when count points beyond the bounds of the internal byte array</exception>
        public void RemoveEnd(int count)
        {
            if (Length == 0)
                throw new ArgumentOutOfRangeException(nameof(count), "Buffer is length 0. Unable to remove members.");

            if (count > _buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Byte count is greater then the length of the array");

            if (count == Length)
            {
                // Remove all values
                Reset();
                return;
            }

            Array.Resize(ref _buffer, _buffer.Length - count);
        }

        /// <summary>Remove array byte members starting with position start for the length length bytes.</summary>
        /// <param name="start">Start position of bytes to remove</param>
        /// <param name="count">How many bytes to remove</param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown if internal buffer is null or length zero, if start argument
        /// is less then zero or past the end of the internal byte array, and if argument count is greater then length of the
        /// internal byte array, start + count is past greater then the length of the buffer array or if argument count is less then 1.
        /// </exception>
        public void Remove(int start, int count)
        {
            if (_buffer.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(start), "Byte array is empty. Unable to remove members.");

            if (start < 0 || start >= Length)
                throw new ArgumentOutOfRangeException(nameof(start), "Start argument is beyond the bounds of the array.");

            if (count > Length || (start + count) > Length || count < 1)
                throw new ArgumentOutOfRangeException(nameof(count), "Length argument is beyond the bounds of the array.");

            if (start == 0)
                RemoveBeginning(count);
            else if (start + count == Length)
                RemoveEnd(count);
            else
                _buffer = _buffer.Take(start).Concat(_buffer.Skip(start + count)).ToArray();
        }

        /// <summary>Get sub-array</summary>
        /// <param name="position">Start of the sub-array. Zero based.</param>
        /// <param name="length">Count of bytes to copy</param>
        /// <returns>MutableByte array containing the sub-array.</returns>
        /// <exception cref="OverflowException">Thrown when position starts before the beginning of the array (position is less then 0) or 
        /// position + length is greater then the length of the byte array contained in the object.</exception>
        public MutableByte Get(int position, int length)
        {
            if (_buffer.Length <= position || _buffer.Length < (position + length))
                throw new OverflowException("Buffer is too small to extract sub-array.\r\n" + string.Format("buffer length: {0} offset: {1} length: {2}", _buffer.Length, position, length));

            return new MutableByte(_buffer.Skip(position).Take(length).ToArray());
        }

        /// <summary>Add <see cref="MutableByte"/> and byte array values into a new MutableByte class.</summary>
        /// <param name="buf1"><see cref="MutableByte"/> class</param>
        /// <param name="buf2"><see cref="MutableByte"/> class</param>
        /// <returns>New <see cref="MutableByte"/> class containing concatenated result</returns>
        public static MutableByte operator +(MutableByte buf1, byte[] buf2)
        {
            return new MutableByte(buf1.Value, buf2);
        }

        /// <summary>Add <see cref="MutableByte"/> buffer values.</summary>
        /// <param name="buf1"><see cref="MutableByte"/> class</param>
        /// <param name="buf2"><see cref="MutableByte"/> class</param>
        /// <returns>New <see cref="MutableByte"/> class containing concatenated result</returns>
        public static MutableByte operator +(MutableByte buf1, MutableByte buf2)
        {
            return new MutableByte(buf1, buf2);
        }

        /// <summary>Add a MutableByte array and a single byte value</summary>
        /// <param name="buf1">MutableByte array</param>
        /// <param name="b">Byte value</param>
        /// <returns>New MutableByte array with values added</returns>
        public static MutableByte operator +(MutableByte buf1, byte b)
        {
            MutableByte tmp = new MutableByte(buf1.Value);
            tmp.Append(b);
            return tmp;
        }

        /// <summary>Compare two <see cref="MutableByte"/> class contents</summary>
        /// <param name="buf1"><see cref="MutableByte"/> class</param>
        /// <param name="buf2"><see cref="MutableByte"/> class</param>
        /// <returns>true if the same, otherwise falseB</returns>
        public static bool operator ==(MutableByte buf1, MutableByte buf2)
        {
            if (((Object)buf1) == null && ((Object)buf2) == null)
                return true;

            if (((Object)buf1) == null || ((Object)buf2) == null)
                return false;

            return buf1.Equals(buf2);
        }

        /// <summary>Negative compare.</summary>
        /// <param name="buf1">First MutableByte array</param>
        /// <param name="buf2">Second MutableByte array</param>
        /// <returns>true if class values are not equal, otherwise false.</returns>
        public static bool operator !=(MutableByte buf1, MutableByte buf2)
        {
            if (((Object)buf1) == null && ((Object)buf2) == null)
                return false;

            if (((Object)buf1) == null || ((Object)buf2) == null)
                return true;

            return !(buf1.Equals(buf2));
        }

        /// <summary>Allow implicit casting of this object as a byte array for any callers.</summary>
        /// <param name="obj">MutableByte object whose values should be cast as byte array</param>
        /// <returns>Byte array represented in the MutableObject class.</returns>
        public static implicit operator byte[] (MutableByte obj)
        {
            return obj.Value;
        }

        /// <summary>Index operator. Index access to the underlying byte array</summary>
        /// <param name="index">Index to access</param>
        /// <returns>byte array value</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if requested byte index is outside the size of the internal byte array</exception>
        public byte this[int index]
        {
            get
            {
                if (index < 0 || index >= Length)
                    return (byte)0x00; // don't throw an exception here

                return _buffer[index];
            }
            set
            {
                if (index < 0 || index >= Length)
                    return; // don't throw an exception here

                _buffer[index] = value;
            }
        }

        /// <summary>Lesser then operator overload.</summary>
        /// <param name="firstClass">First MutableByte class</param>
        /// <param name="secondClass">Second MutableByte class</param>
        /// <returns>True if firstClass is lesser then second class, otherwise false</returns>
        public static bool operator <(MutableByte firstClass, MutableByte secondClass)
        {
            if (firstClass == null && secondClass == null)
                return false;

            if (firstClass == null && secondClass != null)
                return true; // If first one is null then it is less then second one

            if (firstClass != null && secondClass == null)
                return false;

            if (firstClass.CompareTo(secondClass) < 0)
                return true;

            return false;
        }

        /// <summary>Greater then operator overload.</summary>
        /// <param name="firstClass">First MutableByte class</param>
        /// <param name="secondClass">Second MutableByte class</param>
        /// <returns>True if firstClass is greater then second class, otherwise false</returns>
        public static bool operator >(MutableByte firstClass, MutableByte secondClass)
        {
            if (firstClass == null && secondClass == null)
                return false;

            if (firstClass == null && secondClass != null)
                return false; // If first one is null then it is less then second one

            if (firstClass != null && secondClass == null)
                return true;

            if (firstClass.CompareTo(secondClass) < 0)
                return false;

            return true;
        }

        /// <summary>Compares MutableByte object against another MutableByte object or a byte array</summary>
        /// <param name="obj">Object to compare class value with. Argument can be a byte array or an instance of MutableByte class.</param>
        /// <returns>Returns true if objects match, otherwise false.</returns>
        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;

            if (obj is MutableByte)
            {
                MutableByte b = obj as MutableByte;
                if (CompareTo(b) == 0)
                    return true;
            }
            else if (obj is byte[])
            {
                byte[] b = obj as byte[];
                if (CompareTo(b) == 0)
                    return true;
            }

            return false;
        }

        /// <summary>Compare two byte arrays</summary>
        /// <param name="buf1">First byte array</param>
        /// <param name="buf2">Second byte array</param>
        /// <returns>True if array contents are the same, otherwise false.</returns>
        public static bool Equals(byte[] buf1, byte[] buf2)
        {
            if (buf1.Length != buf2.Length)
                return false;

            for (int i = 0; i < buf1.Length; i++)
            {
                if (buf1[i] != buf2[i])
                    return false;
            }

            return true;
        }

        /// <summary>Returns object hash code. Just calls the base class implementation.</summary>
        /// <returns>Base class hash code value</returns>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        /// <summary>Convert array to a string</summary>
        /// <returns>String representation of the object as a hex string</returns>
        public override string ToString()
        {
            if (_buffer == null)
                return "";

            var str = new StringBuilder();
            for (int i = 0; i < _buffer.Length; i++)
            {
                str.Append(string.Format("{0:x02} ", _buffer[i]));
                if (i > 0 && i < (_buffer.Length - 1) && (i % 16) == 0)
                    str.Append("\n");
                else if (i < (_buffer.Length - 1))
                    str.Append(" ");
            }

            return str.ToString();
        }

        /// <summary>
        /// Hexadecimal data dump of the specific range of buffer values
        /// </summary>
        /// <param name="start">Start position for data dump (0 based)</param>
        /// <param name="length">Number of bytes to include in the dump</param>
        /// <returns>String representation of the selected range.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when start and length arguments point to internal byte array locations that are outside of the array bounds.</exception>
        public string ToString(int start, int length)
        {
            if (_buffer == null)
                return "";

            if (_buffer.Length <= start || _buffer.Length < (start + length))
                throw new ArgumentOutOfRangeException(nameof(start), "Range specification past boundaries of the buffer.");

            var output = new StringBuilder();
            var dec = new StringBuilder();
            var pcnt = 0;
            output.AppendFormat("{0:d03}  ", start);

            for (var i = start; i < (start + length); i++)
            {
                output.AppendFormat("{0:x2}", _buffer[i]);
                if (_buffer[i] > 31 && _buffer[i] < 128)
                    dec.Append(Convert.ToChar(_buffer[i]));

                pcnt++;

                if (pcnt == 16)
                {
                    output.Append("    ");
                    output.Append(dec.ToString());
                    output.Append("\n");
                    output.AppendFormat("{0:d03}  ", (i + 1));
                    dec.Remove(0, dec.Length);
                    pcnt = 0;
                }
                else
                    output.Append(" ");
            }

            return output.ToString();
        }

        /// <summary>Clone object</summary>
        /// <returns>Cloned copy of the object cast as <see cref="Object"/></returns>
        public object Clone()
        {
            return new MutableByte(_buffer);
        }

        /// <summary>Reset object data to null</summary>
        public void Reset()
        {
            _buffer = null;
        }

        /// <summary>Reset object data to null</summary>
        public void Clear()
        {
            _buffer = null;
        }

        /// <summary>Compare class to another MutableByte class.</summary>
        /// <param name="other">Class to compare with</param>
        /// <returns>-1 if class is less then, 0 if equal or 1 if greater then class it's compared against</returns>
        public int CompareTo(MutableByte other)
        {
            if (other.Length > Length)
                return -1;

            if (other.Length < Length)
                return 1;

            for (int i = 0; i < Length; i++)
            {
                if (other.Value[i] > Value[i])
                    return -1;

                if (other.Value[i] < Value[i])
                    return 1;
            }
            return 0;
        }

        /// <summary>Compare class to a byte[] array.</summary>
        /// <param name="other">Byte array to compare with</param>
        /// <returns>-1 if class is less then, 0 if equal or 1 if greater then array it's compared against</returns>
        public int CompareTo(byte[] other)
        {
            if (other.Length > Length)
                return -1;

            if (other.Length < Length)
                return 1;

            for (var i = 0; i < Length; i++)
            {
                if (other[i] > Value[i])
                    return -1;

                if (other[i] < Value[i])
                    return 1;
            }

            return 0;
        }
    }
}
