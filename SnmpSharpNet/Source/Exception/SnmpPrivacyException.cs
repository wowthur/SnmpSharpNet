﻿// This file is part of SNMP#NET.
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

namespace SnmpSharpNet.Exception
{
    /// <summary>Privacy encryption or decryption exception</summary>
    /// <remarks>
    /// Exception thrown when errors were encountered related to the privacy protocol encryption and decryption operations.
    ///
    /// Use ParentException field to get the causing error details.
    /// </remarks>
    public class SnmpPrivacyException : SnmpException
    {
        /// <summary>Standard constructor initializes the exceptione error message</summary>
        /// <param name="message">Error message</param>
        public SnmpPrivacyException(string message)
            : base(message)
        {
        }

        /// <summary>Constructor initializes error message and parent exception</summary>
        /// <param name="ex">Parent exception</param>
        /// <param name="message">Error message</param>
        public SnmpPrivacyException(System.Exception ex, string message)
            : base(message, ex)
        {
        }
    }
}
