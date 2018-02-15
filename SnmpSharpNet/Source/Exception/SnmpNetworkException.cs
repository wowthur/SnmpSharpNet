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
    /// <summary>SNMP network exception</summary>
    /// <remarks>
    /// Exception thrown when network error was encountered. Network errors include host, network unreachable, connection refused, etc.
    ///
    /// One network exception that is not covered by this exception is request timeout.
    /// </remarks>
    public class SnmpNetworkException :
        SnmpException
    {
        /// <summary>Standard constructor</summary>
        /// <param name="systemException">System exception that caused the error</param>
        /// <param name="message">Error message</param>
        public SnmpNetworkException(System.Exception systemException, string message)
            : base(message, systemException)
        {
        }

        /// <summary>
        /// Constructor. Used when system exception did not cause the error and there is no parent
        /// exception associated with the error.
        /// </summary>
        /// <param name="msg">Error message</param>
        public SnmpNetworkException(string msg)
            : base(msg)
        {
        }
    }
}
