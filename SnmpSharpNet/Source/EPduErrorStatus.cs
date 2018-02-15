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

namespace SnmpSharpNet
{
    /// <summary>Pdu and ScopedPdu error status value enumeration</summary>
    /// <remarks>Thanks to Pavel_Tatarinov@selinc.com</remarks>
    public enum EPduErrorStatus
    {
        /// <summary>No error</summary>
        NoError = 0,

        /// <summary>request or reply is too big</summary>
        TooBig = 1,

        /// <summary>requested name doesn't exist</summary>
        NoSuchName = 2,

        /// <summary>bad value supplied</summary>
        BadValue = 3,

        /// <summary>Oid is read only</summary>
        ReadOnly = 4,

        /// <summary>general error</summary>
        GenErr = 5,

        /// <summary>access denied</summary>
        NoAccess = 6,

        /// <summary>wrong type</summary>
        WrongType = 7,

        /// <summary>wrong length</summary>
        WrongLength = 8,

        /// <summary>wrong encoding</summary>
        WrongEncoding = 9,

        /// <summary>wrong value</summary>
        WrongValue = 10,

        /// <summary>no creation</summary>
        NoCreation = 11,

        /// <summary>inconsistent value</summary>
        InconsistentValue = 12,

        /// <summary>resource is not available</summary>
        ResourceUnavailable = 13,

        /// <summary>commit failed</summary>
        CommitFailed = 14,

        /// <summary>undo failed</summary>
        UndoFailed = 15,

        /// <summary>authorization error</summary>
        AuthorizationError = 16,

        /// <summary>not writable</summary>
        NotWritable = 17,

        /// <summary>inconsistent name</summary>
        InconsistentName = 18,
    }
}
