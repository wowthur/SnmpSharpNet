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

namespace SnmpSharpNet.Exception
{
    /// <summary>SNMP generic exception. Thrown every time SNMP specific error is encountered.</summary>
    [Serializable]
    public class SnmpException : System.Exception
    {
        public enum EErrorCode
        {
            /// <summary>No error</summary>
            None = 0,
            
            /// <summary>Security model specified in the packet is not supported</summary>
            UnsupportedSecurityModel,
            
            /// <summary>Privacy enabled without authentication combination in a packet is not supported.
            UnsupportedNoAuthPriv,
            
            /// <summary>
            /// Invalid length of the authentication parameter field. Expected length is 12 bytes when authentication is
            /// enabled. Same length is used for both MD5 and SHA-1 authentication protocols.
            /// </summary>
            InvalidAuthenticationParameterLength,
            
            /// <summary>Authentication of the received packet failed.</summary>
            AuthenticationFailed,

            /// Privacy protocol requested is not supported.</summary>
            UnsupportedPrivacyProtocol,

            /// <summary>
            /// Invalid length of the privacy parameter field. Expected length depends on the privacy protocol. This exception
            /// can be raised when privacy packet contents are invalidly set by agent or if wrong privacy protocol is set in the
            /// packet class definition.
            /// </summary>
            InvalidPrivacyParameterLength,

            /// <summary>Authoritative engine id is invalid.</summary>
            InvalidAuthoritativeEngineId,

            /// <summary>Engine boots value is invalid</summary>
            InvalidEngineBoots,

            /// <summary>Received packet is outside the time window acceptable. Packet failed timeliness check.</summary>
            PacketOutsideTimeWindow,

            /// <summary>Invalid request id in the packet.</summary>
            InvalidRequestId,

            /// <summary>
            /// SNMP version 3 maximum message size exceeded. Packet that was encoded will exceed maximum message
            /// size acceptable in this transaction.
            /// </summary>
            MaximumMessageSizeExceeded,

            /// <summary>UdpTarget request cannot be processed because IAgentParameters does not contain required information</summary>
            InvalidIAgentParameters,

            /// <summary>Reply to a request was not received within the timeout period</summary>
            RequestTimedOut,

            /// <summary>Null data received on request.</summary>
            NoDataReceived,

            /// <summary>Security name (user name) in the reply does not match the name sent in request.</summary>
            InvalidSecurityName,

            /// <summary>
            /// Report packet was received when Reportable flag was set to false (we notified the peer that we do
            /// not receive report packets).
            /// </summary>
            ReportOnNoReports,

            /// <summary>Oid value type returned by an earlier operation does not match the value type returned by a subsequent entry.</summary>
            OidValueTypeChanged,

            /// <summary>Specified Oid is invalid</summary>
            InvalidOid
        }

        /// <summary>
        /// Error code. Provides a finer grained information about why the exception happened. This can be useful to
        /// the process handling the error to determine how critical the error that occured is and what followup actions
        /// to take.
        /// </summary>
        protected EErrorCode _errorCode;

        /// <summary>Get/Set error code associated with the exception</summary>
        public EErrorCode ErrorCode
        {
            get { return _errorCode; }
            set { _errorCode = value; }
        }

        /// <summary>Constructor.</summary>
        public SnmpException()
            : base()
        {
        }

        /// <summary>Standard constructor</summary>
        /// <param name="message">SNMP Exception message</param>
        public SnmpException(string message)
            : base(message)
        {
        }

        /// <summary>Constructor</summary>
        /// <param name="message">SNMP Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public SnmpException(string message, System.Exception innerException)
            : base(message, innerException)
        {

        }

        /// <summary>Constructor</summary>
        /// <param name="errorCode">Error code associated with the exception</param>
        /// <param name="message">Error message</param>
        public SnmpException(EErrorCode errorCode, string message)
            : base(message)
        {
            _errorCode = errorCode;
        }

        /// <summary>Constructor</summary>
        /// <param name="errorCode">Error code associated with the exception</param>
        /// <param name="message">SNMP Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public SnmpException(EErrorCode errorCode, string message, System.Exception innerException)
            : base(message, innerException)
        {
            _errorCode = errorCode;
        }
    }
}
