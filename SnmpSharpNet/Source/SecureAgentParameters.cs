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
    using SnmpSharpNet.Security;
    using SnmpSharpNet.Types;

    /// <summary>Secure SNMPv3 agent parameters</summary>
    /// <remarks>
    /// SNMP Agent specific values. This class stores values to access SNMP version 3
    /// agents.
    ///
    /// Pass this class with your request data (Pdu) to the request method of the target class to make
    /// a request.
    ///
    /// Based on the information in this class, an appropriate request will be made by the request class.
    ///
    /// Following request types are generated:
    ///
    /// * if EngineBoots and EngineTime are integer value 0 or if EngineId value is length 0, Discovery
    /// request is made and passed instance of the SecureAgentParameters is updated with returned values.
    ///
    /// * in all other cases, SNMP request is made to the agent
    /// </remarks>
    public class SecureAgentParameters : IAgentParameters
    {
        // <summary>Protocol version. Always == SnmpConstants.</summary>
        // protected Integer32 _version;

        /// <summary>Authoritative engine </summary>
        protected OctetString engineId;

        /// <summaryAuthoritative engine boots value</summary>
        protected Integer32 engineBoots;

        /// <summary>Authoritative engine time value</summary>
        protected Integer32 engineTime;

        /// <summary>
        /// Time stamp when authoritative engine time value was last refreshed with data from the agent.
        ///
        /// This value is used to calculate up to date authoritative agent time value without having to
        /// repeat discovery process every 150 seconds.
        /// </summary>
        protected DateTime engineTimeStamp;

        /// <summary>Security name value, or user name.</summary>
        protected OctetString securityName;

        /// <summary>Privacy protocol to use. For available protocols, see <see cref="EPrivacyProtocols"/> enumeration.</summary>
        protected EPrivacyProtocols privacyProtocol;

        /// <summary>
        /// Authentication digest to use in authNoPriv and authPriv security combinations. For available
        /// authentication digests, see <see cref="AuthenticationDigests"/> enumeration.
        /// </summary>
        protected AuthenticationDigests authenticationProtocol;

        /// <summary>Privacy secret (or privacy password)</summary>
        protected MutableByte privacySecret;

        /// <summary>Authentication secret (or authentication password)</summary>
        protected MutableByte authenticationSecret;

        /// <summary>
        /// Context engine id. By default, this value is set to authoritative engine id value unless specifically
        /// set to a different value here.
        /// </summary>
        protected OctetString contextEngineId;

        /// <summary>
        /// Context name. By default this value is a 0 length string (no context name). Set this value if you
        /// require it to be defined in ScopedPdu.
        /// </summary>
        protected OctetString contextName;

        /// <summary>
        /// Maximum message size. This value is by default set to 64KB and then updated by the maximum message
        /// size value in the response from the agent.
        ///
        /// This value should be the smallest message size supported by both the agent and manager.
        /// </summary>
        protected Integer32 maxMessageSize;

        /// <summary>
        /// Reportable option flag. Set to true by default.
        ///
        /// This flag controls if reportable flag will be set in the packet. When this flag is set in the packet,
        /// agent will respond to invalid requests with Report packets. Without this flag being set, all invalid
        /// requests are silently dropped by the agent.
        /// </summary>
        protected bool reportable;

        /// <summary>Cached privacy key</summary>
        protected byte[] privacyKey;

        /// <summary>Cached authentication key</summary>
        protected byte[] authenticationKey;

        /// <summary>Constructor</summary>
        public SecureAgentParameters()
        {
            Reset();
        }

        /// <summary>Copy constructor. Initialize the class with the values of the parameter class values.</summary>
        /// <param name="second">Parameter class.</param>
        public SecureAgentParameters(SecureAgentParameters second)
            : this()
        {
            contextEngineId.Set(second.ContextEngineId);
            contextName.Set(second.ContextName);
            engineBoots.Value = second.EngineBoots.Value;
            engineId.Set(second.EngineId);
            engineTime.Value = second.EngineTime.Value;
            engineTimeStamp = second.EngineTimeStamp();
            maxMessageSize.Value = second.MaxMessageSize.Value;
            privacyProtocol = second.Privacy;
            privacySecret.Set(second.PrivacySecret);
            authenticationProtocol = second.Authentication;
            authenticationSecret.Set(second.AuthenticationSecret);
            reportable = second.Reportable;
            securityName.Set(second.SecurityName);

            if (second.AuthenticationKey != null)
                authenticationKey = (byte[])second.AuthenticationKey.Clone();

            if (second.PrivacyKey != null)
                privacyKey = (byte[])second.PrivacyKey.Clone();
        }

        /// <summary>Agent authoritative engine id</summary>
        public OctetString EngineId
        {
            get { return engineId; }
        }

        /// <summary>SNMP version 3 agent engine boots value</summary>
        public Integer32 EngineBoots
        {
            get { return engineBoots; }
        }

        /// <summary>Get engine time stamp value (last time engine boots and time values were retrieved from the SNMP agent).</summary>
        /// <returns>DateTime stamp of the time timeliness values were last refreshed</returns>
        internal DateTime EngineTimeStamp()
        {
            return engineTimeStamp;
        }

        /// <summary>SNMP version 3 agent engine time value.</summary>
        public Integer32 EngineTime
        {
            get { return engineTime; }
        }

        /// <summary>Security or user name configured on the SNMP version 3 agent.</summary>
        public OctetString SecurityName
        {
            get { return securityName; }
        }

        /// <summary>Privacy protocol used. Acceptable values are members of <see cref="EPrivacyProtocols"/> enum.</summary>
        public EPrivacyProtocols Privacy
        {
            get { return privacyProtocol; }

            set
            {
                if (value != EPrivacyProtocols.None && PrivacyProtocol.GetInstance(value) == null)
                    throw new SnmpPrivacyException("Invalid privacy protocol");

                privacyProtocol = value;
            }
        }

        /// <summary>Privacy secret. Length of the secret is dependent on the selected privacy method.</summary>
        public MutableByte PrivacySecret
        {
            get { return privacySecret; }
        }

        /// <summary>Authentication method. Acceptable values are members of <see cref="AuthenticationDigests"/> enum.</summary>
        public AuthenticationDigests Authentication
        {
            get { return authenticationProtocol; }

            set
            {
                if (value != AuthenticationDigests.None && Security.Authentication.GetInstance(value) == null)
                    throw new SnmpAuthenticationException("Invalid authentication protocol.");

                authenticationProtocol = value;
            }
        }

        /// <summary>Authentication secret. Secret length depends on the hash algorithm selected.</summary>
        public MutableByte AuthenticationSecret
        {
            get { return authenticationSecret; }
        }

        /// <summary>SNMP version. Only acceptable version is <see cref="ESnmpVersion.Ver3"/></summary>
        public ESnmpVersion Version
        {
            get { return ESnmpVersion.Ver3; }
        }

        /// <summary>
        /// Get SNMP version 3 context engine id. By default, this value will be set
        /// to the same engine id as authoritative engine id (EngineId). I haven't see a
        /// scenario where this value needs to be different by a manager but now there
        /// is an option to do it.
        ///
        /// To use the default operation, do not set this value or, if you've already set it,
        /// reset it to null (object.ContextEngineId.Reset()).
        /// </summary>
        public OctetString ContextEngineId
        {
            get { return contextEngineId; }
        }

        /// <summary>Get SNMP version 3 context name</summary>
        public OctetString ContextName
        {
            get { return contextName; }
        }

        /// <summary>Get SNMP version 3 maximum message size object</summary>
        public Integer32 MaxMessageSize
        {
            get { return maxMessageSize; }
        }

        /// <summary>Get/Set reportable flag status in the SNMP version 3 packet.</summary>
        public bool Reportable
        {
            get { return reportable; }
            set { reportable = value; }
        }

        /// <summary>Prepare class for noAuthNoPriv operations. Set authentication and privacy protocols to none.</summary>
        /// <param name="securityName">User security name</param>
        public void NoAuthNoPriv(string securityName)
        {
            this.securityName.Set(securityName);
            authenticationProtocol = AuthenticationDigests.None;
            authenticationSecret.Clear();
            privacyProtocol = EPrivacyProtocols.None;
            privacySecret.Clear();
        }

        /// <summary>Prepare class for authNoPriv operations. Set privacy protocol to none</summary>
        /// <param name="securityName">User security name</param>
        /// <param name="authDigest">Authentication protocol</param>
        /// <param name="authSecret">Authentication secret (password)</param>
        public void AuthNoPriv(string securityName, AuthenticationDigests authDigest, string authSecret)
        {
            this.securityName.Set(securityName);
            authenticationProtocol = authDigest;
            authenticationSecret.Set(authSecret);
            privacyProtocol = EPrivacyProtocols.None;
            privacySecret.Clear();
        }

        /// <summary>Prepare class for authPriv operations.</summary>
        /// <param name="securityName">User security name</param>
        /// <param name="authDigest">Authentication protocol</param>
        /// <param name="authSecret">Authentication secret (password)</param>
        /// <param name="privProtocol">Privacy protocol</param>
        /// <param name="privSecret">Privacy secret (encryption password)</param>
        public void AuthPriv(string securityName, AuthenticationDigests authDigest, string authSecret, EPrivacyProtocols privProtocol, string privSecret)
        {
            this.securityName.Set(securityName);
            authenticationProtocol = authDigest;
            authenticationSecret.Set(authSecret);
            privacyProtocol = privProtocol;
            privacySecret.Set(privSecret);
        }

        /// <summary>Get/Set cached privacy key value</summary>
        /// <remarks>Privacy key is set by reference.</remarks>
        public byte[] PrivacyKey
        {
            get { return privacyKey; }
            set { privacyKey = value; }
        }

        /// <summary>Get/Set cached authentication key value</summary>
        /// <remarks>Authentication key value is set by reference.</remarks>
        public byte[] AuthenticationKey
        {
            get { return authenticationKey; }
            set { authenticationKey = value; }
        }

        /// <summary>Check if cached privacy or authentication keys are available</summary>
        public bool HasCachedKeys
        {
            get
            {
                if (authenticationProtocol != AuthenticationDigests.None)
                {
                    if (authenticationKey != null && authenticationKey.Length > 0)
                    {
                        if (privacyProtocol != EPrivacyProtocols.None)
                        {
                            if (privacyKey != null && privacyKey.Length > 0)
                                return true;
                        }
                        else
                            return true;
                    }

                    return false;
                }

                return false;
            }
        }

        /// <summary>Checks validity of the class.</summary>
        /// <returns>
        /// Returns false if all required values are not initialized, or if invalid
        /// combination of options is set, otherwise true.
        /// </returns>
        public bool Valid()
        {
            if (SecurityName.Length <= 0 && (authenticationProtocol != AuthenticationDigests.None || privacyProtocol != EPrivacyProtocols.None))
            {
                // You have to supply security name when using security or privacy.
                // in theory you can use blank security name during discovery process so this is not exactly prohibited by it is discouraged
                return false;
            }

            if (authenticationProtocol == AuthenticationDigests.None && privacyProtocol != EPrivacyProtocols.None)
                return false; // noAuthPriv mode is not valid in SNMP version 3

            if (authenticationProtocol != AuthenticationDigests.None && authenticationSecret.Length <= 0)
                return false; // Authentication protocol requires authentication secret

            if (privacyProtocol != EPrivacyProtocols.None && privacySecret.Length <= 0)
                return false; // Privacy protocol requires privacy secret

            if (engineTimeStamp != DateTime.MinValue)
            {
                if (!ValidateEngineTime())
                    return false; // engine time is outside the acceptable timeliness window
            }

            // rest of the values can be empty during the discovery process so no point in checking
            return true;
        }

        /// <summary>InitializePacket SNMP packet with values from this class. Works only on SNMP version 3 packets.</summary>
        /// <param name="packet">Instance of <see cref="SnmpV3Packet"/></param>
        /// <exception cref="SnmpInvalidVersionException">Thrown when parameter packet is not SnmpV3Packet</exception>
        public void InitializePacket(SnmpPacket packet)
        {
            if (packet is SnmpV3Packet pkt)
            {
                bool isAuth = (authenticationProtocol == AuthenticationDigests.None) ? false : true;
                bool isPriv = (privacyProtocol == EPrivacyProtocols.None) ? false : true;

                if (isAuth && isPriv)
                    pkt.AuthPriv(securityName, authenticationSecret, authenticationProtocol, privacySecret, privacyProtocol);
                else if (isAuth && !isPriv)
                    pkt.AuthNoPriv(securityName, authenticationSecret, authenticationProtocol);
                else
                    pkt.NoAuthNoPriv(securityName);

                pkt.USM.EngineId.Set(engineId);
                pkt.USM.EngineBoots = engineBoots.Value;
                pkt.USM.EngineTime = GetCurrentEngineTime();
                pkt.MaxMessageSize = maxMessageSize.Value;
                pkt.MessageFlags.Reportable = reportable;

                if (contextEngineId.Length > 0)
                    pkt.ScopedPdu.ContextEngineId.Set(contextEngineId);
                else
                    pkt.ScopedPdu.ContextEngineId.Set(engineId);

                if (contextName.Length > 0)
                    pkt.ScopedPdu.ContextName.Set(contextName);
                else
                    pkt.ScopedPdu.ContextName.Reset();
            }
            else
                throw new SnmpInvalidVersionException("Invalid SNMP version.");
        }

        /// <summary>
        /// Copy all relevant values from the SnmpV3Packet class. Do not use this class for
        /// updating the SNMP version 3 discovery process results because secret name, authentication
        /// and privacy values are updated as well which discovery process doesn't use.
        /// </summary>
        /// <param name="packet"><see cref="SnmpV3Packet"/> cast as <see cref="SnmpPacket"/></param>
        /// <exception cref="SnmpInvalidVersionException">Thrown when SNMP packet class other then version 3 is passed as parameter</exception>
        public void UpdateValues(SnmpPacket packet)
        {
            if (packet is SnmpV3Packet pkt)
            {
                authenticationProtocol = pkt.USM.Authentication;
                privacyProtocol = pkt.USM.Privacy;
                authenticationSecret.Set(pkt.USM.AuthenticationSecret);
                privacySecret.Set(pkt.USM.PrivacySecret);
                securityName.Set(pkt.USM.SecurityName);

                if (pkt.MaxMessageSize < maxMessageSize.Value)
                    maxMessageSize.Value = pkt.MaxMessageSize;

                UpdateDiscoveryValues(pkt);
            }
            else
                throw new SnmpInvalidVersionException("Invalid SNMP version.");
        }

        /// <summary>
        /// Update class values with SNMP version 3 discovery values from the supplied <see cref="SnmpV3Packet"/>
        /// class. Values updated are EngineId, EngineTime and EngineBoots.
        /// </summary>
        /// <param name="packet"><see cref="SnmpV3Packet"/> class cast as <see cref="SnmpPacket"/></param>
        /// <exception cref="SnmpInvalidVersionException">
        /// Thrown when SNMP packet class other then version 3 is passed as parameter
        /// </exception>
        public void UpdateDiscoveryValues(SnmpPacket packet)
        {
            if (packet is SnmpV3Packet pkt)
            {
                engineId.Set(pkt.USM.EngineId);
                engineTime.Value = pkt.USM.EngineTime;
                engineBoots.Value = pkt.USM.EngineBoots;

                UpdateTimeStamp();

                contextEngineId.Set(pkt.ScopedPdu.ContextEngineId);
                contextName.Set(pkt.ScopedPdu.ContextName);
            }
            else
                throw new SnmpInvalidVersionException("Invalid SNMP version.");
        }

        /// <summary>
        /// Updates engine time timestamp. This value is used to determine if agents engine time stored
        /// in this class is valid.
        ///
        /// Timestamp is saved as DateTime class by default initialized to DateTime.MinValue. Timestamp value
        /// is stored in GMT to make it portable (if it is saved on one computer and loaded on another that uses
        /// a different time zone).
        /// </summary>
        public void UpdateTimeStamp()
        {
            engineTimeStamp = DateTime.UtcNow;
        }

        /// <summary>
        /// Validate agents engine time. Valid engine time value is time that has been initialized to
        /// a value other then default (DateTime.MinValue is default set in the constructor) and that
        /// has been updated in the last 10 times the SNMP v3 timely window (150 seconds). In other words,
        /// valid time is any time value in the last 1500 seconds (or 25 minutes).
        /// </summary>
        /// <returns>True if engine time value is valid, otherwise false.</returns>
        public bool ValidateEngineTime()
        {
            if (engineTimeStamp == DateTime.MinValue)
                return false; // timestamp is at its initial value. not valid

            TimeSpan diff = DateTime.UtcNow.Subtract(engineTimeStamp);

            // if EngineTime value has not been updated in 10 * max acceptable period (150 seconds) then
            // time is no longer valid
            if (diff.TotalSeconds >= (150 * 10))
                return false;

            return true;
        }

        /// <summary>
        /// Calculates and returns current agents engine time. <see cref="ValidateEngineTime"/> is called
        /// prior to calculation to make sure current engine time is timely enough to use.
        ///
        /// EngineTime is calculated as last received engine time + difference in seconds between the time
        /// stamp saved when last time value was received and current time (using the internal GMT clock).
        /// </summary>
        /// <returns>Adjusted engine time value or 0 if time is outside the time window.</returns>
        public int GetCurrentEngineTime()
        {
            if (!ValidateEngineTime())
                return 0;

            TimeSpan diff = DateTime.UtcNow.Subtract(engineTimeStamp);

            // increment the value by one to make sure we don't fall behind the agents clock
            return Convert.ToInt32(engineTime.Value + diff.TotalSeconds + 1);
        }

        /// <summary>
        /// Validate that incoming packet has arrived from the correct engine id and is using a correct
        /// combination of privacy and authentication values.
        /// </summary>
        /// <param name="packet">Received and parsed SNMP version 3 packet.</param>
        /// <returns>True if packet is valid, otherwise false.</returns>
        /// <exception cref="SnmpException">Thrown on following errors with ErrorCode:
        /// * ErrorCode = 0: SecureAgentParameters was updated after request was made but before reply was received (this is not allowed)
        /// * SnmpException.InvalidAuthoritativeEngineId: engine id in the reply does not match request
        /// * SnmpException.InvalidSecurityName: security name mismatch between request and reply packets
        /// * SnmpException.ReportOnNoReports: report packet received when we had reportable set to false in the request
        /// * SnmpException.UnsupportedNoAuthPriv: noAuthPriv is not supported
        /// </exception>
        /// <exception cref="SnmpPrivacyException">Thrown when configured privacy passwords in this class and in the packet class do not match</exception>
        /// <exception cref="SnmpAuthenticationException">Thrown when configured authentication passwords in this class and in the packet class do not match</exception>
        public bool ValidateIncomingPacket(SnmpV3Packet packet)
        {
            // First check if this is a report packet.
            if (packet.Pdu.Type == EPduType.Report)
            {
                if (!reportable)
                {
                    // we do not expect report packets so dump it
                    throw new SnmpException(SnmpException.EErrorCode.ReportOnNoReports, "Unexpected report packet received.");
                }

                if (packet.MessageFlags.Authentication == false && packet.MessageFlags.Privacy)
                {
                    // no authentication and no privacy allowed in report packets
                    throw new SnmpException(SnmpException.EErrorCode.UnsupportedNoAuthPriv, "Authentication and privacy combination is not supported.");
                }

                // the rest will not be checked, there is no point
            }
            else
            {
                if (packet.USM.EngineId != engineId)
                {
                    // different engine id is not allowed
                    throw new SnmpException(SnmpException.EErrorCode.InvalidAuthoritativeEngineId, "EngineId mismatch.");
                }

                if (packet.USM.Authentication != authenticationProtocol || packet.USM.Privacy != privacyProtocol)
                {
                    // we have to have the same authentication and privacy protocol - no last minute changes
                    throw new SnmpException("Agent parameters updated after request was made.");
                }

                if (packet.USM.Authentication != AuthenticationDigests.None)
                {
                    if (packet.USM.AuthenticationSecret != authenticationSecret)
                    {
                        // authentication secret has to match
                        throw new SnmpAuthenticationException("Authentication secret in the packet class does not match the IAgentParameter secret.");
                    }
                }

                if (packet.USM.Privacy != EPrivacyProtocols.None)
                {
                    if (packet.USM.PrivacySecret != privacySecret)
                    {
                        // privacy secret has to match
                        throw new SnmpPrivacyException("Privacy secret in the packet class does not match the IAgentParameters secret.");
                    }
                }

                if (packet.USM.SecurityName != securityName)
                    throw new SnmpException(SnmpException.EErrorCode.InvalidSecurityName, "Security name mismatch.");
            }

            return true;
        }

        /// <summary>Reset privacy and authentication keys to null.</summary>
        public void ResetKeys()
        {
            privacyKey = null;
            authenticationKey = null;
        }

        /// <summary>Reset the class. Initialize all member values to class defaults.</summary>
        public void Reset()
        {
            engineId = new OctetString();
            engineBoots = new Integer32();
            engineTime = new Integer32();

            engineTimeStamp = DateTime.MinValue;

            privacyProtocol = EPrivacyProtocols.None;
            authenticationProtocol = AuthenticationDigests.None;

            privacySecret = new MutableByte();
            authenticationSecret = new MutableByte();

            contextEngineId = new OctetString();
            contextName = new OctetString();
            securityName = new OctetString();

            // max message size is initialized to 64KB by default. It will be
            // to the smaller of the two values after discovery process
            maxMessageSize = new Integer32(64 * 1024);

            reportable = true;

            privacyKey = null;
            authenticationKey = null;
        }

        /// <summary>Clone current object</summary>
        /// <returns>Duplicate object initialized with values from this class.</returns>
        public object Clone()
        {
            return new SecureAgentParameters(this);
        }

        /// <summary>Build cached authentication and privacy encryption keys if they are appropriate for the selected security mode.</summary>
        /// <remarks>
        /// This method should be called after discovery process has been completed and all security related values
        /// have been set. For noAuthNoPriv, none of the keys are generated. authNoPriv will result in authentication
        /// key cached. authPriv will generate authentication and privacy keys.
        ///
        /// For successful key caching you need to set both relevant protocols and secret values.
        /// </remarks>
        public void BuildCachedSecurityKeys()
        {
            authenticationKey = privacyKey = null;

            if (engineId == null || engineId.Length <= 0)
                return;

            if (authenticationSecret == null || authenticationSecret.Length <= 0)
                return;

            if (authenticationProtocol != AuthenticationDigests.None)
            {
                IAuthenticationDigest authProto = Security.Authentication.GetInstance(authenticationProtocol);
                if (authProto != null)
                {
                    authenticationKey = authProto.PasswordToKey(authenticationSecret, engineId);
                    if (privacyProtocol != EPrivacyProtocols.None && privacySecret != null && privacySecret.Length > 0)
                    {
                        IPrivacyProtocol privProto = PrivacyProtocol.GetInstance(privacyProtocol);
                        if (privProto != null)
                            privacyKey = privProto.PasswordToKey(privacySecret, engineId, authProto);
                    }
                }
            }
        }
    }
}
