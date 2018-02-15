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

namespace SnmpSharpNet.Security
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using SnmpSharpNet.Exception;

    /// <summary>MD5 Authentication class.</summary>
    public class AuthenticationMD5 : IAuthenticationDigest
    {
        /// <summary>Standard constructor</summary>
        public AuthenticationMD5()
        {
        }

        /// <summary>Authenticate packet and return authentication parameters value to the caller</summary>
        /// <param name="authenticationSecret">User authentication secret</param>
        /// <param name="engineId">SNMP agent authoritative engine id</param>
        /// <param name="wholeMessage">Message to authenticate</param>
        /// <returns>Authentication parameters value</returns>
        public byte[] Authenticate(byte[] authenticationSecret, byte[] engineId, byte[] wholeMessage)
        {
            byte[] authenticationKey = PasswordToKey(authenticationSecret, engineId);

            return Authenticate(authenticationKey, wholeMessage);
        }

        /// <summary>Authenticate packet and return authentication parameters value to the caller</summary>
        /// <param name="authenticationKey">Pre-generated authentication key</param>
        /// <param name="wholeMessage">Message being authenticated</param>
        /// <returns>Authentication parameters value</returns>
        public byte[] Authenticate(byte[] authenticationKey, byte[] wholeMessage)
        {
            byte[] result = new byte[12];

            HMACMD5 md5 = new HMACMD5(authenticationKey);
            byte[] hash = md5.ComputeHash(wholeMessage);

            return hash.Take(12).ToArray();
        }

        /// <summary>
        /// Verifies correct MD5 authentication of the frame. Prior to calling this method, you have to extract authentication
        /// parameters from the wholeMessage and reset authenticationParameters field in the USM information block to 12 0x00
        /// values.
        /// </summary>
        /// <param name="userPassword">User password</param>
        /// <param name="engineId">Authoritative engine id</param>
        /// <param name="authenticationParameters">Extracted USM authentication parameters</param>
        /// <param name="wholeMessage">Whole message with authentication parameters zeroed (0x00) out</param>
        /// <returns>True if message authentication has passed the check, otherwise false</returns>
        public bool AuthenticateIncomingMessage(byte[] userPassword, byte[] engineId, byte[] authenticationParameters, MutableByte wholeMessage)
        {
            byte[] authenticationKey = PasswordToKey(userPassword, engineId);

            HMACMD5 md5 = new HMACMD5(authenticationKey);
            byte[] hash = md5.ComputeHash(wholeMessage, 0, wholeMessage.Length);

            return hash.Take(12).SequenceEqual(authenticationParameters);
        }

        /// <summary>Verify MD5 authentication of a packet.</summary>
        /// <param name="authenticationKey">Authentication key (not password)</param>
        /// <param name="authenticationParameters">Authentication parameters extracted from the packet being authenticated</param>
        /// <param name="wholeMessage">Entire packet being authenticated</param>
        /// <returns>True on authentication success, otherwise false</returns>
        public bool AuthenticateIncomingMsg(byte[] authenticationKey, byte[] authenticationParameters, MutableByte wholeMessage)
        {
            HMACMD5 md5 = new HMACMD5(authenticationKey);
            byte[] hash = md5.ComputeHash(wholeMessage, 0, wholeMessage.Length);

            return hash.Take(12).SequenceEqual(authenticationParameters);
        }

        /// <summary>Convert user password to acceptable authentication key.</summary>
        /// <param name="userPassword">Authentication password</param>
        /// <param name="engineID">Authoritative engine id</param>
        /// <returns>Localized authentication key</returns>
        /// <exception cref="SnmpAuthenticationException">Thrown when key length is less then 8 bytes</exception>
        public byte[] PasswordToKey(byte[] userPassword, byte[] engineID)
        {
            // key length has to be at least 8 bytes long (RFC3414)
            if (userPassword == null || userPassword.Length < 8)
                throw new SnmpAuthenticationException("Secret key is too short.");

            int passwordIndex = 0;

            byte[] sourceBuffer = new byte[1048576];
            byte[] buf = new byte[64];

            for (int count = 0; count < 1048576; count += 64)
            {
                for (int i = 0; i < 64; ++i)
                    buf[i] = userPassword[passwordIndex++ % userPassword.Length];

                Buffer.BlockCopy(buf, 0, sourceBuffer, count, buf.Length);
            }

            byte[] digest = ComputeHash(sourceBuffer);
            byte[] key = ComputeHash(digest.Concat(engineID).Concat(digest).ToArray());

            return key;
        }

        /// <summary>Length of the digest generated by the authentication protocol</summary>
        public int DigestLength
        {
            get { return 16; }
        }

        /// <summary>Return protocol name.</summary>
        public string Name
        {
            get { return "HMAC-MD5"; }
        }

        /// <summary>Compute hash using authentication protocol.</summary>
        /// <param name="data">Data to hash</param>
        /// <param name="offset">Compute hash from the source buffer offset</param>
        /// <param name="count">Compute hash for source data length</param>
        /// <returns>Hash value</returns>
        public byte[] ComputeHash(byte[] data, int offset, int count)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            return md5.ComputeHash(data, offset, count);
        }

        /// <summary>Compute hash using authentication protocol.</summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash value</returns>
        public byte[] ComputeHash(byte[] data)
        {
            return ComputeHash(data, 0, data.Length);
        }
    }
}
