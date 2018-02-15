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
    using System.Net;
    using System.Threading;

    /// <summary>Internal class holding relevant information for async requests.</summary>
    internal class AsyncRequestState
    {
        /// <summary>Peer end point</summary>
        public IPEndPoint EndPoint { get; set; }

        /// <summary>Get/Set packet buffer</summary>
        public byte[] Packet { get; set; }

        /// <summary>Get/Set packet length value</summary>
        public int PacketLength { get; set; }

        /// <summary>Maximum number of retries (0 = single request, no retries)</summary>
        public int MaxRetries { get; set; }

        /// <summary>Request timeout in milliseconds</summary>
        public int Timeout { get; set; }

        /// <summary>Get/Set timer class</summary>
        public Timer Timer { get; set; }

        /// <summary>Current retry count. Value represents the number of retries that have been sent excluding the original request.</summary>
        public int CurrentRetry { get; set; }

        /// <summary>Constructor.</summary>
        /// <param name="peerIP">Peer IP address</param>
        /// <param name="peerPort">Peer UDP port number</param>
        /// <param name="maxretries">Maximum number of retries</param>
        /// <param name="timeout">Timeout value in milliseconds</param>
        public AsyncRequestState(IPAddress peerIP, int peerPort, int maxretries, int timeout)
        {
            EndPoint = new IPEndPoint(peerIP, peerPort);
            MaxRetries = maxretries;
            Timeout = timeout;

            // current retry value is set to -1 because we do not count the first request as a retry.
            CurrentRetry = -1;
            Timer = null;
        }
    }
}
