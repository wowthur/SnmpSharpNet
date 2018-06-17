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
    using SnmpSharpNet.Exception;
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading.Tasks;

    /// <summary>Async delegate called on completion of Async SNMP request</summary>
    /// <param name="status">SNMP request status. If status is NoError then pdu will contain valid information</param>
    /// <param name="peer">Peer IP and port number. This value is only valid if status is NoError</param>
    /// <param name="buffer">Returned data. This value is only valid if status is NoError</param>
    /// <param name="length">Length of the returned data. This value is only valid if status is NoError.</param>
    internal delegate void SnmpAsyncCallback(EAsyncRequestResult status, IPEndPoint peer, byte[] buffer, int length);

    /// <summary>IP/UDP transport class.</summary>
    public class UdpTransport : IDisposable
    {
        /// <summary>Socket</summary>
        protected Socket socket;

        /// <summary>Flag used to determine if class is using IP version 6 (true) or IP version 4 (false)</summary>
        public bool IsIPv6 { get; set; }

        /// <summary>
        /// Internal variable used to disable host IP address/port number check on received SNMP reply packets. If this option is disabled (default)
        /// only replies from the IP address/port number combination to which the request was sent will be accepted as valid packets.
        ///
        /// This value is set in the AgentParameters class and is only valid for SNMP v1 and v2c requests.
        /// </summary>
        protected bool noSourceCheck;

        /// <summary>Constructor. Initializes and binds the Socket class</summary>
        /// <param name="useV6">Set to true if you wish to initialize the transport for IPv6</param>
        public UdpTransport(bool useV6)
        {
            IsIPv6 = useV6;
            socket = null;
            InitializeSocket(IsIPv6);
        }

        /// <summary>Destructor</summary>
        ~UdpTransport()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
            }
        }

        /// <summary>Initialize class socket</summary>
        /// <param name="useV6">Should socket be initialized for IPv6 (true) of IPv4 (false)</param>
        protected void InitializeSocket(bool useV6)
        {
            if (socket != null)
                Close();

            if (useV6)
                socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            else
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            IPEndPoint ipEndPoint = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            EndPoint ep = ipEndPoint;
            socket.Bind(ep);
        }

        /// <summary>Make sync request using IP/UDP with request timeouts and retries.</summary>
        /// <param name="peer">SNMP agent IP address</param>
        /// <param name="port">SNMP agent port number</param>
        /// <param name="buffer">Data to send to the agent</param>
        /// <param name="bufferLength">Data length in the buffer</param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <param name="retries">Maximum number of retries. 0 = make a single request with no retry attempts</param>
        /// <returns>Byte array returned by the agent. Null on error</returns>
        /// <exception cref="SnmpException">Thrown on request timed out. SnmpException.ErrorCode is set to
        /// SnmpException.RequestTimedOut constant.</exception>
        /// <exception cref="SnmpException">Thrown when IPv4 address is passed to the v6 socket or vice versa</exception>
        public byte[] Request(IPAddress peer, int port, byte[] buffer, int bufferLength, int timeout, int retries)
        {
            if (socket == null)
                return null; // socket has been closed. no new operations are possible.

            if (socket.AddressFamily != peer.AddressFamily)
                throw new SnmpException("Invalid address protocol version.");

            IPEndPoint netPeer = new IPEndPoint(peer, port);

            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, timeout);

            int recv = 0;
            int retry = 0;
            byte[] inbuffer = new byte[64 * 1024];

            EndPoint remote = new IPEndPoint(peer.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            while (true)
            {
                try
                {
                    socket.SendTo(buffer, bufferLength, SocketFlags.None, netPeer);
                    recv = socket.ReceiveFrom(inbuffer, ref remote);
                }
                catch (SocketException ex)
                {
                    switch ((SocketError)ex.ErrorCode)
                    {
                        case SocketError.MessageSize:
                            recv = 0; // Packet too large
                            break;
                        case SocketError.NetworkDown:
                            throw new SnmpNetworkException(ex, "Network error: Destination network is down.");
                        case SocketError.NetworkUnreachable:
                            throw new SnmpNetworkException(ex, "Network error: destination network is unreachable.");
                        case SocketError.ConnectionReset:
                            throw new SnmpNetworkException(ex, "Network error: connection reset by peer.");
                        case SocketError.HostDown:
                            throw new SnmpNetworkException(ex, "Network error: remote host is down.");
                        case SocketError.HostUnreachable:
                            throw new SnmpNetworkException(ex, "Network error: remote host is unreachable.");
                        case SocketError.ConnectionRefused:
                            throw new SnmpNetworkException(ex, "Network error: connection refused.");
                        case SocketError.TimedOut:
                            recv = 0; // Connection attempt timed out. Fall through to retry
                            break;
                        default:
                            // Assume it is a timeout
                            break;
                    }
                }

                if (recv > 0)
                {
                    IPEndPoint remEP = remote as IPEndPoint;
                    if (!noSourceCheck && !remEP.Equals(netPeer))
                    {
                        if (remEP.Address != netPeer.Address)
                            Console.WriteLine("Address miss-match {0} != {1}", remEP.Address, netPeer.Address);

                        if (remEP.Port != netPeer.Port)
                            Console.WriteLine("Port # miss-match {0} != {1}", remEP.Port, netPeer.Port);

                        /* Not good, we got a response from somebody other then who we requested a response from */
                        retry++;
                        if (retry > retries)
                            throw new SnmpException(SnmpException.EErrorCode.RequestTimedOut, "Request has reached maximum retries.");
                    }
                    else
                    {
                        MutableByte buf = new MutableByte(inbuffer, recv);
                        return buf;
                    }
                }
                else
                {
                    retry++;
                    if (retry > retries)
                        throw new SnmpException(SnmpException.EErrorCode.RequestTimedOut, "Request has reached maximum retries.");
                }
            }
        }

        /// <summary>Make sync request using IP/UDP with request timeouts and retries.</summary>
        /// <param name="peer">SNMP agent IP address</param>
        /// <param name="port">SNMP agent port number</param>
        /// <param name="buffer">Data to send to the agent</param>
        /// <param name="bufferLength">Data length in the buffer</param>
        /// <param name="timeout">Timeout in milliseconds</param>
        /// <param name="retries">Maximum number of retries. 0 = make a single request with no retry attempts</param>
        /// <returns>Byte array returned by the agent. Null on error</returns>
        /// <exception cref="SnmpException">Thrown on request timed out. SnmpException.ErrorCode is set to
        /// SnmpException.RequestTimedOut constant.</exception>
        /// <exception cref="SnmpException">Thrown when IPv4 address is passed to the v6 socket or vice versa</exception>
        public async Task<byte[]> RequestAsync(IPAddress peer, int port, byte[] buffer, int bufferLength, int timeout, int retries)
        {
            if (socket == null)
                return null; // socket has been closed. no new operations are possible.

            if (socket.AddressFamily != peer.AddressFamily)
                throw new SnmpException("Invalid address protocol version.");

            IPEndPoint netPeer = new IPEndPoint(peer, port);

            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, timeout);

            int recv = 0;
            int retry = 0;
            byte[] inbuffer = new byte[64 * 1024];

            EndPoint remote = new IPEndPoint(peer.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            while (true)
            {
                try
                {
                    await Task.Factory.FromAsync(
                        socket.BeginSendTo(buffer, 0, bufferLength, SocketFlags.None, netPeer, null, null),
                        end =>
                        {
                            socket.EndSendTo(end);
                        }
                    )
                    .ConfigureAwait(false);

                    await Task.Factory.FromAsync(
                        socket.BeginReceiveFrom(inbuffer, 0, inbuffer.Length, SocketFlags.None, ref remote, null, null),
                        end =>
                        {
                            recv = socket.EndReceiveFrom(end, ref remote);
                        }
                    );
                }
                catch (SocketException ex)
                {
                    switch ((SocketError)ex.ErrorCode)
                    {
                        case SocketError.MessageSize:
                            recv = 0; // Packet too large
                            break;
                        case SocketError.NetworkDown:
                            throw new SnmpNetworkException(ex, "Network error: Destination network is down.");
                        case SocketError.NetworkUnreachable:
                            throw new SnmpNetworkException(ex, "Network error: destination network is unreachable.");
                        case SocketError.ConnectionReset:
                            throw new SnmpNetworkException(ex, "Network error: connection reset by peer.");
                        case SocketError.HostDown:
                            throw new SnmpNetworkException(ex, "Network error: remote host is down.");
                        case SocketError.HostUnreachable:
                            throw new SnmpNetworkException(ex, "Network error: remote host is unreachable.");
                        case SocketError.ConnectionRefused:
                            throw new SnmpNetworkException(ex, "Network error: connection refused.");
                        case SocketError.TimedOut:
                            recv = 0; // Connection attempt timed out. Fall through to retry
                            break;
                        default:
                            // Assume it is a timeout
                            break;
                    }
                }

                if (recv > 0)
                {
                    IPEndPoint remEP = remote as IPEndPoint;
                    if (!noSourceCheck && !remEP.Equals(netPeer))
                    {
                        if (remEP.Address != netPeer.Address)
                            Console.WriteLine("Address miss-match {0} != {1}", remEP.Address, netPeer.Address);

                        if (remEP.Port != netPeer.Port)
                            Console.WriteLine("Port # miss-match {0} != {1}", remEP.Port, netPeer.Port);

                        /* Not good, we got a response from somebody other then who we requested a response from */
                        retry++;
                        if (retry > retries)
                            throw new SnmpException(SnmpException.EErrorCode.RequestTimedOut, "Request has reached maximum retries.");
                    }
                    else
                    {
                        MutableByte buf = new MutableByte(inbuffer, recv);
                        return buf;
                    }
                }
                else
                {
                    retry++;
                    if (retry > retries)
                        throw new SnmpException(SnmpException.EErrorCode.RequestTimedOut, "Request has reached maximum retries.");
                }
            }
        }

        /// <summary>Dispose of the class.</summary>
        public void Dispose()
        {
            Close();
        }

        /// <summary>Close network socket</summary>
        public void Close()
        {
            if (socket != null)
            {
                try
                {
                    socket.Close();
                }
                catch
                {
                }

                socket = null;
            }
        }
    }
}
