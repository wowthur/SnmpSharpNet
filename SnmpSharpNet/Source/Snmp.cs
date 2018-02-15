namespace SnmpSharpNet
{
    public class Snmp : UdpTransport
    {
        /// <summary>Internal event to send result of the async request to.</summary>
        protected event SnmpAsyncResponse OnAsyncResponse;

        /// <summary>Internal storage for request target information.</summary>
        protected ITarget target = null;

        /// <summary>Constructor</summary>
        public Snmp()
            : base(false)
        {
        }
    }
}
