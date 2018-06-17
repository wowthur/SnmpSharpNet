namespace SnmpSharpNet
{
    #pragma warning disable SA1600
    public class Snmp : UdpTransport
    {
        /// <summary>Internal event to send result of the async request to.</summary>
        #pragma warning disable CS0067
        protected event SnmpAsyncResponse OnAsyncResponse;

        /// <summary>Internal storage for request target information.</summary>
        protected ITarget target = null;

        /// <summary>Constructor.</summary>
        public Snmp()
            : base(false)
        {
        }
    }
}
