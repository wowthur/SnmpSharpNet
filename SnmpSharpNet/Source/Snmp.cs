namespace SnmpSharpNet
{
    public class Snmp : UdpTransport
    {
        /// <summary>Internal event to send result of the async request to.</summary>
        protected event SnmpAsyncResponse _response;

        /// <summary>Internal storage for request target information.</summary>
        protected ITarget _target = null;

        #region Constructor(s)

        /// <summary>Constructor</summary>
        public Snmp() : base(false)
        {
        }

        #endregion Constructor(s)
    }
}
