using System;
using System.Runtime.Serialization;

namespace Fuckshadows.Util.SystemProxy
{
    class ProxyException : Exception
    {
        public ProxyException()
        {
        }

        public ProxyException(string message) : base(message)
        {
        }

        public ProxyException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected ProxyException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
