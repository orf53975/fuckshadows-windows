using System.Net;
using System.Net.Sockets;

namespace Fuckshadows.Controller
{
    public class ServiceUserToken
    {
        /// <summary>
        /// Accepted socket from <see cref="Listener"/>
        /// </summary>
        public Socket socket;

        public byte[] firstPacket;

        public int firstPacketLength;

        /* for UDP only */
        public EndPoint remoteEndPoint;
    }
}