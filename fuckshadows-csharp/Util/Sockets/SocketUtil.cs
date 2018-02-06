using System;
using System.Net;
using System.Net.Sockets;
using Fuckshadows.Controller;

namespace Fuckshadows.Util.Sockets
{
    public static class SocketUtil
    {
        private class DnsEndPoint2 : DnsEndPoint
        {
            public DnsEndPoint2(string host, int port) : base(host, port)
            {
            }

            public DnsEndPoint2(string host, int port, AddressFamily addressFamily) : base(host, port, addressFamily)
            {
            }

            public override string ToString()
            {
                return this.Host + ":" + this.Port;
            }
        }

        public static EndPoint GetEndPoint(string host, int port)
        {
            IPAddress ipAddress;
            bool parsed = IPAddress.TryParse(host, out ipAddress);
            if (parsed)
            {
                return new IPEndPoint(ipAddress, port);
            }

            // maybe is a domain name
            // https://blogs.msdn.microsoft.com/webdev/2013/01/08/dual-mode-sockets-never-create-an-ipv4-socket-again/
            return new DnsEndPoint2(host, port, AddressFamily.Unspecified);
        }


        public static void SetTFO(this Socket s)
        {
            if (!Program.TFOSupported) return;
            try
            {
                s.SetSocketOption(SocketOptionLevel.Tcp, (SocketOptionName)15, true);
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }
        }

    }
}
