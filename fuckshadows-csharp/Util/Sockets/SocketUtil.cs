using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Util.Sockets.Buffer;

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

        /// <summary>
        /// Full receive from <see cref="Socket"/> until no data available 
        /// or reaches <see cref="intendedRecvSize"/>
        /// This method relies on <see cref="Socket.Available"/>, internally
        /// it's calling the native method ioctlsocket with the command FIONREAD
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// Null <see cref="Socket"/>
        /// </exception>
        public static async Task<int> FullReceiveTaskAsync(this Socket socket,
            ArraySegment<byte> buf, int intendedRecvSize, SocketFlags flags = SocketFlags.None)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            int bytesReceived = 0;
            int bytesTransffered = 0;
            ArraySegment<byte> tmp = buf.Take(intendedRecvSize);

            while (true)
            {
                bytesTransffered = await socket.ReceiveAsync(tmp, flags);
                if (bytesTransffered <= 0) break;
                Interlocked.Add(ref bytesReceived, bytesTransffered);
                if (socket.Available <= 0) break;
                tmp = tmp.Skip(bytesTransffered);
            }

            return bytesReceived;
        }

        public static async Task<int> FullSendTaskAsync(this Socket socket,
            ArraySegment<byte> buf, int intendedSendSize, SocketFlags flags = SocketFlags.None)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            int bytesSent = 0;
            int bytesTransffered = 0;
            ArraySegment<byte> tmp = buf.Take(intendedSendSize);
            while (true)
            {
                bytesTransffered = await socket.SendAsync(tmp, flags);
                if (bytesTransffered <= 0) break;
                Interlocked.Add(ref bytesSent, bytesTransffered);
                if (bytesSent >= intendedSendSize) break;
                tmp = tmp.Skip(bytesTransffered);
            }

            return bytesSent;
        }

        // value type: small enough and reduce pressure on managed heap and GC
        //             Don't need to copy any instance of this type, thus no field-by-field copy would occur
        public struct TcpTrafficToken
        {
            public readonly int BytesTotal;
            public byte[] PayloadBytes;

            public TcpTrafficToken(int bytesTotal, byte[] payload)
            {
                this.BytesTotal = bytesTotal;
                this.PayloadBytes = payload;
            }
        }
    }

    public static class TplExtensions
    {
        public static void Forget(this Task task) { }
    }
}
