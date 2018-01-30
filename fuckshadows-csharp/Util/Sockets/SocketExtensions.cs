using System;
using System.Net.Sockets;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace Fuckshadows.Util.Sockets
{
    public static class SocketExtensions
    {
        private static readonly Func<Socket, SaeaAwaitable, bool> ACCEPT = (s, a) => s.AcceptAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> CONNECT = (s, a) => s.ConnectAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> DISCONNECT = (s, a) => s.DisconnectAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> RECEIVE = (s, a) => s.ReceiveAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> SEND = (s, a) => s.SendAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> SENDTO = (s, a) => s.SendToAsync(a.Saea);
        private static readonly Func<Socket, SaeaAwaitable, bool> RECEIVEFROM = (s, a) => s.ReceiveFromAsync(a.Saea);

        public static SaeaAwaitable AcceptAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, ACCEPT);
        }

        public static SaeaAwaitable ConnectAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, CONNECT);
        }

        public static SaeaAwaitable DisconnectAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, DISCONNECT);
        }

        public static SaeaAwaitable ReceiveAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, RECEIVE);
        }

        public static SaeaAwaitable ReceiveFromAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, RECEIVEFROM);
        }

        public static SaeaAwaitable SendAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, SEND);
        }

        public static SaeaAwaitable SendToAsync(this Socket socket, SaeaAwaitable awaitable)
        {
            return OperateAsync(socket, awaitable, SENDTO);
        }

        /// <summary>
        ///     Calls the specified asynchronous method of a <see cref="Socket" /> and returns an
        ///     awaitable object that provides the operation result when awaited.
        /// </summary>
        /// <param name="socket">
        ///     <see cref="Socket" /> to run an asynchronous operation.
        /// </param>
        /// <param name="awaitable">
        ///     The <see cref="SaeaAwaitable" /> object to use for this asynchronous socket
        ///     operation.
        /// </param>
        /// <param name="operation">
        ///     Socket operation to perform.
        /// </param>
        /// <returns>
        ///     A <see cref="SaeaAwaitable" /> which, when awaited, returns a
        ///     <see cref="SocketError" /> object that corresponds to the result of
        ///     <paramref name="operation" />.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        ///     <paramref name="socket" /> or <paramref name="awaitable" /> is null.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     A socket operation was already in progress using <paramref name="awaitable"/>.
        ///     -or-
        ///     For accept operations:
        ///     <paramref name="socket" /> is not bound, is not listening for connections, or is
        ///     already connected.
        ///     -or-
        ///     For connect operations:
        ///     <paramref name="socket" /> is listening.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     Windows XP or later is required for this method.
        ///     -or-
        ///     For connect operations:
        ///     Address family of <see cref="Socket.LocalEndPoint" /> is different than the address
        ///     family of <see cref="SocketAsyncEventArgs.RemoteEndPoint" />.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     <paramref name="socket" /> has been disposed.
        /// </exception>
        /// <exception cref="SecurityException">
        ///     For connection operations:
        ///     A caller higher in the call stack does not have permission for the requested
        ///     operation.
        /// </exception>
        private static SaeaAwaitable OperateAsync(Socket socket, SaeaAwaitable awaitable, Func<Socket, SaeaAwaitable, bool> operation)
        {
            if (socket == null)
                throw new ArgumentNullException(nameof(socket));

            if (awaitable == null)
                throw new ArgumentNullException(nameof(awaitable));

            var awaiter = awaitable.GetAwaiter();

            lock (awaiter.SyncRoot)
            {
                if (!awaiter.IsCompleted)
                    throw new InvalidOperationException(
                        "A socket operation is already in progress using the same await-able SAEA.");

                awaiter.Reset();
            }

            try
            {
                if (!operation.Invoke(socket, awaitable))
                    awaiter.Complete();
            }
            catch (SocketException ex)
            {
                awaiter.Complete();
                awaitable.Saea.SocketError =
                    ex.SocketErrorCode != SocketError.Success ? ex.SocketErrorCode : SocketError.SocketError;
            }
            catch (Exception)
            {
                awaiter.Complete();
                awaitable.Saea.SocketError = SocketError.Success;
                throw;
            }

            return awaitable;
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
        public static async Task<TcpTrafficToken> FullReceiveTaskAsync(this Socket socket, SaeaAwaitable awaitable, int intendedRecvSize)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (awaitable == null) throw new ArgumentNullException(nameof(awaitable));
            int bytesReceived = 0;
            SocketError err;
            awaitable.Saea.SetBuffer(0, intendedRecvSize);
            while (true) {
                err = await socket.ReceiveAsync(awaitable);
                if (err != SocketError.Success) break;
                if (awaitable.Saea.BytesTransferred <= 0) break;
                Interlocked.Add(ref bytesReceived, awaitable.Saea.BytesTransferred);
                if (socket.Available <= 0) break;
                if (bytesReceived >= intendedRecvSize) break;
                awaitable.Saea.SetBuffer(awaitable.Saea.Offset + awaitable.Saea.BytesTransferred,
                                         awaitable.Saea.Count - awaitable.Saea.BytesTransferred);
            }
            return new TcpTrafficToken(err, bytesReceived);
        }

        /// <summary>
        /// Similar to <see cref="FullReceiveTaskAsync"/>, while performing receive operation once
        /// </summary>
        /// <param name="socket"></param>
        /// <param name="awaitable"></param>
        /// <param name="intendedRecvSize"></param>
        /// <returns></returns>
        public static async Task<TcpTrafficToken> ReceiveTaskAsync(this Socket socket, SaeaAwaitable awaitable, int intendedRecvSize)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (awaitable == null) throw new ArgumentNullException(nameof(awaitable));
            awaitable.Saea.SetBuffer(0, intendedRecvSize);
            var err = await socket.ReceiveAsync(awaitable);
            return new TcpTrafficToken(err, awaitable.Saea.BytesTransferred);
        }

        public static async Task<TcpTrafficToken> FullSendTaskAsync(this Socket socket, SaeaAwaitable awaitable, int intendedSendSize)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (awaitable == null) throw new ArgumentNullException(nameof(awaitable));
            int bytesSent = 0;
            SocketError err;
            awaitable.Saea.SetBuffer(0, intendedSendSize);
            while (true)
            {
                err = await socket.SendAsync(awaitable);
                if (err != SocketError.Success) break;
                if (awaitable.Saea.BytesTransferred <= 0) break;
                Interlocked.Add(ref bytesSent, awaitable.Saea.BytesTransferred);
                if (bytesSent >= intendedSendSize) break;
                awaitable.Saea.SetBuffer(awaitable.Saea.Offset + awaitable.Saea.BytesTransferred,
                                         awaitable.Saea.Count - awaitable.Saea.BytesTransferred);
            }
            return new TcpTrafficToken(err, bytesSent);
        }

        // value type: small enough and reduce pressure on managed heap and GC
        //             Don't need to copy any instance of this type, thus no field-by-field copy would occur
        public struct TcpTrafficToken
        {
            public readonly SocketError SocketError;
            public readonly int BytesTotalTransferred;

            public TcpTrafficToken(SocketError err, int bytesTotalTransferred)
            {
                this.SocketError = err;
                this.BytesTotalTransferred = bytesTotalTransferred;
            }
        }

        /// <summary>
        /// Setup <see cref="SocketAsyncEventArgs.Buffer"/> in <see cref="SaeaAwaitable"/>
        /// </summary>
        /// <param name="awaitable"></param>
        /// <param name="buf">src buffer</param>
        /// <param name="bufLen">src buffer length</param>
        public static void PrepareSAEABuffer(this SaeaAwaitable awaitable, byte[] buf, int bufLen)
        {
            if (awaitable == null) throw new ArgumentNullException(nameof(awaitable));
            if (buf == null) throw new ArgumentNullException(nameof(buf));
            if (bufLen <= 0) throw new ArgumentOutOfRangeException(nameof(bufLen));

            var saea = awaitable.Saea;
            if (saea == null) throw new NullReferenceException();
            Buffer.BlockCopy(buf, 0, saea.Buffer, 0, bufLen);
            saea.SetBuffer(0, bufLen);
        }
    }
}
