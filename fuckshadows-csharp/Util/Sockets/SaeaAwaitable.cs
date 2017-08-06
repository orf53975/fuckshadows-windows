using System;
using System.Net.Sockets;

namespace Fuckshadows.Util.Sockets
{
    public sealed class SaeaAwaitable : IDisposable
    {
        private const int MAGIC = -256;

        /// <summary>
        ///     An awaiter that waits the completions of asynchronous socket operations.
        /// </summary>
        private readonly SaeaAwaiter _awaiter;

        private int _initBufferSize = MAGIC;

        /// <summary>
        ///     A value indicating whether the <see cref="SaeaAwaitable" /> is disposed.
        /// </summary>
        public bool IsDisposed { get; private set; }

        public SocketAsyncEventArgs Saea { get; } = new SocketAsyncEventArgs();

        public object SyncRoot { get; } = new object();

        public SaeaAwaitable()
        {
            _awaiter = new SaeaAwaiter(this);
        }

        /// <summary>
        ///     Gets the awaitable object to await a socket operation.
        /// </summary>
        /// <returns>
        ///     A <see cref="SaeaAwaiter" /> used to await this <see cref="SaeaAwaitable" />.
        /// </returns>
        public SaeaAwaiter GetAwaiter()
        {
            return _awaiter;
        }

        /// <summary>
        ///     Sets the initial buffer size to restore buffer size before returning to the pool.
        /// </summary>
        public void SetInitBufferSize(int size)
        {
            this._initBufferSize = size;
        }

        /// <summary>
        ///     Clear properties to prepare
        ///     <see cref="SaeaAwaitable" /> for pooling.
        /// </summary>
        public void ClearAndResetSaeaProperties()
        {
            Saea.SocketFlags = SocketFlags.None;
            Saea.SocketError = SocketError.Success;
            Saea.SendPacketsSendSize = 0;
            Saea.SendPacketsElements = null;
            Saea.DisconnectReuseSocket = false;
            Saea.BufferList = null;
            Saea.AcceptSocket = null;
            Saea.RemoteEndPoint = null;
            Saea.UserToken = null;

            if (_initBufferSize != MAGIC)
            {
                // restore buffer
                Saea.SetBuffer(0, _initBufferSize);
            }
        }

        /// <summary>
        ///     Releases all resources used by <see cref="SaeaAwaitable" />.
        /// </summary>
        public void Dispose()
        {
            lock (SyncRoot)
            {
                if (!IsDisposed)
                {
                    Saea.Dispose();
                    IsDisposed = true;
                }
            }
        }
    }
}
