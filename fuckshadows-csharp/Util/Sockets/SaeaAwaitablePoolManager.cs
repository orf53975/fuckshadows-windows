using System;
using System.Net.Sockets;
using Fuckshadows.Controller;

namespace Fuckshadows.Util.Sockets
{
    public static class SaeaAwaitablePoolManager
    {
        // XXX: max buffer size among all services
        private const int EachBufSize = TCPRelay.BufferSize;
        private static readonly object _syncLock = new object();

        public static SaeaAwaitablePool GetAcceptOnlyInstance()
        {
            if (AcceptOnlyInstance == null)
            {
                InitAcceptOnlyPool();
            }

            return AcceptOnlyInstance;
        }

        public static SaeaAwaitablePool GetOrdinaryInstance()
        {
            if (OrdinaryInstance == null)
            {
                InitOrdinaryPool();
            }

            return OrdinaryInstance;
        }

        /// <summary>
        /// Pool for accepting only, do NOT need attaching buffer
        /// </summary>
        private static void InitAcceptOnlyPool()
        {
            if (AcceptOnlyInstance != null) return;
            //accept args pool don't need buffer
            AcceptOnlyInstance = new SaeaAwaitablePool(CreateAcceptSaeaAwaitable,
                CleanAcceptSaeaAwaitable );
        }

        private static void CleanAcceptSaeaAwaitable(SaeaAwaitable s)
        {
            lock (_syncLock)
            {
                s?.Saea?.ResetSAEAProperties(false);
            }
        }

        private static SaeaAwaitable CreateAcceptSaeaAwaitable()
        {
            return new SaeaAwaitable();
        }

        /// <summary>
        /// Pool for ordinary usage that needs buffer to be set
        /// e.g. receive, send, etc
        /// </summary>
        private static void InitOrdinaryPool()
        {
            if (OrdinaryInstance != null) return;
            OrdinaryInstance = new SaeaAwaitablePool(CreateOrdinarySaeaAwaitable,
                CleanOrdinarySaeaAwaitable);
        }

        private static void CleanOrdinarySaeaAwaitable(SaeaAwaitable s)
        {
            lock (_syncLock)
            {
                s?.Saea?.ResetSAEAProperties(true);
            }
        }

        private static SaeaAwaitable CreateOrdinarySaeaAwaitable()
        {
            lock (_syncLock)
            {
                var s = new SaeaAwaitable();
                s.Saea.SetBuffer(new byte[EachBufSize], 0, EachBufSize);
                return s;
            }
        }

        private static SaeaAwaitablePool AcceptOnlyInstance { get; set; } = null;
        private static SaeaAwaitablePool OrdinaryInstance { get; set; } = null;

        public static void ResetSAEAProperties(this SocketAsyncEventArgs Saea, bool isResetBufLen)
        {
            lock (_syncLock)
            {
                if (Saea == null) return;
                Saea.SocketFlags = SocketFlags.None;
                Saea.SocketError = SocketError.Success;
                Saea.SendPacketsSendSize = 0;
                Saea.SendPacketsElements = null;
                Saea.DisconnectReuseSocket = false;
                Saea.BufferList = null;
                Saea.AcceptSocket = null;
                Saea.RemoteEndPoint = null;
                Saea.UserToken = null;
                if (isResetBufLen)
                    Saea.SetBuffer(0, EachBufSize);
            }
        }

        public static void Dispose()
        {
            if (AcceptOnlyInstance != null)
            {
                AcceptOnlyInstance.Dispose();
                AcceptOnlyInstance = null;
            }
            if (OrdinaryInstance != null)
            {
                OrdinaryInstance.Dispose();
                OrdinaryInstance = null;
            }
        }

        public static void Init()
        {
            InitAcceptOnlyPool();
            InitOrdinaryPool();
        }
    }
}