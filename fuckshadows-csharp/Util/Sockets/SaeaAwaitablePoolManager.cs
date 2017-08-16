using Fuckshadows.Controller;

namespace Fuckshadows.Util.Sockets
{
    public static class SaeaAwaitablePoolManager
    {
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
            AcceptOnlyInstance = new SaeaAwaitablePool();
            AcceptOnlyInstance.SetInitPoolSize(256);
            AcceptOnlyInstance.SetMaxPoolSize(Listener.BACKLOG);
            AcceptOnlyInstance.SetNoSetBuffer();
            AcceptOnlyInstance.FinishConfig();
        }

        /// <summary>
        /// Pool for ordinary usage that needs buffer to be set
        /// e.g. receive, send, etc
        /// </summary>
        private static void InitOrdinaryPool()
        {
            if (OrdinaryInstance != null) return;
            OrdinaryInstance = new SaeaAwaitablePool();
            OrdinaryInstance.SetInitPoolSize(256);
            OrdinaryInstance.SetMaxPoolSize(TCPRelay.MAX_HANDLER_NUM);
            // XXX: max buffer size among all services
            OrdinaryInstance.SetEachBufSize(TCPRelay.BufferSize);
            OrdinaryInstance.FinishConfig();
        }

        private static SaeaAwaitablePool AcceptOnlyInstance { get; set; } = null;
        private static SaeaAwaitablePool OrdinaryInstance { get; set; } = null;

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