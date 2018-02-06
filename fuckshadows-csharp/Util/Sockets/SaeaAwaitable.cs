using System;
using System.Net.Sockets;

namespace Fuckshadows.Util.Sockets
{
    public sealed class SaeaAwaitable : IDisposable
    {
        private readonly object _sync = new object();
        private readonly SaeaAwaiter _awaiter;
        private bool _shouldCaptureContext;
        private bool _isDisposed;

        public SaeaAwaitable()
        {
            _awaiter = new SaeaAwaiter(this);
        }

        public SocketAsyncEventArgs Saea { get; private set; } = new SocketAsyncEventArgs();

        public SaeaAwaiter GetAwaiter()
        {
            return _awaiter;
        }

        public bool ShouldCaptureContext
        {
            get => _shouldCaptureContext;
            set
            {
                lock (_awaiter.SyncRoot)
                {
                    if (_awaiter.IsCompleted)
                        _shouldCaptureContext = value;
                    else
                        throw new InvalidOperationException(
                            "A socket operation is already in progress using the same awaitable SAEA.");
                }
            }
        }

        private void Dispose(bool disposing)
        {
            lock (_sync)
            {
                if (_isDisposed) return;
                _isDisposed = true;
                if (disposing)
                {
                }
                Saea.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~SaeaAwaitable()
        {
            Dispose(false);
        }
    }
}
