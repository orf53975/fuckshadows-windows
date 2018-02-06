using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Fuckshadows.Util.Sockets
{
    // https://blogs.msdn.microsoft.com/pfxteam/2011/12/15/awaiting-socket-operations/
    public sealed class SaeaAwaiter : INotifyCompletion
    {
        private static readonly Action SENTINEL = delegate { };
        private readonly SaeaAwaitable _awaitable;
        private Action _continuation;

        public SaeaAwaiter(SaeaAwaitable awaitable)
        {
            _awaitable = awaitable;
            _awaitable.Saea.Completed += OnSaeaCompleted;
        }

        private void OnSaeaCompleted(object sender, SocketAsyncEventArgs args)
        {
            var continuation = _continuation ?? Interlocked.CompareExchange(ref _continuation, SENTINEL, null);

            if (continuation != null)
            {
                var syncContext = _awaitable.ShouldCaptureContext
                    ? this.SyncContext
                    : null;

                this.Complete();

                if (continuation != SENTINEL)
                {
                    if (syncContext != null)
                        syncContext.Post(s => continuation.Invoke(), null);
                    else
                        continuation.Invoke();
                }
            }
        }

        internal object SyncRoot { get; } = new object();

        internal SynchronizationContext SyncContext { private get; set; }

        public SocketError GetResult()
        {
            return _awaitable.Saea.SocketError;
        }

        void INotifyCompletion.OnCompleted(Action continuation)
        {
            if (_continuation == SENTINEL
                || Interlocked.CompareExchange(ref _continuation, continuation, null) == SENTINEL)
            {
                this.Complete();

                if (!_awaitable.ShouldCaptureContext)
                    Task.Run(continuation);
                else
                    Task.Factory.StartNew(
                        continuation,
                        CancellationToken.None,
                        TaskCreationOptions.DenyChildAttach,
                        TaskScheduler.FromCurrentSynchronizationContext());
            }
        }

        public bool IsCompleted { get; private set; } = true;

        internal void Complete()
        {
            if (!IsCompleted)
            {
                if (_awaitable.ShouldCaptureContext)
                    SyncContext = null;

                IsCompleted = true;
            }
        }

        internal void Reset()
        {
            IsCompleted = false;
            _continuation = null;
        }
    }
}
