using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Fuckshadows.Util.Sockets
{
    public sealed class SaeaAwaiter : INotifyCompletion
    {
        // https://blogs.msdn.microsoft.com/pfxteam/2011/12/15/awaiting-socket-operations/

        /// <summary>
        ///     A sentinel delegate that does nothing.
        /// </summary>
        private static readonly Action SENTINEL = delegate { };

        /// <summary>
        ///     The asynchronous socket arguments to await.
        /// </summary>
        private readonly SaeaAwaitable _awaitable;

        /// <summary>
        ///     The continuation delegate that will be called after the current operation is
        ///     awaited.
        /// </summary>
        private Action _continuation;

        /// <summary>
        ///     An object to synchronize access to the awaiter for validations.
        /// </summary>
        public object SyncRoot { get; } = new object();

        /// <summary>
        ///     A value indicating whether the asynchronous operation is completed.
        /// </summary>
        public bool IsCompleted { get; private set; } = true;

        /// <summary>
        ///     Initializes a new instance of the <see cref="SaeaAwaiter" /> class.
        /// </summary>
        /// <param name="awaitable">
        ///     The asynchronous socket arguments to await.
        /// </param>
        public SaeaAwaiter(SaeaAwaitable awaitable)
        {
            _awaitable = awaitable;
            _awaitable.Saea.Completed += (sender, args) =>
            {
                var continuation = _continuation ?? Interlocked.CompareExchange(ref _continuation, SENTINEL, null);

                if (continuation != null)
                {
                    Complete();

                    if (continuation != SENTINEL)
                    {
                        Task.Factory.StartNew(continuation, TaskCreationOptions.PreferFairness);
                    }
                }
            };
        }

        /// <summary>
        ///     Gets the result of the asynchronous socket operation.
        /// </summary>
        /// <returns>
        ///     A <see cref="SocketError" /> that represents the result of the socket operations.
        /// </returns>
        public SocketError GetResult()
        {
            return _awaitable.Saea.SocketError;
        }

        /// <summary>
        ///     Gets invoked when the asynchronous operation is completed and runs the specified
        ///     delegate as continuation.
        /// </summary>
        /// <param name="continuation">
        ///     Continuation to run.
        /// </param>
        public void OnCompleted(Action continuation)
        {
            if (_continuation == SENTINEL
                || Interlocked.CompareExchange(ref _continuation, continuation, null) == SENTINEL)
            {
                Complete();

                Task.Factory.StartNew(continuation, TaskCreationOptions.PreferFairness);
            }
        }

        /// <summary>
        ///     Sets <see cref="IsCompleted" /> to true />
        /// </summary>
        internal void Complete()
        {
            if (!IsCompleted)
            {
                IsCompleted = true;
            }
        }

        /// <summary>
        ///     Resets this awaiter for re-use.
        /// </summary>
        internal void Reset()
        {
            IsCompleted = false;
            _continuation = null;
        }
    }
}
