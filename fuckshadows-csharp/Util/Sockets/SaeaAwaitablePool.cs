using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.ServiceModel.Channels;
using Fuckshadows.Util.Sockets;

namespace Fuckshadows.Controller
{
    public class SaeaAwaitablePool : IDisposable
    {
        private BlockingCollection<SaeaAwaitable> _argsPool = new BlockingCollection<SaeaAwaitable>(new ConcurrentQueue<SaeaAwaitable>());

        private BufferManager _bufferManager = null;

        private bool _disposed;

        private readonly object _disposeLock = new object();

        private readonly object _bufMgrLock = new object();

        private SAEAPoolConfig _config = new SAEAPoolConfig();

        /// <summary>
        /// Create a SAEA pool
        /// </summary>
        public SaeaAwaitablePool()
        {
        }

        public void SetInitPoolSize(int size)
        {
            _config._initPoolSize = size;
        }

        public void SetMaxPoolSize(int maxSize)
        {
            _config._maxPoolSize = maxSize;
        }

        public void SetEachBufSize(int bufSize)
        {
            _config._maxSingleBufSize = RoundUpToNearest(bufSize);
        }

        /// <summary>
        /// Don't allocate and attach buffer, this is used when accepting connections
        /// </summary>
        public void SetNoSetBuffer()
        {
            _config._isSetBuffer = false;
        }

        /// <summary>
        /// Set how many types of SocketOperation will be used
        /// </summary>
        /// <param name="num"></param>
        public void SetNumOfOpsToPreAlloc(int num)
        {
            _config._operationsToPreAlloc = num;
        }

        /// <summary>
        /// Configure internal settings, it's the final call before usage
        /// </summary>
        public void FinishConfig()
        {
            if (_config._isSetBuffer)
            {
                // TakeBuffer expects a buffer of *at least* the specified size
                // thus we set the max single buffer a bit larger
                _bufferManager = BufferManager.CreateBufferManager(
                    _config._maxSingleBufSize * _config._maxPoolSize * _config._operationsToPreAlloc,
                    _config._maxSingleBufSize);
            }

            SaeaAwaitable args;
            var size = _config._initPoolSize;
            for (int i = 0; i < size; i++)
            {
                args = CreateSaeaAwaitable();
                _argsPool.Add(args);
            }
        }

        private static int RoundUpToNearest(int x)
        {
            return (x + 4 - 1) & ~(4 - 1);  //向上取整为2^x的倍数需要将本行的两个4改为2^x
        }

        /// <summary>
        /// Rent a SAEA from pool, must return after use.
        /// </summary>
        /// <returns></returns>
        public SaeaAwaitable Rent()
        {
            int tries = 0;
            SaeaAwaitable args;
            while (! _argsPool.TryTake(out args)) {
                ++tries;
                if (tries > 3) throw new Exception("Too many tries to create SAEA");
                // if we cannot get one, create it and put back
                // then retry
                args = CreateSaeaAwaitable();
                _argsPool.Add(args);
            }

            if (_argsPool.Count > _config._maxPoolSize) {
                Trim(_argsPool.Count - _config._maxPoolSize);
            }

            return args;
        }

        /// <summary>
        /// Return a SAEA that rented before
        /// </summary>
        /// <param name="args"></param>
        public void Return(ref SaeaAwaitable args)
        {
            if (args == null)
                return;
            lock (_bufMgrLock) {
                args.ClearAndResetSaeaProperties();
                if (! _argsPool.IsAddingCompleted)
                    _argsPool.Add(args);
            }
            // set origin to null
            args = null;
        }

        protected SaeaAwaitable CreateSaeaAwaitable()
        {
            lock (_bufMgrLock)
            {
                SaeaAwaitable args = new SaeaAwaitable();

                if (_config._isSetBuffer)
                {
                    byte[] buf = _bufferManager.TakeBuffer(_config._maxSingleBufSize);
                    args.SetInitBufferSize(buf.Length);
                    args.Saea.SetBuffer(buf, 0, buf.Length);
                }

                return args;
            }
        }

        /// <summary>
        /// Clear some SAEAs from pool
        /// </summary>
        /// <param name="count">numbers that you want to dispose</param>
        public void Trim(int count)
        {
            if (count <= 0 || count > _config._maxPoolSize)
                throw new ArgumentOutOfRangeException(nameof(count));
            for (int i = 0; i < count; i++) {
                SaeaAwaitable args;

                if (_argsPool.TryTake(out args)) {
                    ClearBuffer(args);
                    args.Dispose();
                }
            }
        }

        private void ClearBuffer(SaeaAwaitable e)
        {
            if (e == null) throw new ArgumentNullException(nameof(e));
            if (!_config._isSetBuffer) return;
            lock (_bufMgrLock)
            {
                try {
                    if (_config._isSetBuffer) {
                        byte[] buf = e.Saea.Buffer;
                        e.Saea.SetBuffer(null, 0, 0);
                        _bufferManager.ReturnBuffer(buf);
                    }
                } catch (ArgumentNullException) {
                }
            }
        }

        private void ReleaseUnmanagedResources()
        {
            // TODO release unmanaged resources here
            // it seems we don't have any unmanaged objects
        }

        private void Dispose(bool disposing)
        {
            lock (_disposeLock) {
                if (_disposed) return;
                _disposed = true;
            }

            ReleaseUnmanagedResources();
            if (disposing) {
                _argsPool.CompleteAdding();

                while (_argsPool.Count > 0) {
                    SaeaAwaitable arg = _argsPool.Take();
                    ClearBuffer(arg);
                    arg.Dispose();
                }
                _argsPool?.Dispose();
                lock (_bufMgrLock)
                {
                    if (_config._isSetBuffer)
                    {
                        _bufferManager.Clear();
                    }
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~SaeaAwaitablePool() { Dispose(false); }

        private class SAEAPoolConfig
        {
            public int _initPoolSize;
            public int _maxPoolSize;
            public int _maxSingleBufSize;
            public int _operationsToPreAlloc = 4;
            // In general, we will attach buffer
            public bool _isSetBuffer = true;
        }
    }
}