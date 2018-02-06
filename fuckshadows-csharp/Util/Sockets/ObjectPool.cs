using System;
using System.Collections.Concurrent;

namespace Fuckshadows.Util.Sockets
{
    public abstract class ObjectPool<T> : IDisposable
    {
        private readonly ConcurrentBag<T> _bag;
        private readonly object _bagLock = new object();
        private bool _isDisposed;

        public ObjectPool()
        {
            _bag = new ConcurrentBag<T>();
        }

        protected abstract T Create();

        public int Count
        {
            get
            {
                return _bag.Count;
            }
        }

        public void Add(T item)
        {
            lock (_bagLock)
            {
                if (item == null) return;
            }
            _bag.Add(item);
        }

        public T Rent()
        {
            T item;
            var ret = _bag.TryTake(out item);
            if ((ret && item == null) || !ret)
                return Create();
            return item;
        }

        public bool IsDisposed
        {
            get
            {
                lock (_bagLock)
                {
                    return _isDisposed;
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            lock (_bagLock)
            {
                if (_isDisposed)
                    return;

                if (disposing)
                {
                    // free managed objects here
                    for (int i = 0; i < this.Count; i++)
                    {
                        var item = this.Rent() as IDisposable;
                        if (item != null)
                            item.Dispose();
                    }
                }

                _isDisposed = true;
            }
        }
    }
}
