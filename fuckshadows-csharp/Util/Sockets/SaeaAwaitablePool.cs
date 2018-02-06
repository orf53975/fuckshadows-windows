using System;

namespace Fuckshadows.Util.Sockets
{
    public class SaeaAwaitablePool : ObjectPool<SaeaAwaitable>
    {
        private Func<SaeaAwaitable> _createSaea;
        private Action<SaeaAwaitable> _cleanSaea;

        private readonly object _syncLock = new object();

        public SaeaAwaitablePool(Func<SaeaAwaitable> createSaea, Action<SaeaAwaitable> cleanSaea)
            : base()
        {
            if (createSaea == null)
                throw new ArgumentNullException("createSaea");
            if (cleanSaea == null)
                throw new ArgumentNullException("cleanSaea");

            _createSaea = createSaea;
            _cleanSaea = cleanSaea;
        }

        public SaeaAwaitablePool Initialize(int initialCount = 0)
        {
            if (initialCount < 0)
                throw new ArgumentOutOfRangeException(
                    "initialCount",
                    initialCount,
                    "Initial count must not be less than zero.");

            for (int i = 0; i < initialCount; i++)
            {
                Add(Create());
            }

            return this;
        }

        protected override SaeaAwaitable Create()
        {
            lock (_syncLock)
            {
                return _createSaea();
            }
        }

        public void Return(SaeaAwaitable saea)
        {
            lock (_syncLock)
            {
                _cleanSaea(saea);
                Add(saea);
            }
        }
    }
}
