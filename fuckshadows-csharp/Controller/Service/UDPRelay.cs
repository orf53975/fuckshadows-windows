using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Controller.Strategy;
using Fuckshadows.Encryption;
using Fuckshadows.Model;
using Fuckshadows.Util.Sockets;

namespace Fuckshadows.Controller
{
    class UDPRelay : Listener.Service
    {
        private FuckshadowsController _controller;

        // TODO: choose a smart number
        private LRUCache<IPEndPoint, UDPHandler> _cache = new LRUCache<IPEndPoint, UDPHandler>(UDP_HANDLER_NUM);

        public long outbound = 0;
        public long inbound = 0;

        private SaeaAwaitablePool _argsPool;

        private const int UDPPacketLen = 1500;
        private const int UDP_HANDLER_NUM = 512;

        public UDPRelay(FuckshadowsController controller)
        {
            this._controller = controller;
            InitArgsPool();
        }

        private void InitArgsPool()
        {
            _argsPool = new SaeaAwaitablePool();
            _argsPool.SetInitPoolSize(128);
            _argsPool.SetMaxPoolSize(UDP_HANDLER_NUM);
            _argsPool.SetEachBufSize(UDPPacketLen);
            _argsPool.FinishConfig();
        }

        public override bool Handle(ServiceUserToken obj)
        {
            byte[] firstPacket = obj.firstPacket;
            int length = obj.firstPacketLength;
            Socket socket = obj.socket;
            if (socket == null) return false;
            if (socket.ProtocolType != ProtocolType.Udp)
            {
                return false;
            }
            if (length < 4)
            {
                return false;
            }
            IPEndPoint remoteEndPoint = (IPEndPoint) obj.remoteEndPoint;
            UDPHandler handler = _cache.get(remoteEndPoint);
            if (handler == null)
            {
                handler = new UDPHandler(socket,
                    _controller.GetAServer(IStrategyCallerType.UDP, remoteEndPoint, null /*TODO: fix this*/),
                    remoteEndPoint, _argsPool);
                _cache.add(remoteEndPoint, handler);
            }
            Task.Factory.StartNew(async () => { await handler.Start(firstPacket, length); },
                TaskCreationOptions.LongRunning);
            return true;
        }

        public override void Stop()
        {
            _argsPool.Dispose();
        }

        public class UDPHandler
        {
            private Socket _local;
            private Socket _remote;

            private Server _server;
            private EndPoint _localEndPoint;
            private EndPoint _remoteEndPoint;

            private SaeaAwaitablePool _argsPool;

            private int _state;
            private const int _none = 0;
            private const int _running = 1;
            private const int _disposed = 5;

            public bool IsRunning => _state == _running;

            public UDPHandler(Socket local, Server server, EndPoint localEndPoint, SaeaAwaitablePool pool)
            {
                _local = local;
                _server = server;
                _localEndPoint = localEndPoint;
                _argsPool = pool;
                _remoteEndPoint = SocketUtil.GetEndPoint(server.server, server.server_port);
                _remote = new Socket(_remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            }

            public async Task Start(byte[] data, int length)
            {
                Interlocked.Exchange(ref _state, _running);
                SaeaAwaitable udpSaea = null;
                try
                {
                    while (IsRunning)
                    {
                        IEncryptor encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password);
                        byte[] dataIn = new byte[length - 3];
                        Array.Copy(data, 3, dataIn, 0, length - 3);
                        udpSaea = _argsPool.Rent();

                        int outlen;
                        encryptor.EncryptUDP(dataIn, length - 3, udpSaea.Saea.Buffer, out outlen);
                        udpSaea.Saea.SetBuffer(0, outlen);
                        udpSaea.Saea.RemoteEndPoint = _remoteEndPoint;

                        Logging.Debug(_localEndPoint, _remoteEndPoint, outlen, "UDP Relay");
                        var ret = await _remote.SendToAsync(udpSaea);
                        if (ret != SocketError.Success)
                        {
                            Close();
                            return;
                        }
                        udpSaea = _argsPool.Rent();
                        udpSaea.Saea.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                        ret = await _remote.ReceiveFromAsync(udpSaea);
                        if (ret != SocketError.Success)
                        {
                            Close();
                            return;
                        }
                        var bytesReceived = udpSaea.Saea.BytesTransferred;
                        Logging.Debug($"++++++Receive Server Port, size:" + bytesReceived);


                        byte[] dataOut = new byte[bytesReceived];
                        encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password);
                        encryptor.DecryptUDP(udpSaea.Saea.Buffer, bytesReceived, dataOut, out outlen);
                        _argsPool.Return(udpSaea);
                        udpSaea = null;

                        udpSaea = _argsPool.Rent();
                        byte[] buf = udpSaea.Saea.Buffer;
                        buf[0] = buf[1] = buf[2] = 0;
                        Array.Copy(dataOut, 0, buf, 3, outlen);
                        udpSaea.Saea.RemoteEndPoint = _localEndPoint;
                        udpSaea.Saea.SetBuffer(0, outlen + 3);
                        Logging.Debug(_localEndPoint, _remoteEndPoint, outlen, "UDP Relay");
                        ret = await _local.SendToAsync(udpSaea);
                        if (ret != SocketError.Success)
                        {
                            Close();
                            return;
                        }
                        _argsPool.Return(udpSaea);
                        udpSaea = null;
                    }
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
                finally
                {
                    _argsPool.Return(udpSaea);
                    udpSaea = null;
                }
            }

            public void Close()
            {
                int origin = Interlocked.Exchange(ref _state, _disposed);
                if (origin == _disposed) return;
                try
                {
                    _remote?.Close();
                }
                catch (Exception ex)
                {
                    Logging.LogUsefulException(ex);
                }
            }
        }
    }

    #region LRU cache

    // cc by-sa 3.0 http://stackoverflow.com/a/3719378/1124054
    class LRUCache<K, V> where V : UDPRelay.UDPHandler
    {
        private int capacity;

        private Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>> cacheMap =
            new Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>>();

        private LinkedList<LRUCacheItem<K, V>> lruList = new LinkedList<LRUCacheItem<K, V>>();

        public LRUCache(int capacity)
        {
            this.capacity = capacity;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public V get(K key)
        {
            LinkedListNode<LRUCacheItem<K, V>> node;
            if (cacheMap.TryGetValue(key, out node))
            {
                V value = node.Value.value;
                lruList.Remove(node);
                lruList.AddLast(node);
                return value;
            }
            return default(V);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void add(K key, V val)
        {
            if (cacheMap.Count >= capacity)
            {
                RemoveFirst();
            }

            LRUCacheItem<K, V> cacheItem = new LRUCacheItem<K, V>(key, val);
            LinkedListNode<LRUCacheItem<K, V>> node = new LinkedListNode<LRUCacheItem<K, V>>(cacheItem);
            lruList.AddLast(node);
            cacheMap.Add(key, node);
        }

        private void RemoveFirst()
        {
            // Remove from LRUPriority
            LinkedListNode<LRUCacheItem<K, V>> node = lruList.First;
            lruList.RemoveFirst();

            // Remove from cache
            cacheMap.Remove(node.Value.key);
            node.Value.value.Close();
        }
    }

    class LRUCacheItem<K, V>
    {
        public LRUCacheItem(K k, V v)
        {
            key = k;
            value = v;
        }

        public K key;
        public V value;
    }

    #endregion
}