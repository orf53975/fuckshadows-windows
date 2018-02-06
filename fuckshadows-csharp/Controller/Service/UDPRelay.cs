﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Encryption;
using Fuckshadows.Model;
using Fuckshadows.Util.Sockets;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Controller
{
    class UDPRelay : Listener.Service
    {
        private FuckshadowsController _controller;

        // TODO: choose a smart number
        private LRUCache<IPEndPoint, UDPHandler> _cache = new LRUCache<IPEndPoint, UDPHandler>(UDP_HANDLER_NUM);

        public long outbound = 0;
        public long inbound = 0;

        private const int UDP_HANDLER_NUM = 512;

        public UDPRelay(FuckshadowsController controller)
        {
            this._controller = controller;
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
                    _controller.GetAServer(remoteEndPoint, null /*TODO: fix this*/),
                    remoteEndPoint);
                _cache.add(remoteEndPoint, handler);
            }
            Task.Factory.StartNew(async () => { await handler.Start(firstPacket, length); }).Forget();
            return true;
        }

        public override void Stop()
        {
        }

        public class UDPHandler
        {
            private Socket _localSocket;
            private Socket _serverSocket;

            private Server _server;
            private EndPoint _localEndPoint;
            private EndPoint _serverEndPoint;

            private int _state = _none;
            private const int _none = 0;
            private const int _running = 1;
            private const int _disposed = 5;

            public bool IsRunning => _state == _running;

            public UDPHandler(Socket local, Server server, EndPoint localEndPoint)
            {
                _localSocket = local;
                _server = server;
                _localEndPoint = localEndPoint;
                _serverEndPoint = SocketUtil.GetEndPoint(server.server, server.server_port);
                _serverSocket = new Socket(SocketType.Dgram, ProtocolType.Udp);
            }

            public async Task Start(byte[] data, int length)
            {
                Interlocked.Exchange(ref _state, _running);
                ArraySegment<byte> tmpArrSegment = default(ArraySegment<byte>);
                try
                {
                    Logging.Debug($"-----UDP relay got {length}-----");
                    IEncryptor encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password);
                    byte[] dataIn = new byte[length - 3];
                    Array.Copy(data, 3, dataIn, 0, length - 3);

                    int outlen;
                    byte[] maxUDPBytes = new byte[1500];
                    encryptor.EncryptUDP(dataIn, dataIn.Length, maxUDPBytes, out outlen);
                    tmpArrSegment = new ArraySegment<byte>(maxUDPBytes, 0, outlen);
                    int ret = await _serverSocket.SendToAsync(tmpArrSegment, SocketFlags.None, _serverEndPoint);
                    if (ret <= 0)
                    {
                        Logging.Error($"[udp] remote sendto {ret}");
                        Close();
                        return;
                    }
                    Logging.Debug($"[udp] remote sendto {_localEndPoint} -> {_serverEndPoint} {ret}");


                    while (IsRunning)
                    {

                        tmpArrSegment = new ArraySegment<byte>(maxUDPBytes, 0, 1500);
                        var result = await _serverSocket.ReceiveFromAsync(tmpArrSegment, SocketFlags.None,
                            new IPEndPoint(IPAddress.Any, 0));
                        var bytesReceived = result.ReceivedBytes;
                        if (bytesReceived <= 0)
                        {
                            Logging.Error($"[udp] remote recvfrom {ret},{bytesReceived}");
                            Close();
                            return;
                        }
                        Logging.Debug($"[udp] remote recvfrom {result.RemoteEndPoint} -> {_localSocket.LocalEndPoint} {bytesReceived}");
                        byte[] dataOut = new byte[bytesReceived];
                        encryptor = EncryptorFactory.GetEncryptor(_server.method, _server.password);
                        encryptor.DecryptUDP(maxUDPBytes, bytesReceived, dataOut, out outlen);


                        byte[] buf = maxUDPBytes;
                        buf[0] = buf[1] = buf[2] = 0;
                        Array.Copy(dataOut, 0, buf, 3, outlen);

                        tmpArrSegment = new ArraySegment<byte>(maxUDPBytes, 0, outlen + 3);
                        var bytesSent = await _localSocket.SendToAsync(tmpArrSegment, SocketFlags.None, _localEndPoint);
                        if (bytesSent <= 0)
                        {
                            Logging.Error($"[udp] local sendto {ret}");
                            Close();
                            return;
                        }
                        Logging.Debug($"[udp] local sendto {_localSocket.LocalEndPoint} -> {_localEndPoint} {bytesSent}");
                    }
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
            }

            public void Close()
            {
                int origin = Interlocked.Exchange(ref _state, _disposed);
                if (origin == _disposed) return;
                Logging.Debug("[udp] Closing remote socket");
                try
                {
                    _serverSocket.Close();
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