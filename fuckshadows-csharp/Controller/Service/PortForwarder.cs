using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Util.Sockets;

namespace Fuckshadows.Controller
{
    class PortForwarder : Listener.Service
    {
        private readonly int _targetPort;
        private SaeaAwaitablePool _argsPool;
        public const int RecvSize = 8192;
        private const int MAX_HANDLER_NUM = TCPRelay.MAX_HANDLER_NUM;

        public PortForwarder(int targetPort)
        {
            _targetPort = targetPort;
            InitArgsPool();
        }

        private void InitArgsPool()
        {
            _argsPool = new SaeaAwaitablePool();
            _argsPool.SetInitPoolSize(512);
            _argsPool.SetMaxPoolSize(MAX_HANDLER_NUM);
            _argsPool.SetEachBufSize(RecvSize);
            _argsPool.SetNumOfOpsToPreAlloc(2);
            _argsPool.FinishConfig();
        }

        public override bool Handle(ServiceUserToken obj)
        {
            Socket socket = obj.socket;
            if (socket == null) return false;
            if (socket.ProtocolType != ProtocolType.Tcp)
            {
                return false;
            }
            byte[] firstPacket = obj.firstPacket;
            int length = obj.firstPacketLength;

            new Handler().Start(firstPacket, length, socket, _targetPort, _argsPool);
            return true;
        }

        public override void Stop()
        {
            _argsPool.Dispose();
        }

        private class Handler
        {
            private SaeaAwaitablePool _argsPool;
            private byte[] _firstPacket;
            private int _firstPacketLength;
            private Socket _local;

            private Socket _remote;

            //private bool _closed = false;
            private bool _localShutdown = false;

            private bool _remoteShutdown = false;

            // instance-based lock
            private readonly object _Lock = new object();

            private int _state = _none;
            private const int _none = 0;
            private const int _running = 1;
            private const int _disposed = 5;

            public bool IsRunning => _state == _running;

            public void Start(byte[] firstPacket, int length, Socket socket, int targetPort, SaeaAwaitablePool pool)
            {
                _firstPacket = firstPacket;
                _firstPacketLength = length;
                _local = socket;
                _argsPool = pool;

                Interlocked.Exchange(ref _state, _running);

                try
                {
                    // Connect to the remote endpoint.
                    _remote = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    _remote.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                    _remote.SetTFO();

                    Task.Factory.StartNew(async () => { await StartConnect(targetPort); },
                        TaskCreationOptions.PreferFairness);
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
            }

            private async Task StartConnect(int port)
            {
                SaeaAwaitable tcpSaea = null;
                try
                {
                    tcpSaea = _argsPool.Rent();
                    var realSaea = tcpSaea.Saea;
                    realSaea.RemoteEndPoint = SocketUtil.GetEndPoint("127.0.0.1", port);
                    tcpSaea.PrepareSAEABuffer(_firstPacket, _firstPacketLength);
                    var ret = await _remote.ConnectAsync(tcpSaea);
                    if (ret != SocketError.Success)
                    {
                        Close();
                        return;
                    }

                    Task.Factory.StartNew(StartPipe, TaskCreationOptions.PreferFairness).Forget();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
                finally
                {
                    _argsPool.Return(ref tcpSaea);
                }
            }


            private void StartPipe()
            {
                Task.Factory.StartNew(async () => { await Upstream(); }, TaskCreationOptions.AttachedToParent);
                Task.Factory.StartNew(async () => { await Downstream(); }, TaskCreationOptions.AttachedToParent);
            }

            private static bool IsShutdown(SocketExtensions.TcpTrafficToken token)
            {
                var err = token.SocketError;
                var bytesTransferred = token.BytesTotalTransferred;
                return err == SocketError.Success && bytesTransferred <= 0;
            }

            // server recv -> local send
            private async Task Downstream()
            {
                SaeaAwaitable serverRecvSaea = null;
                SaeaAwaitable localSendSaea = null;
                try
                {
                    while (IsRunning)
                    {
                        serverRecvSaea = _argsPool.Rent();
                        var token = await _remote.FullReceiveTaskAsync(serverRecvSaea, RecvSize);
                        var err = token.SocketError;
                        var bytesRecved = token.BytesTotalTransferred;
                        Logging.Debug($"Downstream server recv: {err},{bytesRecved}");

                        if (IsShutdown(token))
                        {
                            //lock (_closeConnLock)
                            //{
                            _local.Shutdown(SocketShutdown.Send);
                            _localShutdown = true;
                            CheckClose();
                            //}
                            return;
                        }
                        if (err != SocketError.Success)
                        {
                            Logging.Debug($"Downstream server recv socket err: {err}");
                            Close();
                            return;
                        }
                        Debug.Assert(bytesRecved <= RecvSize);


                        localSendSaea = _argsPool.Rent();
                        Buffer.BlockCopy(serverRecvSaea.Saea.Buffer, 0, localSendSaea.Saea.Buffer, 0,
                            bytesRecved);
                        _argsPool.Return(ref serverRecvSaea);

                        token = await _local.FullSendTaskAsync(localSendSaea, bytesRecved);
                        err = token.SocketError;
                        var bytesSent = token.BytesTotalTransferred;
                        Logging.Debug($"Downstream local send socket err: {err},{bytesSent}");
                        if (err != SocketError.Success)
                        {
                            Close();
                            return;
                        }
                        Debug.Assert(bytesSent == bytesRecved);
                    }
                }
                catch (AggregateException agex)
                {
                    foreach (var ex in agex.InnerExceptions)
                    {
                        Logging.LogUsefulException(ex);
                    }
                    Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
                finally
                {
                    _argsPool.Return(ref serverRecvSaea);
                    _argsPool.Return(ref localSendSaea);
                }
            }

            // local recv -> server send
            private async Task Upstream()
            {
                SaeaAwaitable localRecvSaea = null;
                SaeaAwaitable serverSendSaea = null;
                try
                {
                    while (IsRunning)
                    {
                        localRecvSaea = _argsPool.Rent();
                        var token = await _local.FullReceiveTaskAsync(localRecvSaea, RecvSize);
                        var err = token.SocketError;
                        var bytesRecved = token.BytesTotalTransferred;
                        Logging.Debug($"Upstream local recv: {err},{bytesRecved}");
                        if (IsShutdown(token))
                        {
                            //lock (_closeConnLock)
                            //{
                            _remote.Shutdown(SocketShutdown.Send);
                            _remoteShutdown = true;
                            CheckClose();
                            //}
                            return;
                        }
                        if (err != SocketError.Success)
                        {
                            Logging.Debug($"Upstream local recv socket err: {err}");
                            Close();
                            return;
                        }
                        Debug.Assert(bytesRecved <= RecvSize);

                        serverSendSaea = _argsPool.Rent();
                        Buffer.BlockCopy(localRecvSaea.Saea.Buffer, 0, serverSendSaea.Saea.Buffer, 0,
                            bytesRecved);
                        _argsPool.Return(ref localRecvSaea);

                        token = await _remote.FullSendTaskAsync(serverSendSaea, bytesRecved);
                        err = token.SocketError;
                        var bytesSent = token.BytesTotalTransferred;
                        Logging.Debug($"Upstream server send: {err},{bytesSent}");
                        if (err != SocketError.Success)
                        {
                            Close();
                            return;
                        }
                        Debug.Assert(bytesSent == bytesRecved);
                    }
                }
                catch (AggregateException agex)
                {
                    foreach (var ex in agex.InnerExceptions)
                    {
                        Logging.LogUsefulException(ex);
                    }
                    Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                    Close();
                }
                finally
                {
                    _argsPool.Return(ref localRecvSaea);
                    _argsPool.Return(ref serverSendSaea);
                }
            }

            private void CheckClose()
            {
                if (_localShutdown && _remoteShutdown)
                {
                    Close();
                }
            }

            public void Close()
            {
                int origin = Interlocked.CompareExchange(ref _state, _disposed, _running);
                if (origin == _disposed)
                {
                    return;
                }

                try
                {
                    _local?.Shutdown(SocketShutdown.Both);
                    _local?.Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                }

                try
                {
                    _remote?.Shutdown(SocketShutdown.Both);
                    _remote?.Close();
                }
                catch (Exception e)
                {
                    Logging.LogUsefulException(e);
                }
            }
        }
    }
}