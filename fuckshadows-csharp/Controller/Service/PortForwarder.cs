using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Util.Sockets;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Controller
{
    class PortForwarder : Listener.Service
    {
        private readonly int _targetPort;
        private ISegmentBufferManager _segmentBufferManager;
        public const int RecvSize = 8192;

        public PortForwarder(int targetPort)
        {
            _targetPort = targetPort;
            _segmentBufferManager = new SegmentBufferManager(2048, RecvSize);
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
            if (length <= 0) return false;

            new Handler().Start(firstPacket, length, socket, _targetPort, _segmentBufferManager);
            return true;
        }

        public override void Stop()
        {
        }

        private class Handler
        {
            private ISegmentBufferManager _segmentBufferManager;
            private byte[] _firstPacket;
            private int _firstPacketLength;
            private Socket _local;

            private Socket _remote;

            //private bool _closed = false;
            private bool _localShutdown = false;

            private bool _remoteShutdown = false;

            private int _state = _none;
            private const int _none = 0;
            private const int _running = 1;
            private const int _disposed = 5;

            public bool IsRunning => _state == _running;

            public void Start(byte[] firstPacket, int length, Socket socket,
                int targetPort, ISegmentBufferManager bm)
            {
                _firstPacket = firstPacket;
                _firstPacketLength = length;
                _local = socket;
                _segmentBufferManager = bm;

                Interlocked.Exchange(ref _state, _running);

                try
                {
                    // Connect to the remote endpoint.
                    _remote = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    _remote.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

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
                try
                {
                    var RemoteEndPoint = SocketUtil.GetEndPoint("127.0.0.1", port);
                    await _remote.ConnectAsync(RemoteEndPoint);
                    var seg = _firstPacket.AsArraySegment(0, _firstPacketLength);
                    var ret = await _remote.FullSendTaskAsync(seg, _firstPacketLength);
                    if (ret <= 0)
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
            }


            private void StartPipe()
            {
                Task.Factory.StartNew(async () => { await Upstream(); });
                Task.Factory.StartNew(async () => { await Downstream(); });
            }

            // server recv -> local send
            private async Task Downstream()
            {
                ArraySegment<byte> buf = default(ArraySegment<byte>);
                try
                {
                    while (IsRunning)
                    {
                        buf = _segmentBufferManager.BorrowBuffer();
                        var bytesRecved = await _remote.ReceiveAsync(buf, SocketFlags.None);

                        Logging.Debug($"Downstream server recv: {bytesRecved}");

                        if (bytesRecved == 0)
                        {
                            _local.Shutdown(SocketShutdown.Send);
                            _localShutdown = true;
                            CheckClose();
                            return;
                        }
                        else if (bytesRecved < 0)
                        {
                            Close();
                            return;
                        }

                        Debug.Assert(bytesRecved <= RecvSize);

                        var bytesSent = await _local.FullSendTaskAsync(buf.Take(bytesRecved), bytesRecved);
                        Logging.Debug($"Downstream local send socket err: {bytesSent}");
                        if (bytesSent <= 0)
                        {
                            Close();
                            return;
                        }
                        Debug.Assert(bytesSent == bytesRecved);
                        _segmentBufferManager.ReturnBuffer(buf);
                        buf = default(ArraySegment<byte>);
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
                    if (buf != default(ArraySegment<byte>))
                    {
                        _segmentBufferManager.ReturnBuffer(buf);
                        buf = default(ArraySegment<byte>);
                    }
                }
            }

            // local recv -> server send
            private async Task Upstream()
            {
                ArraySegment<byte> buf = default(ArraySegment<byte>);
                try
                {
                    while (IsRunning)
                    {
                        buf = _segmentBufferManager.BorrowBuffer();
                        var bytesRecved = await _local.ReceiveAsync(buf, SocketFlags.None);

                        Logging.Debug($"Upstream local recv: {bytesRecved}");
                        if (bytesRecved == 0)
                        {
                            _remote.Shutdown(SocketShutdown.Send);
                            _remoteShutdown = true;
                            CheckClose();
                            return;
                        }
                        else if (bytesRecved < 0)
                        {
                            Close();
                            return;
                        }

                        var bytesSent = await _remote.FullSendTaskAsync(buf.Take(bytesRecved), bytesRecved);

                        Logging.Debug($"Upstream server send: {bytesSent}");
                        if (bytesSent <= 0)
                        {
                            Close();
                            return;
                        }
                        _segmentBufferManager.ReturnBuffer(buf);
                        buf = default(ArraySegment<byte>);
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
                    if (buf != default(ArraySegment<byte>))
                    {
                        _segmentBufferManager.ReturnBuffer(buf);
                        buf = default(ArraySegment<byte>);
                    }
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