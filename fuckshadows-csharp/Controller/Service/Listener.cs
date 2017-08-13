using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Fuckshadows.Model;
using Fuckshadows.Util.Sockets;

namespace Fuckshadows.Controller
{
    public partial class Listener
    {
        private Configuration _config;
        private bool _shareOverLan;
        private Socket _tcpListenerSocket;
        private Socket _udpSocket;
        private readonly List<IService> _services;
        private SaeaAwaitablePool _acceptArgsPool;
        private SaeaAwaitablePool _argsPool;

        private const int BACKLOG = 1024;
        private const int MaxFirstPacketLen = 4096;

        private int _state;
        private const int _none = 0;
        private const int _listening = 1;
        private const int _disposed = 5;

        public bool IsListening => _state == _listening;

        public Listener(List<IService> services)
        {
            this._services = services;
        }

        private bool CheckIfPortInUse(int port)
        {
            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] ipEndPoints = ipProperties.GetActiveTcpListeners();

            foreach (IPEndPoint endPoint in ipEndPoints)
            {
                if (endPoint.Port == port)
                {
                    return true;
                }
            }
            return false;
        }

        private void InitArgsPool()
        {
            //accept args pool don't need buffer
            _acceptArgsPool = new SaeaAwaitablePool();
            _acceptArgsPool.SetInitPoolSize(256);
            _acceptArgsPool.SetMaxPoolSize(BACKLOG);
            _acceptArgsPool.SetNoSetBuffer();
            _acceptArgsPool.SetNumOfOpsToPreAlloc(1);
            _acceptArgsPool.FinishConfig();

            // first packet handling pool
            _argsPool = new SaeaAwaitablePool();
            _argsPool.SetInitPoolSize(256);
            _argsPool.SetMaxPoolSize(8192);
            _argsPool.SetEachBufSize(MaxFirstPacketLen);
            _argsPool.SetNumOfOpsToPreAlloc(2);
            _argsPool.FinishConfig();
        }

        public void Start(Configuration config)
        {
            this._config = config;
            this._shareOverLan = config.shareOverLan;

            int origin = Interlocked.CompareExchange(ref _state, _listening, _none);
            if (origin == _disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
            else if (origin != _none)
            {
                throw new InvalidOperationException("Listener has already started.");
            }

            if (CheckIfPortInUse(_config.localPort))
                throw new Exception(I18N.GetString("Port already in use"));

            try
            {
                InitArgsPool();
                // Create a TCP/IP socket.
                _tcpListenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _tcpListenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                IPEndPoint localEndPoint = _shareOverLan
                    ? new IPEndPoint(IPAddress.Any, _config.localPort)
                    : new IPEndPoint(IPAddress.Loopback, _config.localPort);

                _tcpListenerSocket.SetTFO();
                // Bind the socket to the local endpoint and listen for incoming connections.
                _tcpListenerSocket.Bind(localEndPoint);
                _udpSocket.Bind(localEndPoint);
                _tcpListenerSocket.Listen(BACKLOG);

                // Start an asynchronous socket to listen for connections.
                Logging.Info("Fuckshadows started");
                Logging.Info($"TFO: {Program.TFOSupported}");

                Task.Run(async () => { await Accept(); });

                Task.Run(async () => { await StartRecvFrom(); });
            }
            catch (SocketException)
            {
                _tcpListenerSocket.Close();
                throw;
            }
        }

        private async Task StartRecvFrom()
        {
            SaeaAwaitable udpSaea = null;
            try
            {
                while (IsListening)
                {
                    udpSaea = _argsPool.Rent();
                    udpSaea.Saea.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    var err = await _udpSocket.ReceiveFromAsync(udpSaea);
                    ServiceUserToken token = new ServiceUserToken();
                    if (err == SocketError.Success && udpSaea.Saea.BytesTransferred > 0)
                    {
                        var e = udpSaea.Saea;
                        token.socket = _udpSocket;
                        token.firstPacket = new byte[e.BytesTransferred];
                        token.firstPacketLength = e.BytesTransferred;
                        token.remoteEndPoint = e.RemoteEndPoint;
                        Buffer.BlockCopy(e.Buffer, e.Offset, token.firstPacket, 0, e.BytesTransferred);
                    }
                    _argsPool.Return(ref udpSaea);

                    foreach (IService service in _services)
                    {
                        if (service.Handle(token))
                        {
                            return;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }
            finally
            {
                _argsPool.Return(ref udpSaea);
            }
        }

        private async Task Accept()
        {
            SaeaAwaitable saea = null;
            try
            {
                while (IsListening)
                {
                    saea = _acceptArgsPool.Rent();

                    var socketError = await _tcpListenerSocket.AcceptAsync(saea);
                    if (socketError == SocketError.Success)
                    {
                        Logging.Debug("accepted a connection");
                        var acceptedSocket = saea.Saea.AcceptSocket;
                        Task.Factory.StartNew(async () => { await RecvFirstPacket(acceptedSocket); },
                            TaskCreationOptions.PreferFairness).Forget();
                    }
                    else
                    {
                        Logging.Error($"Accept socket err: {socketError}");
                    }
                    _acceptArgsPool.Return(ref saea);
                }
            }
            catch (Exception ex)
            {
                Logging.LogUsefulException(ex);
            }
            finally
            {
                _acceptArgsPool.Return(ref saea);
            }
        }

        private async Task RecvFirstPacket(Socket clientSocket)
        {
            SaeaAwaitable arg = null;
            try
            {
                arg = _argsPool.Rent();
                var token = await clientSocket.FullReceiveTaskAsync(arg, MaxFirstPacketLen);
                var err = token.SocketError;
                var serviceToken = new ServiceUserToken();
                var bytesReceived = token.BytesTotalTransferred;
                Logging.Debug($"RecvFirstPacket: {err},{bytesReceived}");
                if (err == SocketError.Success && bytesReceived > 0)
                {
                    serviceToken.socket = clientSocket;
                    serviceToken.firstPacket = new byte[bytesReceived];
                    Buffer.BlockCopy(arg.Saea.Buffer, 0, serviceToken.firstPacket, 0, bytesReceived);
                    serviceToken.firstPacketLength = bytesReceived;
                }
                else
                {
                    Logging.Error($"RecvFirstPacket socket err: {err},{bytesReceived}");
                    goto Error;
                }
                _argsPool.Return(ref arg);

                foreach (IService service in _services)
                {
                    if (service.Handle(serviceToken))
                    {
                        return;
                    }
                }
                Error:
                // no service found for this
                if (clientSocket.ProtocolType == ProtocolType.Tcp)
                {
                    clientSocket.Close();
                }
            }
            catch (Exception e)
            {
                Logging.Error(e);
            }
            finally
            {
                _argsPool.Return(ref arg);
            }
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _state, _disposed) == _disposed)
            {
                return;
            }

            if (_tcpListenerSocket != null)
            {
                _tcpListenerSocket.Close();
                _tcpListenerSocket = null;
            }
            if (_udpSocket != null)
            {
                _udpSocket.Close();
                _udpSocket = null;
            }

            _services.ForEach(s => s.Stop());

            _acceptArgsPool.Dispose();
            _argsPool.Dispose();
        }
    }
}