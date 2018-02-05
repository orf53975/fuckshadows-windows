using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Encryption;
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

        public const int BACKLOG = 1024;
        private const int MaxFirstPacketLen = 4096;

        private int _state = _none;
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
            _acceptArgsPool = SaeaAwaitablePoolManager.GetAcceptOnlyInstance();
            _argsPool = SaeaAwaitablePoolManager.GetOrdinaryInstance();
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
                // XXX: this constructor will create a IPv6 socket with dual mode enabled
                _tcpListenerSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _tcpListenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _tcpListenerSocket.SetTFO();

                _udpSocket = new Socket(SocketType.Dgram, ProtocolType.Udp);
                _udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                // still listening on v4 addr, we will get v4 mapped v6 addr
                IPEndPoint localEndPoint = _shareOverLan
                    ? new IPEndPoint(IPAddress.Any, _config.localPort)
                    : new IPEndPoint(IPAddress.Loopback, _config.localPort);

                // Bind the socket to the local endpoint and listen for incoming connections.
                _tcpListenerSocket.Bind(localEndPoint);
                _udpSocket.Bind(localEndPoint);
                _tcpListenerSocket.Listen(BACKLOG);

                // Start an asynchronous socket to listen for connections.
                Logging.Info("Fuckshadows started");
                Logging.Info($"TFO: {Program.TFOSupported}");
                Logging.Info(EncryptorFactory.DumpRegisteredEncryptor());

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
                    var saea = udpSaea.Saea;
                    var bytesRecved = saea.BytesTransferred;
                    
                    if (err == SocketError.Success && bytesRecved > 0)
                    {
                        ServiceUserToken token = new ServiceUserToken
                        {
                            socket = _udpSocket,
                            firstPacket = new byte[bytesRecved],
                            firstPacketLength = bytesRecved,
                            remoteEndPoint = saea.RemoteEndPoint
                        };
                        Buffer.BlockCopy(saea.Buffer, 0, token.firstPacket, 0, bytesRecved);

                        Task.Factory.StartNew(() => HandleUDPServices(token)).Forget();
                    }
                    else
                    {
                        Logging.Error($"RecvFrom: {err},{bytesRecved}");
                    }
                    _argsPool.Return(udpSaea);
                    udpSaea = null;
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }
            finally
            {
                _argsPool.Return(udpSaea);
                udpSaea = null;
            }
        }

        private void HandleUDPServices(ServiceUserToken token)
        {
            foreach (IService service in _services)
            {
                if (service.Handle(token))
                {
                    return;
                }
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
                    _acceptArgsPool.Return(saea);
                    saea = null;
                }
            }
            catch (Exception ex)
            {
                Logging.LogUsefulException(ex);
            }
            finally
            {
                _acceptArgsPool.Return(saea);
                saea = null;
            }
        }

        private async Task RecvFirstPacket(Socket clientSocket)
        {
            SaeaAwaitable arg = null;
            try
            {
                arg = _argsPool.Rent();
                // Full receive here to get the whole first packet and parse it in single operation
                var token = await clientSocket.FullReceiveTaskAsync(arg, MaxFirstPacketLen);
                var err = token.SocketError;
                ServiceUserToken serviceToken = null;
                var bytesReceived = token.BytesTotalTransferred;
                Logging.Debug($"RecvFirstPacket: {err},{bytesReceived}");
                if (err == SocketError.Success && bytesReceived > 0)
                {
                    serviceToken = new ServiceUserToken
                    {
                        socket = clientSocket,
                        firstPacket = new byte[bytesReceived],
                        firstPacketLength = bytesReceived
                    };
                    Buffer.BlockCopy(arg.Saea.Buffer, 0, serviceToken.firstPacket, 0, bytesReceived);
                }
                else
                {
                    Logging.Error($"RecvFirstPacket socket err: {err},{bytesReceived}");
                    goto Shutdown;
                }
                _argsPool.Return(arg);
                arg = null;

                foreach (IService service in _services)
                {
                    if (service.Handle(serviceToken))
                    {
                        return;
                    }
                }
                Shutdown:
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
                _argsPool.Return(arg);
                arg = null;
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
        }
    }
}