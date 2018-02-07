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
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Controller
{
    public partial class Listener
    {
        private Configuration _config;
        private bool _shareOverLan;
        private Socket _tcpListenerSocket;
        private Socket _udpSocket;
        private readonly List<IService> _services;

        public const int BACKLOG = 1024;
        private const int MaxFirstPacketLen = 4096;

        private ISegmentBufferManager _segmentBufferManager;

        private int _state = _none;
        private const int _none = 0;
        private const int _listening = 1;
        private const int _disposed = 5;

        public bool IsListening => _state == _listening;

        public Listener(List<IService> services)
        {
            this._services = services;
            _segmentBufferManager = new SegmentBufferManager(1024, MaxFirstPacketLen, 2);
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
                // Create a TCP/IP socket.
                // XXX: this constructor will create a IPv6 socket with dual mode enabled
                _tcpListenerSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _tcpListenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

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
            ArraySegment<byte> buf = default(ArraySegment<byte>);
            try
            {
                while (IsListening)
                {
                    var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    buf = _segmentBufferManager.BorrowBuffer();
                    var result = await _udpSocket.ReceiveFromAsync(buf, SocketFlags.None, remoteEndPoint);
                    var bytesRecved = result.ReceivedBytes;
                    if (bytesRecved > 0)
                    {
                        ServiceUserToken token = new ServiceUserToken
                        {
                            socket = _udpSocket,
                            firstPacket = buf.ToByteArray(bytesRecved),
                            firstPacketLength = bytesRecved,
                            remoteEndPoint = result.RemoteEndPoint
                        };

                        Task.Factory.StartNew(() => HandleUDPServices(token)).Forget();
                    }
                    else
                    {
                        Logging.Error($"RecvFrom: {bytesRecved}");
                    }

                    _segmentBufferManager.ReturnBuffer(buf);
                    buf = default(ArraySegment<byte>);
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
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
            try
            {
                while (IsListening)
                {
                    var socket = await _tcpListenerSocket.AcceptAsync();
                    Logging.Debug("accepted a connection");
                    Task.Factory.StartNew(async () => { await RecvFirstPacket(socket); },
                         TaskCreationOptions.PreferFairness).Forget();
                }
            }
            catch (Exception ex)
            {
                Logging.LogUsefulException(ex);
            }
        }

        private async Task RecvFirstPacket(Socket clientSocket)
        {
            ArraySegment<byte> buf = default(ArraySegment<byte>);
            try
            {
                // Full receive here to get the whole first packet and parse it in single operation
                buf = _segmentBufferManager.BorrowBuffer();
                var token = await clientSocket.FullReceiveTaskAsync(MaxFirstPacketLen);
                var bytesReceived = token.BytesTotal;
                ServiceUserToken serviceToken = null;
                Logging.Debug($"RecvFirstPacket: {bytesReceived}");
                if (bytesReceived > 0)
                {
                    serviceToken = new ServiceUserToken
                    {
                        socket = clientSocket,
                        firstPacket = token.PayloadBytes,
                        firstPacketLength = bytesReceived
                    };
                }
                else
                {
                    Logging.Error($"RecvFirstPacket socket err: {bytesReceived}");
                    goto Shutdown;
                }

                _segmentBufferManager.ReturnBuffer(buf);
                buf = default(ArraySegment<byte>);

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
                if (buf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(buf);
                    buf = default(ArraySegment<byte>);
                }
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