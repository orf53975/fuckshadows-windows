using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Fuckshadows.Encryption;
using Fuckshadows.Encryption.AEAD;
using Fuckshadows.Encryption.Exception;
using Fuckshadows.Model;
using Fuckshadows.Util.Sockets;
using static Fuckshadows.Encryption.EncryptorBase;

namespace Fuckshadows.Controller
{
    class TCPRelay : Listener.Service
    {
        private FuckshadowsController _controller;
        private DateTime _lastSweepTime;
        private Configuration _config;
        public SaeaAwaitablePool _argsPool;
        public ISet<TCPHandler> Handlers { get; }
        public const int MAX_HANDLER_NUM = 4096;

        public const int CMD_CONNECT = 0x01;
        public const int CMD_UDP_ASSOC = 0x03;

        public static readonly byte[] Sock5HandshakeResponseReject = {0, 0x5B /* other bytes are ignored */};

        //+----+--------+
        //|VER | METHOD |
        //+----+--------+
        //| 1  |   1    |
        //+----+--------+
        public static readonly byte[] Sock5HandshakeResponseSuccess = {5, 0 /* no auth required */};

        //+----+-----+-------+------+----------+----------+
        //|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        //+----+-----+-------+------+----------+----------+
        //| 1  |  1  | X'00' |  1   | Variable |    2     |
        //+----+-----+-------+------+----------+----------+
        public static readonly byte[] Sock5ConnectRequestReplySuccess = {5, 0, 0, ATYP_IPv4, 0, 0, 0, 0, 0, 0};

        // IMPORTANT: choose RecvSize and BufferSize carefully, make sure AEAD and stream ciphers both work well
        public const int RecvSize = 4096;

        public const int BufferSize = RecvSize + (int) AEADEncryptor.MaxChunkSize + 32 /* max salt len */;

        public TCPRelay(FuckshadowsController controller, Configuration conf)
        {
            _controller = controller;
            _config = conf;
            Handlers = new HashSet<TCPHandler>();
            _lastSweepTime = DateTime.Now;
            InitArgsPool();
        }

        public override bool Handle(ServiceUserToken obj)
        {
            byte[] firstPacket = obj.firstPacket;
            int length = obj.firstPacketLength;
            Socket socket = obj.socket;
            if (socket == null) return false;
            if (socket.ProtocolType != ProtocolType.Tcp
                || (length < 2 || firstPacket[0] != 5))
                return false;
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            TCPHandler handler = new TCPHandler(_controller, _config, this, socket);

            IList<TCPHandler> handlersToClose = new List<TCPHandler>();
            lock (Handlers)
            {
                Handlers.Add(handler);
                DateTime now = DateTime.Now;
                if (now - _lastSweepTime > TimeSpan.FromSeconds(1))
                {
                    _lastSweepTime = now;
                    foreach (TCPHandler handler1 in Handlers)
                        if (now - handler1.lastActivity > TimeSpan.FromSeconds(900))
                            handlersToClose.Add(handler1);
                }
            }

            foreach (TCPHandler handler1 in handlersToClose)
            {
                Logging.Debug("Closing timed out TCP connection.");
                handler1.Close();
            }

            /*
             * Start after we put it into Handlers set. Otherwise if it failed in handler.Start()
             * then it will call handler.Close() before we add it into the set.
             * Then the handler will never release until the next Handle call. Sometimes it will
             * cause odd problems (especially during memory profiling).
             */
            handler.Start(firstPacket, length);
            IncrementTCPConnectionCounter();

            return true;
        }

        private void InitArgsPool()
        {
            _argsPool = SaeaAwaitablePoolManager.GetOrdinaryInstance();
        }

        public override void Stop()
        {
            List<TCPHandler> handlersToClose = new List<TCPHandler>();
            lock (Handlers)
            {
                handlersToClose.AddRange(Handlers);
            }
            handlersToClose.ForEach(h => h.Close());
        }

        public void UpdateInboundCounter(Server server, long n)
        {
            _controller.UpdateInboundCounter(server, n);
        }

        public void UpdateOutboundCounter(Server server, long n)
        {
            _controller.UpdateOutboundCounter(server, n);
        }

        public void IncrementTCPConnectionCounter()
        {
            _controller.IncrementTCPConnectionCounter();
        }

        public void DecrementTCPConnectionCounter()
        {
            _controller.DecrementTCPConnectionCounter();
        }
    }

    internal class TCPHandler
    {
        public DateTime lastActivity;

        private SaeaAwaitablePool _argsPool;
        private FuckshadowsController _controller;
        private Configuration _config;
        private TCPRelay _tcprelay;
        private Socket _localSocket;
        private Socket _serverSocket;

        private IEncryptor _encryptor;
        private Server _server;

        private byte[] _firstPacket;
        private int _firstPacketLength;

        private byte[] _remainingBytes;
        private int _remainingBytesLen;

        private byte[] _addrBuf;
        private int _addrBufLength = -1;

        // flags indicating client or remote shutdown socket
        private bool _localShutdown = false;

        private bool _remoteShutdown = false;

        // instance-based lock without static
        private readonly object _encryptionLock = new object();

        private readonly object _decryptionLock = new object();

        // parsed addr buf
        private EndPoint _destEndPoint = null;

        private int _state = _none;
        private const int _none = 0;
        private const int _running = 1;
        private const int _disposed = 5;

        public bool IsRunning => _state == _running;

        public TCPHandler(FuckshadowsController controller, Configuration config, TCPRelay tcprelay, Socket socket)
        {
            _controller = controller;
            _config = config;
            _tcprelay = tcprelay;
            _localSocket = socket;
            _argsPool = tcprelay._argsPool;

            lastActivity = DateTime.Now;
        }


        public void Start(byte[] firstPacket, int length)
        {
            Interlocked.Exchange(ref _state, _running);
            _firstPacket = firstPacket;
            _firstPacketLength = length;
            Task.Factory.StartNew(async () => { await HandshakeSendResponse(); }).Forget();
        }

        private async Task HandshakeSendResponse()
        {
            SaeaAwaitable tcpSaea = null;
            try
            {
                if (_firstPacketLength <= 1)
                {
                    Logging.Debug("Invalid first packet length");
                    Close();
                    return;
                }
                byte[] response = TCPRelay.Sock5HandshakeResponseSuccess;
                if (_firstPacket[0] != 5)
                {
                    // reject socks 4
                    response = TCPRelay.Sock5HandshakeResponseReject;
                    Logging.Error("socks 5 protocol error");
                }

                tcpSaea = _argsPool.Rent();
                tcpSaea.PrepareSAEABuffer(response, response.Length);
                var token = await _localSocket.FullSendTaskAsync(tcpSaea, response.Length);
                var err = token.SocketError;
                var bytesSent = token.BytesTotalTransferred;
                Logging.Debug($"HandshakeSendResponse: {err},{bytesSent}");
                if (err != SocketError.Success)
                {
                    Close();
                    return;
                }
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
                Debug.Assert(bytesSent == response.Length);
                Task.Factory.StartNew(async () => { await Sock5RequestRecv(); }).Forget();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
            }
            finally
            {
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
            }
        }

        private async Task Sock5RequestRecv()
        {
            SaeaAwaitable tcpSaea = null;
            try
            {
                tcpSaea = _argsPool.Rent();
                var token = await _localSocket.FullReceiveTaskAsync(tcpSaea, TCPRelay.RecvSize);
                var err = token.SocketError;
                var recvSize = token.BytesTotalTransferred;
                Logging.Debug($"Sock5RequestRecv: {err},{recvSize}");
                if (err != SocketError.Success)
                {
                    Close();
                    return;
                }

                var recvBuf = tcpSaea.Saea.Buffer;
                if (recvSize >= 5)
                {
                    byte _command = recvBuf[1];
                    if (_command != TCPRelay.CMD_CONNECT && _command != TCPRelay.CMD_UDP_ASSOC)
                    {
                        Logging.Debug("Unsupported CMD=" + _command);
                        Close();
                        return;
                    }


                    ParseAddrBuf(recvBuf, recvSize);

                    /* drop [ VER | CMD | RSV ] */
                    var totalTransferredWithoutLeading = recvSize - 3;
                    // save remaing
                    _remainingBytesLen = totalTransferredWithoutLeading - _addrBufLength;
                    if (_remainingBytesLen > 0)
                    {
                        _remainingBytes = new byte[_remainingBytesLen];
                        Buffer.BlockCopy(recvBuf, _addrBufLength, _remainingBytes, 0, _remainingBytesLen);
                    }
                    _argsPool.Return(tcpSaea);
                    tcpSaea = null;
                    // read address and call the corresponding method
                    if (_command == TCPRelay.CMD_CONNECT)
                    {
                        Task.Factory.StartNew(async () => { await Sock5ConnectResponseSend(); }).Forget();
                    }
                    else if (_command == TCPRelay.CMD_UDP_ASSOC)
                    {
                        Task.Factory.StartNew(async () => { await HandleUDPAssociate(); }).Forget();
                    }
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
            }
            finally
            {
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
            }
        }

        private async Task Sock5ConnectResponseSend()
        {
            SaeaAwaitable tcpSaea = null;
            try
            {
                tcpSaea = _argsPool.Rent();
                tcpSaea.PrepareSAEABuffer(TCPRelay.Sock5ConnectRequestReplySuccess,
                    TCPRelay.Sock5ConnectRequestReplySuccess.Length);
                var token = await _localSocket.FullSendTaskAsync(tcpSaea,
                    TCPRelay.Sock5ConnectRequestReplySuccess.Length);
                var err = token.SocketError;
                var bytesSent = token.BytesTotalTransferred;
                Logging.Debug($"Sock5ConnectResponseSend: {err},{bytesSent}");
                if (err != SocketError.Success)
                {
                    Close();
                    return;
                }
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
                Debug.Assert(bytesSent == TCPRelay.Sock5ConnectRequestReplySuccess.Length);
                Task.Factory.StartNew(async () => { await StartConnect(); }).Forget();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
            }
            finally
            {
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
            }
        }

        private void ParseAddrBuf(byte[] buf, int bufLen)
        {
            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+
            Logging.Debug("enter ParseAddrBuf");
            _addrBuf = buf.Skip(3).Take(bufLen - 3).ToArray();
            Logging.Dump("Sock5RequestRecv recvBuf", buf, bufLen);
            Logging.Dump(nameof(_addrBuf), _addrBuf, _addrBuf.Length);
            int atyp = _addrBuf[0];
            string dstAddr = "Unknown";
            int dstPort = -1;
            switch (atyp)
            {
                case ATYP_IPv4: // IPv4 address, 4 bytes
                    dstAddr = new IPAddress(_addrBuf.Skip(1).Take(4).ToArray()).ToString();
                    dstPort = (_addrBuf[5] << 8) + _addrBuf[6];

                    _addrBufLength = ADDR_ATYP_LEN + 4 + ADDR_PORT_LEN;
                    break;
                case ATYP_DOMAIN: // domain name, length + str
                    int len = _addrBuf[1];
                    dstAddr = System.Text.Encoding.UTF8.GetString(_addrBuf, 2, len);
                    dstPort = (_addrBuf[len + 2] << 8) + _addrBuf[len + 3];

                    _addrBufLength = ADDR_ATYP_LEN + 1 + len + ADDR_PORT_LEN;
                    break;
                case ATYP_IPv6: // IPv6 address, 16 bytes
                    dstAddr = $"[{new IPAddress(_addrBuf.Skip(1).Take(16).ToArray())}]";
                    dstPort = (_addrBuf[17] << 8) + _addrBuf[18];

                    _addrBufLength = ADDR_ATYP_LEN + 16 + ADDR_PORT_LEN;
                    break;
            }
            Logging.Debug(nameof(_addrBufLength) + " " + _addrBufLength);
            _destEndPoint = SocketUtil.GetEndPoint(dstAddr, dstPort);

            if (_config.isVerboseLogging)
            {
                Logging.Info($"AddrBuf: connect to {dstAddr}:{dstPort}");
            }
        }

        private async Task HandleUDPAssociate()
        {
            IPEndPoint endPoint = (IPEndPoint) _localSocket.LocalEndPoint;
            IPAddress endPointAddress = endPoint.Address;
            if (endPointAddress.IsIPv4MappedToIPv6) {
                endPointAddress = endPointAddress.MapToIPv4();
            }
            byte[] address = endPointAddress.GetAddressBytes();
            int port = endPoint.Port;
            byte[] response = new byte[4 + address.Length + ADDR_PORT_LEN];
            response[0] = 5;
            switch (endPointAddress.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    response[3] = ATYP_IPv4;
                    break;
                case AddressFamily.InterNetworkV6:
                    response[3] = ATYP_IPv6;
                    break;
            }
            Array.Copy(address, 0, response, 4, address.Length);
            response[response.Length - 1] = (byte) (port & 0xFF);
            response[response.Length - 2] = (byte) ((port >> 8) & 0xFF);

            SaeaAwaitable tcpSaea = null;
            SaeaAwaitable circularRecvSaea = null;
            try
            {
                tcpSaea = _argsPool.Rent();
                tcpSaea.PrepareSAEABuffer(response, response.Length);
                var token = await _localSocket.FullSendTaskAsync(tcpSaea, response.Length);
                var err = token.SocketError;
                var sentSize = token.BytesTotalTransferred;
                Logging.Debug($"Udp assoc local send: {err},{sentSize}");
                if (err != SocketError.Success)
                {
                    Close();
                    return;
                }
                Debug.Assert(sentSize == response.Length);
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
                circularRecvSaea = _argsPool.Rent();

                while (IsRunning)
                {
                    // UDP Assoc: Read all from socket and wait until client closes the connection
                    token = await _localSocket.FullReceiveTaskAsync(circularRecvSaea, TCPRelay.RecvSize);
                    Logging.Debug($"udp assoc local recv: {err}");
                    var ret = token.SocketError;
                    var bytesRecved = token.BytesTotalTransferred;
                    if (ret != SocketError.Success)
                    {
                        Logging.Error($"udp assoc: {ret},{bytesRecved}");
                        Close();
                        return;
                    }
                    if (bytesRecved <= 0)
                    {
                        Close();
                        return;
                    }
                    circularRecvSaea.ClearAndResetSaeaProperties();
                }
                _argsPool.Return(circularRecvSaea);
                circularRecvSaea = null;
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
            }
            finally
            {
                _argsPool.Return(tcpSaea);
                tcpSaea = null;
                _argsPool.Return(circularRecvSaea);
                circularRecvSaea = null;
            }
        }

        private void CreateRemote()
        {
            Server server = _controller.GetAServer((IPEndPoint) _localSocket.RemoteEndPoint,
                _destEndPoint);
            if (server == null || server.server == "")
                throw new ArgumentException("No server configured");

            _encryptor = EncryptorFactory.GetEncryptor(server.method, server.password);

            _server = server;

            /* prepare address buffer length for AEAD */
            Logging.Debug($"_addrBufLength={_addrBufLength}");
            _encryptor.AddrBufLength = _addrBufLength;
        }

        private async Task StartConnect()
        {
            SaeaAwaitable serverSaea = null;
            try
            {
                CreateRemote();

                _serverSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _serverSocket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                _serverSocket.SetTFO();

                // encrypt and attach encrypted buffer to ConnectAsync
                serverSaea = _argsPool.Rent();
                var realSaea = serverSaea.Saea;

                var encryptedbufLen = -1;
                Logging.Dump("StartConnect(): enc addrBuf", _addrBuf, _addrBufLength);
                DoEncrypt(_addrBuf, _addrBufLength, realSaea.Buffer, out encryptedbufLen);
                Logging.Debug("StartConnect(): addrBuf enc len " + encryptedbufLen);
                if (_remainingBytesLen > 0)
                {
                    Logging.Debug($"StartConnect(): remainingBytesLen: {_remainingBytesLen}");
                    var encRemainingBufLen = -1;
                    byte[] tmp = new byte[4096];
                    Logging.Dump("StartConnect(): enc remaining", _remainingBytes, _remainingBytesLen);
                    DoEncrypt(_remainingBytes, _remainingBytesLen, tmp, out encRemainingBufLen);
                    Logging.Debug("StartConnect(): remaining enc len " + encRemainingBufLen);
                    Buffer.BlockCopy(tmp, 0, realSaea.Buffer, encryptedbufLen, encRemainingBufLen);
                    encryptedbufLen += encRemainingBufLen;
                }
                Logging.Debug("actual enc buf len " + encryptedbufLen);
                realSaea.RemoteEndPoint = SocketUtil.GetEndPoint(_server.server, _server.server_port);
                realSaea.SetBuffer(0, encryptedbufLen);

                var err = await _serverSocket.ConnectAsync(serverSaea);
                if (err != SocketError.Success)
                {
                    Logging.Error($"StartConnect: {err}");
                    Close();
                    return;
                }
                Logging.Debug("remote connected");
                if (serverSaea.Saea.BytesTransferred != encryptedbufLen)
                {
                    // not sent all data, it may caused by TFO, disable it
                    Logging.Info("Disable TCP Fast Open due to initial send failure");
                    Program.DisableTFO();
                    Close();
                    return;
                }

                _argsPool.Return(serverSaea);
                serverSaea = null;

                if (_config.isVerboseLogging)
                {
                    Logging.Info($"Socket connected to ss server: {_server.FriendlyName()}");
                }

                Task.Factory.StartNew(StartPipe, TaskCreationOptions.PreferFairness).Forget();
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
                _argsPool.Return(serverSaea);
                serverSaea = null;
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
            SaeaAwaitable serverRecvSaea = null;
            SaeaAwaitable localSendSaea = null;
            try
            {
                while (IsRunning)
                {
                    serverRecvSaea = _argsPool.Rent();
                    var token = await _serverSocket.FullReceiveTaskAsync(serverRecvSaea, TCPRelay.RecvSize);
                    var err = token.SocketError;
                    var bytesRecved = token.BytesTotalTransferred;
                    Logging.Debug($"Downstream server recv: {err},{bytesRecved}");

                    if (IsShutdown(token))
                    {
                        //lock (_closeConnLock)
                        //{
                        _localSocket.Shutdown(SocketShutdown.Send);
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
                    Debug.Assert(bytesRecved <= TCPRelay.RecvSize);
                    _tcprelay.UpdateInboundCounter(_server, bytesRecved);
                    lastActivity = DateTime.Now;

                    localSendSaea = _argsPool.Rent();
                    int decBufLen = -1;
                    lock (_decryptionLock)
                    {
                        DoDecrypt(serverRecvSaea.Saea.Buffer,
                            bytesRecved,
                            localSendSaea.Saea.Buffer,
                            out decBufLen);
                    }
                    _argsPool.Return(serverRecvSaea);
                    serverRecvSaea = null;

                    token = await _localSocket.FullSendTaskAsync(localSendSaea, decBufLen);
                    err = token.SocketError;
                    var bytesSent = token.BytesTotalTransferred;
                    Logging.Debug($"Downstream local send socket err: {err},{bytesSent}");
                    if (err != SocketError.Success)
                    {
                        Close();
                        return;
                    }
                    _argsPool.Return(localSendSaea);
                    localSendSaea = null;
                    Debug.Assert(bytesSent == decBufLen);
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
                _argsPool.Return(serverRecvSaea);
                serverRecvSaea = null;
                _argsPool.Return(localSendSaea);
                localSendSaea = null;
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
                    var token = await _localSocket.FullReceiveTaskAsync(localRecvSaea, TCPRelay.RecvSize);
                    var err = token.SocketError;
                    var bytesRecved = token.BytesTotalTransferred;
                    Logging.Debug($"Upstream local recv: {err},{bytesRecved}");
                    if (IsShutdown(token))
                    {
                        //lock (_closeConnLock)
                        //{
                        _serverSocket.Shutdown(SocketShutdown.Send);
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
                    Debug.Assert(bytesRecved <= TCPRelay.RecvSize);

                    serverSendSaea = _argsPool.Rent();
                    int encBufLen = -1;
                    lock (_encryptionLock)
                    {
                        DoEncrypt(localRecvSaea.Saea.Buffer,
                            bytesRecved,
                            serverSendSaea.Saea.Buffer,
                            out encBufLen);
                    }
                    _argsPool.Return(localRecvSaea);
                    localRecvSaea = null;

                    _tcprelay.UpdateOutboundCounter(_server, encBufLen);

                    token = await _serverSocket.FullSendTaskAsync(serverSendSaea, encBufLen);
                    err = token.SocketError;
                    var bytesSent = token.BytesTotalTransferred;
                    Logging.Debug($"Upstream server send: {err},{bytesSent}");
                    if (err != SocketError.Success)
                    {
                        Close();
                        return;
                    }
                    _argsPool.Return(serverSendSaea);
                    serverSendSaea = null;
                    Debug.Assert(bytesSent == encBufLen);
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
                _argsPool.Return(localRecvSaea);
                localRecvSaea = null;
                _argsPool.Return(serverSendSaea);
                serverSendSaea = null;
            }
        }

        private static bool IsShutdown(SocketExtensions.TcpTrafficToken token)
        {
            var err = token.SocketError;
            var bytesTransferred = token.BytesTotalTransferred;
            return err == SocketError.Success && bytesTransferred <= 0;
        }

        #region Enc/Dec Worker

        private void DoEncrypt(byte[] inBuf, int inLen, byte[] outBuf, out int outLen)
        {
            int bytesOut = -1;
            try
            {
                _encryptor.Encrypt(inBuf, inLen, outBuf, out bytesOut);
            }
            catch (CryptoErrorException)
            {
                Logging.Debug("encryption error");
                throw;
            }
            outLen = bytesOut;
        }

        private void DoDecrypt(byte[] inBuf, int inLen, byte[] outBuf, out int outLen)
        {
            int bytesOut = -1;
            try
            {
                _encryptor.Decrypt(inBuf, inLen, outBuf, out bytesOut);
            }
            catch (CryptoErrorException e)
            {
                Logging.LogUsefulException(e);
                throw;
            }
            outLen = bytesOut;
        }

        #endregion

        #region Close Connection

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

            lock (_tcprelay.Handlers)
            {
                _tcprelay.Handlers.Remove(this);
            }
            Logging.Debug("Closing local and server socket");
            Logging.Debug($"_localShutdown: {_localShutdown} _remoteShutdown: {_remoteShutdown}");
            try
            {
                _localSocket?.Shutdown(SocketShutdown.Both);
                _localSocket?.Close();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }

            try
            {
                _serverSocket?.Shutdown(SocketShutdown.Both);
                _serverSocket?.Close();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }

            lock (_encryptionLock)
            {
                lock (_decryptionLock)
                {
                    _encryptor?.Dispose();
                }
            }

            _tcprelay.DecrementTCPConnectionCounter();
        }

        #endregion
    }
}