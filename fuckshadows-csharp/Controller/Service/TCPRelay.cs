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
using Fuckshadows.Model;
using Fuckshadows.Util.Sockets;
using Fuckshadows.Util.Sockets.Buffer;
using static Fuckshadows.Encryption.EncryptorBase;

namespace Fuckshadows.Controller
{
    class TCPRelay : Listener.Service
    {
        private FuckshadowsController _controller;
        private DateTime _lastSweepTime;
        private Configuration _config;
        public ISegmentBufferManager _segmentBufferManager;
        public ISet<TCPHandler> Handlers { get; }

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

        // max size for single receive operation
        public const int RecvSize = 4096;

        // IMPORTANT: choose size carefully, make sure AEAD and stream ciphers both work well
        //            and we have enough space to handle chunks
        public const int BufferSize = 5 * (RecvSize + (int) AEADEncryptor.MaxChunkSize + 32 /* max salt len */);

        public TCPRelay(FuckshadowsController controller, Configuration conf)
        {
            _controller = controller;
            _config = conf;
            Handlers = new HashSet<TCPHandler>();
            _lastSweepTime = DateTime.Now;
            _segmentBufferManager = new SegmentBufferManager(2048, BufferSize);
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

        private ISegmentBufferManager _segmentBufferManager;
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
            _segmentBufferManager = tcprelay._segmentBufferManager;

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

                var responseSeg = response.AsArraySegment(0, response.Length);
                var bytesSent = await _localSocket.FullSendTaskAsync(responseSeg, response.Length);
                Logging.Debug($"HandshakeSendResponse: {bytesSent}");
                if (bytesSent <= 0)
                {
                    Close();
                    return;
                }

                Debug.Assert(bytesSent == response.Length);
                Task.Factory.StartNew(async () => { await Sock5RequestRecv(); }).Forget();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
            }
        }

        private async Task Sock5RequestRecv()
        {
            try
            {
                var token = await _localSocket.FullReceiveTaskAsync(TCPRelay.RecvSize);
                var recvSize = token.BytesTotal;
                Logging.Debug($"Sock5RequestRecv: {recvSize}");
                if (recvSize <= 0)
                {
                    Close();
                    return;
                }

                var recvBuf = token.PayloadBytes;
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
        }

        private async Task Sock5ConnectResponseSend()
        {
            try
            {
                var bytesSent = await _localSocket.FullSendTaskAsync(
                    TCPRelay.Sock5ConnectRequestReplySuccess.AsArraySegment(0, TCPRelay.Sock5ConnectRequestReplySuccess.Length),
                    TCPRelay.Sock5ConnectRequestReplySuccess.Length);
                Logging.Debug($"Sock5ConnectResponseSend: {bytesSent}");
                if (bytesSent <= 0)
                {
                    Close();
                    return;
                }

                Debug.Assert(bytesSent == TCPRelay.Sock5ConnectRequestReplySuccess.Length);
                Task.Factory.StartNew(async () => { await StartConnect(); }).Forget();
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
                Close();
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
            Logging.DumpByteArray("Sock5RequestRecv recvBuf", buf, bufLen);
            Logging.DumpByteArray(nameof(_addrBuf), _addrBuf, _addrBuf.Length);
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

            ArraySegment<byte> buf = default(ArraySegment<byte>);
            try
            {
                buf = _segmentBufferManager.BorrowBuffer();
                var responseSeg = response.AsArraySegment(0, response.Length);
                var sentSize = await _localSocket.FullSendTaskAsync(responseSeg, response.Length);

                Logging.Debug($"Udp assoc local send: {sentSize}");
                if (sentSize <= 0)
                {
                    Close();
                    return;
                }
                Debug.Assert(sentSize == response.Length);

                while (IsRunning)
                {
                    // UDP Assoc: Read all from socket and wait until client closes the connection
                    var bytesRecved = await _localSocket.ReceiveAsync(buf, SocketFlags.None);

                    if (bytesRecved <= 0)
                    {
                        if (bytesRecved != 0)
                            Logging.Error($"udp assoc: {bytesRecved}");
                        Close();
                        return;
                    }
                }
                _segmentBufferManager.ReturnBuffer(buf);
                buf = default(ArraySegment<byte>);
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

        // XXX: use SAEA to utilize TFO instead of the SocketTaskExtensions class
        private async Task StartConnect()
        {
            ArraySegment<byte> addrEncBuf = default(ArraySegment<byte>);
            ArraySegment<byte> remainingEncBuf = default(ArraySegment<byte>);
            try
            {
                CreateRemote();

                addrEncBuf = _segmentBufferManager.BorrowBuffer();
                

                _serverSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _serverSocket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);

                var encryptedbufLen = -1;
                Logging.DumpByteArray("StartConnect(): enc addrBuf", _addrBuf, _addrBufLength);
                var addrBufSeg = _addrBuf.AsArraySegment(0, _addrBufLength);
                lock (_encryptionLock)
                {
                    _encryptor.Encrypt(addrBufSeg, _addrBufLength, addrEncBuf, out encryptedbufLen);
                }
                Logging.Debug("StartConnect(): addrBuf enc len " + encryptedbufLen);
                if (_remainingBytesLen > 0)
                {
                    Logging.Debug($"StartConnect(): remainingBytesLen: {_remainingBytesLen}");
                    var remainingBuf = _remainingBytes.AsArraySegment(0, _remainingBytesLen);
                    remainingEncBuf = _segmentBufferManager.BorrowBuffer();
                    var encRemainingBufLen = -1;
                    Logging.DumpByteArray("StartConnect(): enc remaining", _remainingBytes, _remainingBytesLen);
                    lock (_encryptionLock)
                    {
                        _encryptor.Encrypt(remainingBuf, _remainingBytesLen, remainingEncBuf, out encRemainingBufLen);
                    }
                    Logging.Debug("StartConnect(): remaining enc len " + encRemainingBufLen);
                    ArraySegmentExtensions.BlockCopy(remainingEncBuf, 0, addrEncBuf, encryptedbufLen, encRemainingBufLen);
                    encryptedbufLen += encRemainingBufLen;

                    _segmentBufferManager.ReturnBuffer(remainingEncBuf);
                    remainingEncBuf = default(ArraySegment<byte>);

                }
                Logging.Debug("actual enc buf len " + encryptedbufLen);

                // TODO: use SAEA for TFO
                await _serverSocket.ConnectAsync(SocketUtil.GetEndPoint(_server.server, _server.server_port));

                var bytesSent = await _serverSocket.FullSendTaskAsync(addrEncBuf, encryptedbufLen);
                if (bytesSent <= 0)
                {
                    Logging.Error($"StartConnect: {bytesSent}");
                    Close();
                    return;
                }
                Logging.Debug("remote connected");

                if (_config.isVerboseLogging)
                {
                    Logging.Info($"Socket connected to ss server: {_server.FriendlyName()}");
                }

                _segmentBufferManager.ReturnBuffer(addrEncBuf);
                addrEncBuf = default(ArraySegment<byte>);

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
                if (addrEncBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(addrEncBuf);
                    addrEncBuf = default(ArraySegment<byte>);
                }

                if (remainingEncBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(remainingEncBuf);
                    remainingEncBuf = default(ArraySegment<byte>);
                }
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
            ArraySegment<byte> serverRecvBuf = default(ArraySegment<byte>);
            ArraySegment<byte> localSendBuf = default(ArraySegment<byte>);
            try
            {
                while (IsRunning)
                {
                    serverRecvBuf = _segmentBufferManager.BorrowBuffer();
                    var bytesRecved = await _serverSocket.ReceiveAsync(serverRecvBuf, SocketFlags.None);
                    Logging.Debug($"Downstream server recv: {bytesRecved}");

                    if (bytesRecved == 0)
                    {
                        _localSocket.Shutdown(SocketShutdown.Send);
                        _localShutdown = true;
                        CheckClose();
                        return;
                    }
                    else if (bytesRecved < 0)
                    {
                        Logging.Debug($"Downstream server recv socket err: {bytesRecved}");
                        Close();
                        return;
                    }
                    Debug.Assert(bytesRecved <= TCPRelay.RecvSize);
                    _tcprelay.UpdateInboundCounter(_server, bytesRecved);
                    lastActivity = DateTime.Now;
                    localSendBuf = _segmentBufferManager.BorrowBuffer();

                    int decBufLen = -1;
                    lock (_decryptionLock)
                    {
                        _encryptor.Decrypt(serverRecvBuf,
                            bytesRecved,
                            localSendBuf,
                            out decBufLen);
                    }

                    _segmentBufferManager.ReturnBuffer(serverRecvBuf);
                    serverRecvBuf = default(ArraySegment<byte>);

                    // AEAD: if we need more to decrypt, keep receiving from remote
                    if (decBufLen <= 0) continue;

                    var bytesSent = await _localSocket.FullSendTaskAsync(localSendBuf, decBufLen);

                    Logging.Debug($"Downstream local send socket err: {bytesSent}");
                    if (bytesSent <= 0)
                    {
                        Close();
                        return;
                    }

                    Debug.Assert(bytesSent == decBufLen);
                    _segmentBufferManager.ReturnBuffer(localSendBuf);
                    localSendBuf = default(ArraySegment<byte>);
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
                if (serverRecvBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(serverRecvBuf);
                    serverRecvBuf = default(ArraySegment<byte>);
                }
                if (localSendBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(localSendBuf);
                    localSendBuf = default(ArraySegment<byte>);
                }
            }
        }

        // local recv -> server send
        private async Task Upstream()
        {
            ArraySegment<byte> localRecvBuf = default(ArraySegment<byte>);
            ArraySegment<byte> serverSendBuf = default(ArraySegment<byte>);
            try
            {
                while (IsRunning)
                {
                    localRecvBuf = _segmentBufferManager.BorrowBuffer();
                    var bytesRecved = await _localSocket.ReceiveAsync(localRecvBuf, SocketFlags.None);
                    Logging.Debug($"Upstream local recv: {bytesRecved}");
                    if (bytesRecved == 0)
                    {
                        _serverSocket.Shutdown(SocketShutdown.Send);
                        _remoteShutdown = true;
                        CheckClose();
                        return;
                    }
                    else if (bytesRecved < 0)
                    {
                        Logging.Debug($"Upstream local recv socket err: {bytesRecved}");
                        Close();
                        return;
                    }
                    Debug.Assert(bytesRecved <= TCPRelay.RecvSize);

                    serverSendBuf = _segmentBufferManager.BorrowBuffer();

                    int encBufLen = -1;
                    lock (_encryptionLock)
                    {
                        _encryptor.Encrypt(localRecvBuf,
                            bytesRecved,
                            serverSendBuf,
                            out encBufLen);
                    }

                    _segmentBufferManager.ReturnBuffer(localRecvBuf);
                    localRecvBuf = default(ArraySegment<byte>);

                    _tcprelay.UpdateOutboundCounter(_server, encBufLen);

                    var bytesSent = await _serverSocket.FullSendTaskAsync(serverSendBuf, encBufLen);

                    Logging.Debug($"Upstream server send: {bytesSent}");
                    if (bytesSent <= 0)
                    {
                        Close();
                        return;
                    }
                    
                    Debug.Assert(bytesSent == encBufLen);

                    _segmentBufferManager.ReturnBuffer(serverSendBuf);
                    serverSendBuf = default(ArraySegment<byte>);
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
                if (localRecvBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(localRecvBuf);
                    localRecvBuf = default(ArraySegment<byte>);
                }
                if (serverSendBuf != default(ArraySegment<byte>))
                {
                    _segmentBufferManager.ReturnBuffer(serverSendBuf);
                    serverSendBuf = default(ArraySegment<byte>);
                }
            }
        }

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