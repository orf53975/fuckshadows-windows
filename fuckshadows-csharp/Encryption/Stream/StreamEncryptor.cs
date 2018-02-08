using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Fuckshadows.Encryption.CircularBuffer;
using Fuckshadows.Controller;
using Fuckshadows.Util.Sockets.Buffer;
using static Fuckshadows.Util.Utils;

namespace Fuckshadows.Encryption.Stream
{
    public abstract class StreamEncryptor
        : EncryptorBase
    {
        // for UDP only
        protected static byte[] _udpTmpBuf = new byte[65536];

        // every connection should create its own buffer
        private ByteCircularBuffer _encCircularBuffer = new ByteCircularBuffer(TCPRelay.BufferSize);
        private ByteCircularBuffer _decCircularBuffer = new ByteCircularBuffer(TCPRelay.BufferSize);

        protected Dictionary<string, EncryptorInfo> ciphers;

        protected byte[] _encryptIV;
        protected byte[] _decryptIV;

        // Is first packet
        protected bool _decryptIVReceived;
        protected bool _encryptIVSent;

        protected string _method;
        protected int _cipher;
        // internal name in the crypto library
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        // long-time master key
        protected static byte[] _key = null;
        protected int keyLen;
        protected int ivLen;

        public StreamEncryptor(ISegmentBufferManager bm, string method, string password)
            : base(bm, method, password)
        {
            InitEncryptorInfo(method);
            InitKey(password);
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        private void InitEncryptorInfo(string method)
        {
            method = method.ToLower();
            _method = method;
            ciphers = getCiphers();
            CipherInfo = ciphers[_method];
            _innerLibName = CipherInfo.InnerLibName;
            _cipher = CipherInfo.Type;
            if (_cipher == 0) {
                throw new System.Exception("method not found");
            }
            keyLen = CipherInfo.KeySize;
            ivLen = CipherInfo.IvSize;
        }

        private void InitKey(string password)
        {
            byte[] passbuf = Encoding.UTF8.GetBytes(password);
            if (_key == null) _key = new byte[keyLen];
            if (_key.Length != keyLen) Array.Resize(ref _key, keyLen);
            LegacyDeriveKey(passbuf, _key, keyLen);
        }

        public static void LegacyDeriveKey(byte[] password, byte[] key, int keylen)
        {
            byte[] result = new byte[password.Length + MD5_LEN];
            int i = 0;
            byte[] md5sum = null;
            while (i < keylen) {
                if (i == 0) {
                    md5sum = MbedTLS.MD5(password);
                } else {
                    Array.Copy(md5sum, 0, result, 0, MD5_LEN);
                    Array.Copy(password, 0, result, MD5_LEN, password.Length);
                    md5sum = MbedTLS.MD5(result);
                }
                Array.Copy(md5sum, 0, key, i, Math.Min(MD5_LEN, keylen - i));
                i += MD5_LEN;
            }
        }

        protected virtual void initCipher(ArraySegment<byte> iv, bool isEncrypt)
        {
            if (isEncrypt) {
                _encryptIV = new byte[ivLen];
                Buffer.BlockCopy(iv.Array,iv.Offset, _encryptIV,0, ivLen);
            } else {
                _decryptIV = new byte[ivLen];
                Buffer.BlockCopy(iv.Array,iv.Offset, _decryptIV, 0,ivLen);
            }
        }

        protected abstract void cipherUpdate(bool isEncrypt, int length, ArraySegment<byte> buf, ArraySegment<byte> outbuf);

        protected static void randBytes(ArraySegment<byte> buf, int length) { RNG.GetBytes(buf.Array,buf.Offset, length); }

        #region TCP

        public override void Encrypt(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            int cipherOffset = 0;
            Debug.Assert(_encCircularBuffer != null, "_encCircularBuffer != null");
            _encCircularBuffer.Put(buf.Array, buf.Offset, length);
            if (! _encryptIVSent) {
                // Generate IV
                byte[] ivBytes = new byte[ivLen];
                var ivSeg = ivBytes.AsArraySegment(0, ivLen);
                randBytes(ivSeg, ivLen);
                initCipher(ivSeg, true);
                
                ArraySegmentExtensions.BlockCopy(ivSeg, 0, outbuf, 0, ivLen);
                cipherOffset = ivLen;
                _encryptIVSent = true;
            }
            int size = _encCircularBuffer.Size;
            byte[] plain = _encCircularBuffer.Get(size);
            byte[] cipher = new byte[size];
            var cipherSeg = cipher.AsArraySegment();
            cipherUpdate(true, size, plain.AsArraySegment(), cipherSeg);
            ArraySegmentExtensions.BlockCopy(cipherSeg, 0, outbuf, cipherOffset, size);
            outlength = size + cipherOffset;
        }

        public override void Decrypt(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            Debug.Assert(_decCircularBuffer != null, "_circularBuffer != null");
            _decCircularBuffer.Put(buf.Array, buf.Offset, length);
            if (! _decryptIVReceived) {
                if (_decCircularBuffer.Size <= ivLen) {
                    // we need more data
                    outlength = 0;
                    return;
                }
                // start decryption
                _decryptIVReceived = true;
                byte[] iv = _decCircularBuffer.Get(ivLen);
                initCipher(iv.AsArraySegment(), false);
            }
            byte[] cipher = _decCircularBuffer.ToArray();
            var cipherSeg = cipher.AsArraySegment();
            cipherUpdate(false, cipher.Length, cipherSeg, outbuf);
            // move pointer only
            _decCircularBuffer.Skip(_decCircularBuffer.Size);
            outlength = cipher.Length;
            // done the decryption
        }

        #endregion

        #region UDP

        public override void EncryptUDP(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            // Generate IV
            randBytes(outbuf, ivLen);
            initCipher(outbuf, true);
            lock (_udpTmpBuf)
            {
                var tmpSeg = _udpTmpBuf.AsArraySegment();
                cipherUpdate(true, length, buf, tmpSeg);
                outlength = length + ivLen;
                ArraySegmentExtensions.BlockCopy(tmpSeg, 0, outbuf, ivLen, length);
            }
        }

        public override void DecryptUDP(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            // Get IV from first pos
            initCipher(buf, false);
            outlength = length - ivLen;
            lock (_udpTmpBuf) {
                // C# could be multi-threaded
                var tmpSeg = _udpTmpBuf.AsArraySegment();
                ArraySegmentExtensions.BlockCopy(buf, ivLen, tmpSeg, 0, length - ivLen);
                cipherUpdate(false, length - ivLen, tmpSeg, outbuf);
            }
        }

        #endregion
    }
}