﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using Fuckshadows.Encryption.CircularBuffer;
using Fuckshadows.Controller;
using Fuckshadows.Encryption.Exception;
using static Fuckshadows.Util.Utils;

namespace Fuckshadows.Encryption.AEAD
{
    public abstract class AEADEncryptor
        : EncryptorBase
    {
        // We are using the same saltLen and keyLen
        private const string Personal = "fuckshadows-g3nk";
        private static readonly byte[] PersonalBytes = Encoding.ASCII.GetBytes(Personal);

        // for UDP only
        protected static byte[] _udpTmpBuf = new byte[65536];

        // every connection should create its own buffer
        private ByteCircularBuffer _encCircularBuffer = new ByteCircularBuffer(MAX_INPUT_SIZE * 2);
        private ByteCircularBuffer _decCircularBuffer = new ByteCircularBuffer(MAX_INPUT_SIZE * 2);

        public const int CHUNK_LEN_BYTES = 2;
        public const uint CHUNK_LEN_MASK = 0x3FFFu;
        public const uint CHUNK_MAX_LEN_WITH_GARBAGE = CHUNK_LEN_MASK - FS_MAX_GARBAGE;
        public const int FS_MAX_GARBAGE = 255 + FS_GARBAGE_LEN;
        public const int FS_GARBAGE_LEN = 1;

        // overhead of one chunk, reserved for AEAD ciphers
        public const int ChunkOverheadSize = 16 * 2 /* two tags */ + CHUNK_LEN_BYTES;

        // max chunk size
        public const uint MaxChunkSize = CHUNK_LEN_MASK + CHUNK_LEN_BYTES + 16 * 2;

        public const int DefaultMSS = 536;

        // For TFO, ensure no fragmentation in initial send
        public const int MaxInitGarbageLen = DefaultMSS - (1 + 1 + 255 + 2) /* addrbuf max domain len */ - ChunkOverheadSize - 32 /* salt len */;

        protected Dictionary<string, EncryptorInfo> ciphers;

        protected string _method;
        protected int _cipher;
        // internal name in the crypto library
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        protected static byte[] _Masterkey = null;
        protected byte[] _sessionKey;
        protected int keyLen;
        protected int saltLen;
        protected int tagLen;
        protected int nonceLen;

        protected byte[] _encryptSalt;
        protected byte[] _decryptSalt;

        protected byte[] _encNonce;
        protected byte[] _decNonce;
        // Is first packet
        protected bool _decryptSaltReceived;
        protected bool _encryptSaltSent;

        // Is first chunk(tcp request)
        protected bool _tcpRequestSent;

        // zero-length garbage
        protected static readonly byte[] ZeroGarbageBytes = {0 /* length indicator */};

        public AEADEncryptor(string method, string password)
            : base(method, password)
        {
            InitEncryptorInfo(method);
            InitKey(password);
            // Initialize all-zero nonce for each connection
            _encNonce = new byte[nonceLen];
            _decNonce = new byte[nonceLen];
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        protected void InitEncryptorInfo(string method)
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
            saltLen = CipherInfo.SaltSize;
            tagLen = CipherInfo.TagSize;
            nonceLen = CipherInfo.NonceSize;
        }

        protected void InitKey(string password)
        {
            byte[] passbuf = Encoding.UTF8.GetBytes(password);
            // init master key
            if (_Masterkey == null) _Masterkey = new byte[keyLen];
            if (_Masterkey.Length != keyLen) Array.Resize(ref _Masterkey, keyLen);
            DeriveKey(passbuf, _Masterkey, keyLen);
            // init session key
            if (_sessionKey == null) _sessionKey = new byte[keyLen];
        }

        public void DeriveKey(byte[] password, byte[] key, int keylen)
        {
            int ret = Sodium.crypto_generichash(key, keylen, password, (ulong) password.Length, null, 0);
            if (ret != 0) throw new System.Exception("failed to generate hash");
        }

        public void DeriveSessionKey(byte[] salt, byte[] masterKey, byte[] sessionKey)
        {
            int ret = Sodium.crypto_generichash_blake2b_salt_personal(sessionKey, keyLen, null, 0, masterKey,
                                                                      keyLen, salt, PersonalBytes);
            if (ret != 0) throw new System.Exception("failed to generate session key");
        }

        protected void IncrementNonce(bool isEncrypt)
        {
            Sodium.sodium_increment(isEncrypt ? _encNonce : _decNonce, nonceLen);
        }

        public virtual void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            if (isEncrypt) {
                _encryptSalt = new byte[saltLen];
                Array.Copy(salt, _encryptSalt, saltLen);
            } else {
                _decryptSalt = new byte[saltLen];
                Array.Copy(salt, _decryptSalt, saltLen);
            }
            Logging.Dump("Salt", salt, saltLen);
        }

        public static void randBytes(byte[] buf, int length) { RNG.GetBytes(buf, length); }

        public abstract void cipherEncrypt(byte[] plaintext, uint plen, byte[] ciphertext, ref uint clen);

        public abstract void cipherDecrypt(byte[] ciphertext, uint clen, byte[] plaintext, ref uint plen);

        #region TCP

        public override void Encrypt(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            Debug.Assert(_encCircularBuffer != null, "_encCircularBuffer != null");

            _encCircularBuffer.Put(buf, 0, length);
            outlength = 0;
            Logging.Debug("---Start Encryption");
            if (! _encryptSaltSent) {
                _encryptSaltSent = true;
                // Generate salt
                byte[] saltBytes = new byte[saltLen];
                randBytes(saltBytes, saltLen);
                InitCipher(saltBytes, true, false);
                Array.Copy(saltBytes, 0, outbuf, 0, saltLen);
                outlength = saltLen;
                Logging.Debug($"_encryptSaltSent outlength {outlength}");
            }

            if (! _tcpRequestSent) {
                _tcpRequestSent = true;
                // The first TCP request
                int encAddrBufLength;

                byte[] garbage = GetGarbage(AddrBufLength, true);
                Logging.Debug("garbage len: " + garbage.Length);

                byte[] encAddrBufBytes = new byte[garbage.Length + AddrBufLength + tagLen * 2 + CHUNK_LEN_BYTES];
                byte[] addrBytes = _encCircularBuffer.Get(AddrBufLength);
                byte[] addrWithGarbage = new byte[AddrBufLength + garbage.Length];
                PerfByteCopy(garbage, 0, addrWithGarbage, 0, garbage.Length);
                PerfByteCopy(addrBytes, 0, addrWithGarbage, garbage.Length, AddrBufLength);
                ChunkEncrypt(addrWithGarbage, AddrBufLength + garbage.Length, encAddrBufBytes, out encAddrBufLength);
                Debug.Assert(encAddrBufLength == garbage.Length + AddrBufLength + tagLen * 2 + CHUNK_LEN_BYTES);
                Array.Copy(encAddrBufBytes, 0, outbuf, outlength, encAddrBufLength);
                outlength += encAddrBufLength;
                Logging.Debug($"_tcpRequestSent outlength {outlength}");
            }

            // handle other chunks
            while (true) {
                uint bufSize = (uint)_encCircularBuffer.Size;
                if (bufSize <= 0) return;
                var chunklength = (int)Math.Min(bufSize, CHUNK_MAX_LEN_WITH_GARBAGE);
                byte[] chunkBytes = _encCircularBuffer.Get(chunklength);

                byte[] garbage = GetGarbage(chunklength, false);
                int garbageLength = garbage.Length;
                Logging.Debug("garbage len: " + garbageLength);
                byte[] chunkWithGarbage = new byte[chunklength + garbageLength];
                PerfByteCopy(garbage, 0, chunkWithGarbage, 0, garbageLength);
                PerfByteCopy(chunkBytes, 0, chunkWithGarbage, garbageLength, chunklength);
                chunklength += garbageLength;

                int encChunkLength;
                byte[] encChunkBytes = new byte[chunklength + tagLen * 2 + CHUNK_LEN_BYTES];
                ChunkEncrypt(chunkWithGarbage, chunklength, encChunkBytes, out encChunkLength);
                Debug.Assert(encChunkLength == chunklength + tagLen * 2 + CHUNK_LEN_BYTES);
                PerfByteCopy(encChunkBytes, 0, outbuf, outlength, encChunkLength);
                outlength += encChunkLength;
                Logging.Debug("chunks enc outlength " + outlength);
                bufSize = (uint)_encCircularBuffer.Size;
                if (bufSize <= 0) {
                    Logging.Debug("No more data to encrypt, leaving");
                    return;
                }
            }
        }


        public override void Decrypt(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            Debug.Assert(_decCircularBuffer != null, "_decCircularBuffer != null");
            int bufSize;
            outlength = 0;
            // drop all into buffer
            _decCircularBuffer.Put(buf, 0, length);

            Logging.Debug("---Start Decryption");
            if (! _decryptSaltReceived) {
                bufSize = _decCircularBuffer.Size;
                // check if we get the leading salt
                if (bufSize <= saltLen) {
                    // need more
                    return;
                }
                _decryptSaltReceived = true;
                byte[] salt = _decCircularBuffer.Get(saltLen);
                InitCipher(salt, false, false);
                Logging.Debug("get salt len " + saltLen);
            }

            // handle chunks
            while (true) {
                bufSize = _decCircularBuffer.Size;
                // check if we have any data
                if (bufSize <= 0) {
                    Logging.Debug("No data in _decCircularBuffer");
                    return;
                }

                // first get chunk length
                if (bufSize <= CHUNK_LEN_BYTES + tagLen) {
                    // so we only have chunk length and its tag?
                    return;
                }

                #region Chunk Decryption

                byte[] encLenBytes = _decCircularBuffer.Peek(CHUNK_LEN_BYTES + tagLen);
                uint decChunkLenLength = 0;
                byte[] decChunkLenBytes = new byte[CHUNK_LEN_BYTES];
                // try to dec chunk len
                cipherDecrypt(encLenBytes, CHUNK_LEN_BYTES + (uint)tagLen, decChunkLenBytes, ref decChunkLenLength);
                Debug.Assert(decChunkLenLength == CHUNK_LEN_BYTES);
                // finally we get the real chunk len
                ushort chunkLen = (ushort) IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(decChunkLenBytes, 0));
                if (chunkLen <= 0 || chunkLen > CHUNK_LEN_MASK)
                {
                    // we get invalid chunk
                    throw new CryptoErrorException($"Invalid chunk length: {chunkLen}");
                }
                Logging.Debug("Get the real chunk len:" + chunkLen);
                bufSize = _decCircularBuffer.Size;
                if (bufSize < CHUNK_LEN_BYTES + tagLen /* we haven't remove them */+ chunkLen + tagLen) {
                    Logging.Debug("No more data to decrypt one chunk");
                    return;
                }
                IncrementNonce(false);

                // we have enough data to decrypt one chunk
                // drop chunk len and its tag from buffer
                _decCircularBuffer.Skip(CHUNK_LEN_BYTES + tagLen);
                byte[] encChunkBytes = _decCircularBuffer.Get(chunkLen + tagLen);
                byte[] decChunkBytes = new byte[chunkLen];
                uint decChunkLen = 0;
                cipherDecrypt(encChunkBytes, chunkLen + (uint)tagLen, decChunkBytes, ref decChunkLen);
                Debug.Assert(decChunkLen == chunkLen);
                IncrementNonce(false);

                #endregion

                int garbageLen = decChunkBytes[0] + FS_GARBAGE_LEN;

                // output to outbuf
                PerfByteCopy(decChunkBytes, garbageLen, outbuf, outlength, (int) decChunkLen - garbageLen);
                outlength += (int)decChunkLen - garbageLen;
                Logging.Debug("aead dec outlength " + outlength);
                bufSize = _decCircularBuffer.Size;
                // check if we already done all of them
                if (bufSize <= 0) {
                    Logging.Debug("No data in _decCircularBuffer, already all done");
                    return;
                }
            }
        }

        #endregion

        #region UDP

        public override void EncryptUDP(ArraySegment<byte> buf, int length, ArraySegment<byte> outbuf, out int outlength)
        {
            // Generate salt
            randBytes(outbuf, saltLen);
            InitCipher(outbuf, true, true);
            uint olen = 0;
            lock (_udpTmpBuf) {
                cipherEncrypt(buf, (uint) length, _udpTmpBuf, ref olen);
                Debug.Assert(olen == length + tagLen);
                PerfByteCopy(_udpTmpBuf, 0, outbuf, saltLen, (int) olen);
                outlength = (int) (saltLen + olen);
            }
        }

        public override void DecryptUDP(ArraySegment<byte> arraySegment, int length, ArraySegment<byte> segment, out int outlength)
        {
            InitCipher(buf, false, true);
            uint olen = 0;
            lock (_udpTmpBuf) {
                // copy remaining data to first pos
                PerfByteCopy(buf, saltLen, buf, 0, length - saltLen);
                cipherDecrypt(buf, (uint) (length - saltLen), _udpTmpBuf, ref olen);
                PerfByteCopy(_udpTmpBuf, 0, outbuf, 0, (int) olen);
                outlength = (int) olen;
            }
        }

        #endregion

        // we know the plaintext length before encryption, so we can do it in one operation
        private void ChunkEncrypt(byte[] plaintext, int plainLen, byte[] ciphertext, out int cipherLen)
        {
            // already take CHUNK_MAX_LEN_WITH_GARBAGE into account outside
            if (plainLen <= 0 || plainLen > CHUNK_LEN_MASK) {
                throw new CryptoErrorException($"invalid incoming chunk len: {plainLen}");
            }

            // encrypt len
            byte[] encLenBytes = new byte[CHUNK_LEN_BYTES + tagLen];
            uint encChunkLenLength = 0;
            byte[] lenbuf = BitConverter.GetBytes((ushort) IPAddress.HostToNetworkOrder((short)plainLen));
            cipherEncrypt(lenbuf, CHUNK_LEN_BYTES, encLenBytes, ref encChunkLenLength);
            Debug.Assert(encChunkLenLength == CHUNK_LEN_BYTES + tagLen);
            IncrementNonce(true);

            // encrypt corresponding data
            byte[] encBytes = new byte[plainLen + tagLen];
            uint encBufLength = 0;
            cipherEncrypt(plaintext, (uint) plainLen, encBytes, ref encBufLength);
            Debug.Assert(encBufLength == plainLen + tagLen);
            IncrementNonce(true);

            // construct outbuf
            Array.Copy(encLenBytes, 0, ciphertext, 0, (int) encChunkLenLength);
            PerfByteCopy(encBytes, 0, ciphertext, (int) encChunkLenLength, (int) encBufLength);
            cipherLen = (int) (encChunkLenLength + encBufLength);
        }

        private static byte[] GetGarbage(int plaintextLength, bool isInitialSend)
        {
            if (plaintextLength > 1300)
            {
                return ZeroGarbageBytes;
            }
            byte[] lenBytes = new byte[FS_GARBAGE_LEN];
            RNG.GetBytes(lenBytes);
            int len = lenBytes[0];
            if (!isInitialSend) {
                if (plaintextLength > 1200)
                {
                    len &= 0x1F;
                }
                else if (plaintextLength > 900)
                {
                    len &= 0x2F;
                }
                else if (plaintextLength > 400)
                {
                    len &= 0x3F;
                }
            } else {
                // for TFO, don't exceed MSS
                len = Math.Min(MaxInitGarbageLen, len);
            }
            byte[] ret = new byte[len + FS_GARBAGE_LEN];
            RNG.GetBytes(ret, FS_GARBAGE_LEN, len);
            ret[0] = (byte) len;
            return ret;
        }
    }
}