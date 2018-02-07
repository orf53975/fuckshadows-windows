using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Fuckshadows.Encryption.Exception;
using Fuckshadows.Util.Sockets.Buffer;


namespace Fuckshadows.Encryption.Stream
{
    public class StreamMbedTLSEncryptor
        : StreamEncryptor, IDisposable
    {
        const int CIPHER_RC4 = 1;
        const int CIPHER_AES = 2;
        const int CIPHER_BLOWFISH = 3;
        const int CIPHER_CAMELLIA = 4;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        private ArraySegment<byte> inBytesSeg;
        private ArraySegment<byte> outBytesSeg;

        public StreamMbedTLSEncryptor(ISegmentBufferManager bm, string method, string password)
            : base(bm, method, password)
        {
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo> {
            { "aes-128-cfb", new EncryptorInfo("AES-128-CFB128", 16, 16, CIPHER_AES) },
            { "aes-192-cfb", new EncryptorInfo("AES-192-CFB128", 24, 16, CIPHER_AES) },
            { "aes-256-cfb", new EncryptorInfo("AES-256-CFB128", 32, 16, CIPHER_AES) },
            { "aes-128-ctr", new EncryptorInfo("AES-128-CTR", 16, 16, CIPHER_AES) },
            { "aes-192-ctr", new EncryptorInfo("AES-192-CTR", 24, 16, CIPHER_AES) },
            { "aes-256-ctr", new EncryptorInfo("AES-256-CTR", 32, 16, CIPHER_AES) },
            { "bf-cfb", new EncryptorInfo("BLOWFISH-CFB64", 16, 8, CIPHER_BLOWFISH) },
            { "camellia-128-cfb", new EncryptorInfo("CAMELLIA-128-CFB128", 16, 16, CIPHER_CAMELLIA) },
            { "camellia-192-cfb", new EncryptorInfo("CAMELLIA-192-CFB128", 24, 16, CIPHER_CAMELLIA) },
            { "camellia-256-cfb", new EncryptorInfo("CAMELLIA-256-CFB128", 32, 16, CIPHER_CAMELLIA) },
            { "rc4-md5", new EncryptorInfo("ARC4-128", 16, 16, CIPHER_RC4) }
        };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        protected override Dictionary<string, EncryptorInfo> getCiphers()
        {
            return _ciphers;
        }

        protected override void initCipher(ArraySegment<byte> iv, bool isEncrypt)
        {
            base.initCipher(iv, isEncrypt);
            IntPtr ctx = Marshal.AllocHGlobal(MbedTLS.cipher_get_size_ex());
            if (isEncrypt)
            {
                _encryptCtx = ctx;
            }
            else
            {
                _decryptCtx = ctx;
            }
            byte[] realkey;
            if (_method == "rc4-md5")
            {
                byte[] temp = new byte[keyLen + ivLen];
                realkey = new byte[keyLen];
                Array.Copy(_key, 0, temp, 0, keyLen);
                Array.Copy(isEncrypt?_encryptIV:_decryptIV, 0, temp, keyLen, ivLen);
                realkey = MbedTLS.MD5(temp);
            }
            else
            {
                realkey = _key;
            }
            MbedTLS.cipher_init(ctx);
            if (MbedTLS.cipher_setup( ctx, MbedTLS.cipher_info_from_string( _innerLibName ) ) != 0 )
                throw new System.Exception("Cannot initialize mbed TLS cipher context");
            /*
             * MbedTLS takes key length by bit
             * cipher_setkey() will set the correct key schedule
             * and operation
             *
             *  MBEDTLS_AES_{EN,DE}CRYPT
             *  == MBEDTLS_BLOWFISH_{EN,DE}CRYPT
             *  == MBEDTLS_CAMELLIA_{EN,DE}CRYPT
             *  == MBEDTLS_{EN,DE}CRYPT
             *  
             */
            if (MbedTLS.cipher_setkey(ctx, realkey, keyLen * 8,
                isEncrypt ? MbedTLS.MBEDTLS_ENCRYPT : MbedTLS.MBEDTLS_DECRYPT) != 0 )
                throw new System.Exception("Cannot set mbed TLS cipher key");
            if (MbedTLS.cipher_set_iv(ctx, isEncrypt?_encryptIV:_decryptIV, ivLen) != 0)
                throw new System.Exception("Cannot set mbed TLS cipher IV");
            if (MbedTLS.cipher_reset(ctx) != 0)
                throw new System.Exception("Cannot finalize mbed TLS cipher context");
        }

        protected override void cipherUpdate(bool isEncrypt, int length, ArraySegment<byte> buf, ArraySegment<byte> outbuf)
        {
            byte[] inBytes = new byte[length];
            ArraySegmentExtensions.BlockCopy(buf, 0, inBytes.AsArraySegment(), );
            // C# could be multi-threaded
            if (_disposed)
            {
                throw new ObjectDisposedException(this.ToString());
            }
            var ret = MbedTLS.cipher_update(isEncrypt ? _encryptCtx : _decryptCtx,
                buf, length, outbuf, ref length);
            if (ret != 0)
                throw new CryptoErrorException($"ret is {ret}");
        }

        #region IDisposable

        private bool _disposed;

        // instance based lock
        private readonly object _lock = new object();

        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~StreamMbedTLSEncryptor()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
            }

            if (disposing)
            {
                // free managed objects
            }

            // free unmanaged objects
            if (_encryptCtx != IntPtr.Zero)
            {
                MbedTLS.cipher_free(_encryptCtx);
                Marshal.FreeHGlobal(_encryptCtx);
                _encryptCtx = IntPtr.Zero;
            }
            if (_decryptCtx != IntPtr.Zero)
            {
                MbedTLS.cipher_free(_decryptCtx);
                Marshal.FreeHGlobal(_decryptCtx);
                _decryptCtx = IntPtr.Zero;
            }
        }

        #endregion
    }
}
