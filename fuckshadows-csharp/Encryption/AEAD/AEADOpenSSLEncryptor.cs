using System;
using System.Collections.Generic;
using Fuckshadows.Encryption.Exception;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADOpenSSLEncryptor
        : AEADEncryptor, IDisposable
    {
        const int CIPHER_AES = 1;
        const int CIPHER_CHACHA20IETFPOLY1305 = 2;

        private byte[] _opensslEncSubkey;
        private byte[] _opensslDecSubkey;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        private IntPtr _cipherInfoPtr = IntPtr.Zero;

        public AEADOpenSSLEncryptor(ISegmentBufferManager bm, string method, string password)
            : base(bm, method, password)
        {
            _opensslEncSubkey = new byte[keyLen];
            _opensslDecSubkey = new byte[keyLen];
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            {"aes-128-gcm", new EncryptorInfo("aes-128-gcm", 16, 16, 12, 16, CIPHER_AES)},
            {"aes-192-gcm", new EncryptorInfo("aes-192-gcm", 24, 24, 12, 16, CIPHER_AES)},
            {"aes-256-gcm", new EncryptorInfo("aes-256-gcm", 32, 32, 12, 16, CIPHER_AES)},
            {"chacha20-ietf-poly1305", new EncryptorInfo("chacha20-poly1305", 32, 32, 12, 16, CIPHER_CHACHA20IETFPOLY1305)}
        };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        protected override Dictionary<string, EncryptorInfo> getCiphers()
        {
            return _ciphers;
        }

        public override void InitCipher(ArraySegment<byte> salt, bool isEncrypt, bool isUdp)
        {
            base.InitCipher(salt, isEncrypt, isUdp);
            _cipherInfoPtr = OpenSSL.GetCipherInfo(_innerLibName);
            if (_cipherInfoPtr == IntPtr.Zero) throw new System.Exception("openssl: cipher not found");
            IntPtr ctx = OpenSSL.EVP_CIPHER_CTX_new();
            if (ctx == IntPtr.Zero) throw new System.Exception("openssl: fail to create ctx");

            if (isEncrypt)
            {
                _encryptCtx = ctx;
            }
            else
            {
                _decryptCtx = ctx;
            }

            // UDP: master key
            // TCP: session key
            if (isUdp)
            {
                if (isEncrypt)
                {
                    _opensslEncSubkey = _Masterkey;
                }
                else
                {
                    _opensslDecSubkey = _Masterkey;
                }
            }
            else
            {
                DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt, _Masterkey,
                    isEncrypt ? _opensslEncSubkey : _opensslDecSubkey);
            }

            var ret = OpenSSL.EVP_CipherInit_ex(ctx, _cipherInfoPtr, IntPtr.Zero, null, null,
                isEncrypt ? OpenSSL.OPENSSL_ENCRYPT : OpenSSL.OPENSSL_DECRYPT);
            if (ret != 1) throw new System.Exception("openssl: fail to init ctx");

            ret = OpenSSL.EVP_CIPHER_CTX_set_key_length(ctx, keyLen);
            if (ret != 1) throw new System.Exception("openssl: fail to set key length");

            unsafe
            {
                ret = OpenSSL.EVP_CIPHER_CTX_ctrl(ctx, OpenSSL.EVP_CTRL_AEAD_SET_IVLEN,
                    nonceLen, default(byte*));
            }

            if (ret != 1) throw new System.Exception("openssl: fail to set AEAD nonce length");

            ret = OpenSSL.EVP_CipherInit_ex(ctx, IntPtr.Zero, IntPtr.Zero,
                isEncrypt ? _opensslEncSubkey : _opensslDecSubkey,
                null,
                isEncrypt ? OpenSSL.OPENSSL_ENCRYPT : OpenSSL.OPENSSL_DECRYPT);
            if (ret != 1) throw new System.Exception("openssl: cannot set key");
            OpenSSL.EVP_CIPHER_CTX_set_padding(ctx, 0);
        }

        public override void cipherEncrypt(ArraySegment<byte> plaintext, int plen, ArraySegment<byte> ciphertext,
            ref int clen)
        {
            OpenSSL.SetCtxNonce(_encryptCtx, _encNonce, true);
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            clen = 0;
            int tmpLen = 0;
            unsafe
            {
                fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                    pP = &plaintext.Array[plaintext.Offset])
                {
                    ret = OpenSSL.EVP_CipherUpdate(_encryptCtx, cP, out clen,
                        pP, plen);
                }
            }

            if (ret != 1) throw new CryptoErrorException("openssl: fail to encrypt AEAD");

            // For AEAD cipher, it should not output anything

            unsafe
            {
                fixed (byte* cP = &ciphertext.Array[ciphertext.Offset + clen]
                )
                {
                    ret = OpenSSL.EVP_CipherFinal_ex(_encryptCtx, cP, ref tmpLen);
                }
            }

            if (ret != 1) throw new CryptoErrorException("openssl: fail to finalize AEAD");
            if (tmpLen > 0)
            {
                throw new System.Exception("openssl: fail to finish AEAD");
            }

            // append tag just after ciphertext
            unsafe
            {
                fixed (byte* cP = &ciphertext.Array[ciphertext.Offset + clen])
                {
                    ret = OpenSSL.EVP_CIPHER_CTX_ctrl(_encryptCtx,
                    OpenSSL.EVP_CTRL_AEAD_GET_TAG, tagLen, cP);
                
                }
            }
            if (ret != 1) throw new CryptoErrorException("openssl: fail to get AEAD tag");
            clen += tagLen;
        }

        public override void cipherDecrypt(ArraySegment<byte> ciphertext, int clen, ArraySegment<byte> plaintext,
            ref int plen)
        {
            OpenSSL.SetCtxNonce(_decryptCtx, _decNonce, false);
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            int tmpLen = 0;
            plen = 0;

            // split tag
            byte[] tagbuf = new byte[tagLen];
            ArraySegmentExtensions.BlockCopy(ciphertext, clen - tagLen, tagbuf.AsArraySegment(), 0, tagLen);

            unsafe
            {
                fixed (byte* tagP = tagbuf)
                {
                    ret = OpenSSL.EVP_CIPHER_CTX_ctrl(_decryptCtx,
                        OpenSSL.EVP_CTRL_AEAD_SET_TAG, tagLen, tagP);

                }
            }
            if (ret != 1) throw new CryptoErrorException("openssl: fail to set AEAD tag");

            unsafe
            {
                fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                    pP = &plaintext.Array[plaintext.Offset])
                {
                    ret = OpenSSL.EVP_CipherUpdate(_decryptCtx,
                        pP, out plen, cP, clen - tagLen);
                }
            }

            
            if (ret != 1) throw new CryptoErrorException("openssl: fail to decrypt AEAD");

            // For AEAD cipher, it should not output anything

            unsafe
            {
                fixed (byte* pP = &plaintext.Array[plaintext.Offset]
                )
                {
                    ret = OpenSSL.EVP_CipherFinal_ex(_decryptCtx, pP + plen, ref tmpLen);
                }
            }

            if (ret <= 0)
            {
                // If this is not successful authenticated
                throw new CryptoErrorException($"ret is {ret}");
            }

            if (tmpLen > 0)
            {
                throw new System.Exception("openssl: fail to finish AEAD");
            }
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

        ~AEADOpenSSLEncryptor()
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
                OpenSSL.EVP_CIPHER_CTX_free(_encryptCtx);
                _encryptCtx = IntPtr.Zero;
            }

            if (_decryptCtx != IntPtr.Zero)
            {
                OpenSSL.EVP_CIPHER_CTX_free(_decryptCtx);
                _decryptCtx = IntPtr.Zero;
            }
        }

        #endregion
    }
}