using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Fuckshadows.Encryption.Exception;

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

        public AEADOpenSSLEncryptor(string method, string password)
            : base(method, password)
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

        public override void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            base.InitCipher(salt, isEncrypt, isUdp);
            IntPtr cipherInfo = OpenSSL.GetCipherInfo(_innerLibName);
            if (cipherInfo == IntPtr.Zero) throw new System.Exception("openssl: cipher not found");
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

            var ret = OpenSSL.EVP_CipherInit_ex(ctx, cipherInfo, IntPtr.Zero, null, null,
                isEncrypt ? OpenSSL.OPENSSL_ENCRYPT : OpenSSL.OPENSSL_DECRYPT);
            if (ret != 1) throw new System.Exception("openssl: fail to init ctx");

            ret = OpenSSL.EVP_CIPHER_CTX_set_key_length(ctx, keyLen);
            if (ret != 1) throw new System.Exception("openssl: fail to set key length");

            ret = OpenSSL.EVP_CIPHER_CTX_ctrl(ctx, OpenSSL.EVP_CTRL_AEAD_SET_IVLEN,
                nonceLen, IntPtr.Zero);
            if (ret != 1) throw new System.Exception("openssl: fail to set AEAD nonce length");

            ret = OpenSSL.EVP_CipherInit_ex(ctx, IntPtr.Zero, IntPtr.Zero,
                isEncrypt ? _opensslEncSubkey : _opensslDecSubkey,
                null,
                OpenSSL.OPENSSL_CIPHER_ENC_UNCHANGED);
            if (ret != 1) throw new System.Exception("openssl: cannot set key");
            OpenSSL.EVP_CIPHER_CTX_set_padding(ctx, 0);
        }

        public override void cipherEncrypt(byte[] plaintext, uint plen, byte[] ciphertext, ref uint clen)
        {

            using (var ms = new MemoryStream())
            {
                OpenSSL.ResetCtxNonce(_encryptCtx, _encNonce);
                // buf: all plaintext
                // outbuf: ciphertext + tag
                int ret;
                int tmpLen = 0;
                clen = 0;
                var tmpBuf = new byte[ciphertext.Length];

                ret = OpenSSL.EVP_CipherUpdate(_encryptCtx, tmpBuf, out tmpLen,
                    plaintext, (int) plen);
                if (ret != 1) throw new CryptoErrorException("openssl: fail to encrypt AEAD");
                ms.Write(tmpBuf, 0, tmpLen);
                clen += (uint)tmpLen;

                ret = OpenSSL.EVP_CipherFinal_ex(_encryptCtx, tmpBuf, ref tmpLen);
                if (ret != 1) throw new CryptoErrorException("openssl: fail to finalize AEAD");
                if (tmpLen > 0)
                {
                    ms.Write(tmpBuf, 0, tmpLen);
                    clen += (uint)tmpLen;
                }

                OpenSSL.AEADGetTag(_encryptCtx, tmpBuf, tagLen);
                ms.Write(tmpBuf, 0, tagLen);
                clen += (uint) tagLen;

                var outArr = ms.ToArray();
                Array.Copy(outArr, 0, ciphertext, 0, outArr.Length);
            }
        }

        public override void cipherDecrypt(byte[] ciphertext, uint clen, byte[] plaintext, ref uint plen)
        {
            using (var ms = new MemoryStream())
            {
                OpenSSL.ResetCtxNonce(_decryptCtx, _decNonce);
                // buf: ciphertext + tag
                // outbuf: plaintext
                int ret;
                int tmpLen = 0;
                plen = 0;
                var tmpBuf = new byte[plaintext.Length];

                // split tag
                byte[] tagbuf = new byte[tagLen];
                Array.Copy(ciphertext, (int) (clen - tagLen), tagbuf, 0, tagLen);
                OpenSSL.AEADSetTag(_decryptCtx, tagbuf, tagLen);

                ret = OpenSSL.EVP_CipherUpdate(_decryptCtx,
                    tmpBuf, out tmpLen, ciphertext, (int) (clen - tagLen));
                if (ret != 1) throw new CryptoErrorException("openssl: fail to decrypt AEAD");
                ms.Write(tmpBuf, 0, tmpLen);
                plen += (uint)tmpLen;

                ret = OpenSSL.EVP_CipherFinal_ex(_decryptCtx, tmpBuf, ref tmpLen);
                if (ret <= 0)
                {
                    // If this is not successful authenticated
                    throw new CryptoErrorException($"ret is {ret}");
                }
                if (tmpLen > 0)
                {
                    ms.Write(tmpBuf, 0, tmpLen);
                    plen += (uint)tmpLen;
                }

                var outArr = ms.ToArray();
                Array.Copy(outArr, 0, plaintext, 0, outArr.Length);
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