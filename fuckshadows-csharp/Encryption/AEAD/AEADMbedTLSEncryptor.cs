using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Fuckshadows.Encryption.Exception;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADMbedTLSEncryptor
        : AEADEncryptor, IDisposable
    {
        const int CIPHER_AES = 1;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        public AEADMbedTLSEncryptor(ISegmentBufferManager bm, string method, string password)
            : base(bm, method, password)
        {
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            {"aes-128-gcm", new EncryptorInfo("AES-128-GCM", 16, 16, 12, 16, CIPHER_AES)},
            {"aes-192-gcm", new EncryptorInfo("AES-192-GCM", 24, 24, 12, 16, CIPHER_AES)},
            {"aes-256-gcm", new EncryptorInfo("AES-256-GCM", 32, 32, 12, 16, CIPHER_AES)},
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
            IntPtr ctx = Marshal.AllocHGlobal(MbedTLS.cipher_get_size_ex());
            if (isEncrypt)
            {
                _encryptCtx = ctx;
            }
            else
            {
                _decryptCtx = ctx;
            }

            MbedTLS.cipher_init(ctx);
            if (MbedTLS.cipher_setup(ctx, MbedTLS.cipher_info_from_string(_innerLibName)) != 0)
                throw new System.Exception("Cannot initialize mbed TLS cipher context");

            if (isUdp)
            {
                CipherSetKey(isEncrypt, _Masterkey);
            }
            else
            {
                DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt,
                    _Masterkey, _sessionKey);
                CipherSetKey(isEncrypt, _sessionKey);
            }
        }

        // UDP: master key
        // TCP: session key
        private void CipherSetKey(bool isEncrypt, byte[] key)
        {
            IntPtr ctx = isEncrypt ? _encryptCtx : _decryptCtx;
            int ret = MbedTLS.cipher_setkey(ctx, key, keyLen * 8,
                isEncrypt ? MbedTLS.MBEDTLS_ENCRYPT : MbedTLS.MBEDTLS_DECRYPT);
            if (ret != 0) throw new System.Exception("failed to set key");
            ret = MbedTLS.cipher_reset(ctx);
            if (ret != 0) throw new System.Exception("failed to finish preparation");
        }

        public override void cipherEncrypt(ArraySegment<byte> plaintext, int plen, ArraySegment<byte> ciphertext,
            ref int clen)
        {
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            byte[] tagbuf = new byte[tagLen];
            uint olen = 0;
            switch (_cipher)
            {
                case CIPHER_AES:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _encNonce,
                            tagP = tagbuf)
                        {
                            ret = MbedTLS.cipher_auth_encrypt(_encryptCtx,
                                /* nonce */
                                nonceP, (uint) nonceLen,
                                /* AD */
                                IntPtr.Zero, 0,
                                /* plain */
                                pP, (uint) plen,
                                /* cipher */
                                cP, ref olen,
                                tagP, (uint) tagLen);
                        }
                    }

                    if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
                    Debug.Assert(olen == plen);
                    // attach tag to ciphertext
                    ArraySegmentExtensions.BlockCopy(tagbuf.AsArraySegment(), 0, ciphertext, (int) plen, tagLen);
                    clen = (int) olen + tagLen;
                    break;
                default:
                    throw new System.Exception("not implemented");
            }
        }

        public override void cipherDecrypt(ArraySegment<byte> ciphertext, int clen, ArraySegment<byte> plaintext,
            ref int plen)
        {
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            uint olen = 0;
            // split tag
            byte[] tagbuf = new byte[tagLen];
            ArraySegmentExtensions.BlockCopy(ciphertext, (int) (clen - tagLen), tagbuf.AsArraySegment(), 0, tagLen);
            switch (_cipher)
            {
                case CIPHER_AES:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _decNonce,
                            tagP = tagbuf)
                        {
                            ret = MbedTLS.cipher_auth_decrypt(_decryptCtx,
                                nonceP, (uint) nonceLen,
                                IntPtr.Zero, 0,
                                cP, (uint) (clen - tagLen),
                                pP, ref olen,
                                tagP, (uint) tagLen);
                        }
                    }

                    if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
                    Debug.Assert(olen == clen - tagLen);
                    plen = (int) olen;
                    break;
                default:
                    throw new System.Exception("not implemented");
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

        ~AEADMbedTLSEncryptor()
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