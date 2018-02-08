using System;
using System.Collections.Generic;
using System.Diagnostics;
using Fuckshadows.Controller;
using Fuckshadows.Encryption.Exception;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Encryption.AEAD
{
    public class AEADSodiumEncryptor
        : AEADEncryptor, IDisposable
    {
        private const int CIPHER_CHACHA20POLY1305 = 1;
        private const int CIPHER_CHACHA20IETFPOLY1305 = 2;
        private const int CIPHER_XCHACHA20IETFPOLY1305 = 3;
        private const int CIPHER_AES256GCM = 4;

        private byte[] _sodiumEncSubkey;
        private byte[] _sodiumDecSubkey;

        public AEADSodiumEncryptor(ISegmentBufferManager bm, string method, string password)
            : base(bm, method, password)
        {
            _sodiumEncSubkey = new byte[keyLen];
            _sodiumDecSubkey = new byte[keyLen];
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            {"chacha20-poly1305", new EncryptorInfo(32, 32, 8, 16, CIPHER_CHACHA20POLY1305)},
            {"chacha20-ietf-poly1305", new EncryptorInfo(32, 32, 12, 16, CIPHER_CHACHA20IETFPOLY1305)},
            {"xchacha20-ietf-poly1305", new EncryptorInfo(32, 32, 24, 16, CIPHER_XCHACHA20IETFPOLY1305)},
            {"aes-256-gcm", new EncryptorInfo(32, 32, 12, 16, CIPHER_AES256GCM)},
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
            // UDP: master key
            // TCP: session key
            if (isUdp)
            {
                if (isEncrypt)
                {
                    _sodiumEncSubkey = _Masterkey;
                }
                else
                {
                    _sodiumDecSubkey = _Masterkey;
                }
            }
            else
            {
                DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt, _Masterkey,
                    isEncrypt ? _sodiumEncSubkey : _sodiumDecSubkey);
            }
        }


        public override void cipherEncrypt(ArraySegment<byte> plaintext, int plen, ArraySegment<byte> ciphertext,
            ref int clen)
        {
            Debug.Assert(_sodiumEncSubkey != null);
            // buf: all plaintext
            // outbuf: ciphertext + tag
            int ret;
            ulong encClen = 0;
            Logging.DumpByteArray("_encNonce before enc", _encNonce, nonceLen);
            Logging.DumpByteArray("_sodiumEncSubkey", _sodiumEncSubkey, keyLen);
            Logging.DumpByteArraySegment("before cipherEncrypt: plain", plaintext, (int) plen);
            switch (_cipher)
            {
                case CIPHER_CHACHA20POLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _encNonce,
                            subkeyP = _sodiumEncSubkey)
                        {
                            ret = Sodium.crypto_aead_chacha20poly1305_encrypt(cP, ref encClen,
                                pP, (ulong) plen,
                                default(byte*), 0,
                                default(byte*), nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _encNonce,
                            subkeyP = _sodiumEncSubkey)
                        {
                            ret = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(cP, ref encClen,
                                pP, (ulong) plen,
                                default(byte*), 0,
                                default(byte*), nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_XCHACHA20IETFPOLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _encNonce,
                            subkeyP = _sodiumEncSubkey)
                        {
                            ret = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cP, ref encClen,
                                pP, (ulong) plen,
                                default(byte*), 0,
                                default(byte*), nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_AES256GCM:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _encNonce,
                            subkeyP = _sodiumEncSubkey)
                        {
                            ret = Sodium.crypto_aead_aes256gcm_encrypt(cP, ref encClen,
                                pP, (ulong) plen,
                                default(byte*), 0,
                                default(byte*), nonceP,
                                subkeyP);
                        }
                    }

                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
            Logging.DumpByteArraySegment("after cipherEncrypt: cipher", ciphertext, (int) encClen);
            clen = (int) encClen;
        }

        public override void cipherDecrypt(ArraySegment<byte> ciphertext, int clen, ArraySegment<byte> plaintext,
            ref int plen)
        {
            Debug.Assert(_sodiumDecSubkey != null);
            // buf: ciphertext + tag
            // outbuf: plaintext
            int ret;
            ulong decPlen = 0;
            Logging.DumpByteArray("_decNonce before dec", _decNonce, nonceLen);
            Logging.DumpByteArray("_sodiumDecSubkey", _sodiumDecSubkey, keyLen);
            Logging.DumpByteArraySegment("before cipherDecrypt: cipher", ciphertext, (int) clen);
            switch (_cipher)
            {
                case CIPHER_CHACHA20POLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _decNonce,
                            subkeyP = _sodiumDecSubkey)
                        {
                            ret = Sodium.crypto_aead_chacha20poly1305_decrypt(pP, ref decPlen,
                                default(byte*), cP,
                                (ulong) clen, default(byte*),
                                0, nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_CHACHA20IETFPOLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _decNonce,
                            subkeyP = _sodiumDecSubkey)
                        {
                            ret = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(pP, ref decPlen,
                                default(byte*), cP,
                                (ulong) clen, default(byte*),
                                0, nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_XCHACHA20IETFPOLY1305:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _decNonce,
                            subkeyP = _sodiumDecSubkey)
                        {
                            ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(pP, ref decPlen,
                                default(byte*), cP,
                                (ulong) clen, default(byte*),
                                0, nonceP,
                                subkeyP);
                        }
                    }

                    break;
                case CIPHER_AES256GCM:
                    unsafe
                    {
                        fixed (byte* cP = &ciphertext.Array[ciphertext.Offset],
                            pP = &plaintext.Array[plaintext.Offset],
                            nonceP = _decNonce,
                            subkeyP = _sodiumDecSubkey)
                        {
                            ret = Sodium.crypto_aead_aes256gcm_decrypt(pP, ref decPlen,
                                default(byte*), cP,
                                (ulong) clen, default(byte*),
                                0, nonceP,
                                subkeyP);
                        }
                    }

                    break;
                default:
                    throw new System.Exception("not implemented");
            }

            if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
            Logging.DumpByteArraySegment("after cipherDecrypt: plain", plaintext, (int) decPlen);
            plen = (int) decPlen;
        }

        public override void Dispose()
        {
        }
    }
}