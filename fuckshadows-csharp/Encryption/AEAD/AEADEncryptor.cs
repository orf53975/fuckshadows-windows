using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fuckshadows.Encryption;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.AEAD
{
    public abstract class AEADEncryptor
        : EncryptorBase
    {
        private const string personal = "fuckshadows-g3nk";
        private static byte[] personalBytes = Encoding.ASCII.GetBytes(personal);

        private const int CHUNK_LEN_BYTES = 2;

        protected static byte[] tempbuf = new byte[MAX_INPUT_SIZE];

        protected Dictionary<string, EncryptorInfo> ciphers;

        private static readonly ConcurrentDictionary<string, byte[]> CachedKeys =
            new ConcurrentDictionary<string, byte[]>();

        protected byte[] _encryptSalt;
        protected byte[] _decryptSalt;

        // Is first packet
        protected bool _decryptSaltReceived;
        protected bool _encryptSaltSent;

        protected string _method;
        protected int _cipher;
        // internal name in the crypto library
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        protected byte[] _Masterkey;
        protected byte[] _sessionKey;
        protected int keyLen;
        protected int saltLen;
        protected int tagLen;

        public AEADEncryptor(string method, string password)
            : base(method, password)
        {
            InitKey(method, password);
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        private void InitKey(string method, string password)
        {
            method = method.ToLower();
            _method = method;
            string k = $"{method}:{password}";
            ciphers = getCiphers();
            CipherInfo = ciphers[_method];
            _innerLibName = CipherInfo.InnerLibName;
            _cipher = CipherInfo.Type;
            if (_cipher == 0)
            {
                throw new System.Exception("method not found");
            }
            keyLen = CipherInfo.KeySize;
            saltLen = CipherInfo.SaltSize;
            tagLen = CipherInfo.TagSize;
            _Masterkey = CachedKeys.GetOrAdd(k, (nk) =>
            {
                byte[] passbuf = Encoding.UTF8.GetBytes(password);
                byte[] key = new byte[keyLen];
                DeriveKey(passbuf, key);
                return key;
            });
        }

        private void DeriveKey(byte[] password, byte[] key)
        {
            int ret = Sodium.crypto_generichash(key, keyLen, password, (ulong) password.Length, IntPtr.Zero, 0);
            if (ret != 0) throw new System.Exception("failed to generate hash");
        }

        private void DeriveSessionKey(byte[] salt, byte[] masterKey, byte[] sessionKey)
        {
            int ret = Sodium.crypto_generichash_blake2b_salt_personal(sessionKey, keyLen, IntPtr.Zero, 0, masterKey,
                keyLen, salt, personalBytes);
            if (ret != 0) throw new System.Exception("failed to generate session key");
        }

        protected virtual void initCipher(byte[] salt, bool isCipher)
        {
            if (isCipher)
            {
                _encryptSalt = new byte[saltLen];
                Array.Copy(salt, _encryptSalt, saltLen);
            }
            else
            {
                _decryptSalt = new byte[saltLen];
                Array.Copy(salt, _decryptSalt, saltLen);
            }
        }

        protected abstract void cipherEncrypt(bool isUdp, int length, byte[] buf, byte[] outbuf);
        protected abstract void cipherDecrypt(bool isUdp, int length, byte[] buf, byte[] ourbuf);

        protected static void randBytes(byte[] buf, int length)
        {
            RNG.GetBytes(buf, length);
        }

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (!_encryptSaltSent)
            {
                // Generate salt
                randBytes(outbuf, saltLen);
                initCipher(outbuf, true);
                _encryptSaltSent = true;
                lock (tempbuf)
                {
                    cipherEncrypt(false, length, buf, tempbuf);
                    outlength = length + tagLen * 2 + saltLen + CHUNK_LEN_BYTES;
                    Buffer.BlockCopy(tempbuf, 0, outbuf, saltLen, length);
                }
            }
            else
            {
                outlength = length + tagLen * 2 + CHUNK_LEN_BYTES;
                cipherEncrypt(false, length, buf, outbuf);
            }
        }

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Generate salt
            randBytes(outbuf, saltLen);
            initCipher(outbuf, true);
            _encryptSaltSent = true;
            lock (tempbuf)
            {
                cipherEncrypt(true, length, buf, tempbuf);
                outlength = length + tagLen + saltLen;
                Buffer.BlockCopy(tempbuf, 0, outbuf, saltLen, length);
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (!_decryptSaltReceived)
            {
                _decryptSaltReceived = true;
                // Get IV from first packet
                initCipher(buf, false);
                outlength = length - saltLen;
                lock (tempbuf)
                {
                    Buffer.BlockCopy(buf, saltLen, tempbuf, 0, length - saltLen);
                    //cipherUpdate(false, length - ivLen, tempbuf, outbuf);
                }
            }
            else
            {
                outlength = length;
                //cipherUpdate(false, length, buf, outbuf);
            }
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            throw new NotImplementedException();
        }
    }
}
