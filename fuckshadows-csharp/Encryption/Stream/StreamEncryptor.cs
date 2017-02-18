using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text;
using System.Net;
using Fuckshadows.Encryption.Exception;

namespace Fuckshadows.Encryption.Stream
{
    public abstract class StreamEncryptor
        : EncryptorBase
    {
        protected static byte[] tempbuf = new byte[MAX_INPUT_SIZE];

        protected Dictionary<string, EncryptorInfo> ciphers;

        private static readonly ConcurrentDictionary<string, byte[]> CachedKeys =
            new ConcurrentDictionary<string, byte[]>();

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
        protected byte[] _key;
        protected int keyLen;
        protected int ivLen;

        public StreamEncryptor(string method, string password)
            : base(method, password)
        {
            InitKey(method, password);
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        private void InitKey(string method, string password)
        {
            method = method.ToLower();
            _method = method;
            string k = method + ":" + password;
            ciphers = getCiphers();
            CipherInfo = ciphers[_method];
            _innerLibName = CipherInfo.InnerLibName;
            _cipher = CipherInfo.Type;
            if (_cipher == 0)
            {
                throw new System.Exception("method not found");
            }
            keyLen = CipherInfo.KeySize;
            ivLen = CipherInfo.IvSize;
            _key = CachedKeys.GetOrAdd(k, (nk) =>
            {
                byte[] passbuf = Encoding.UTF8.GetBytes(password);
                byte[] key = new byte[keyLen];
                bytesToKey(passbuf, key);
                return key;
            });
        }

        protected void bytesToKey(byte[] password, byte[] key)
        {
            byte[] result = new byte[password.Length + 16];
            int i = 0;
            byte[] md5sum = null;
            while (i < key.Length)
            {
                if (i == 0)
                {
                    md5sum = MbedTLS.MD5(password);
                }
                else
                {
                    md5sum.CopyTo(result, 0);
                    password.CopyTo(result, md5sum.Length);
                    md5sum = MbedTLS.MD5(result);
                }
                md5sum.CopyTo(key, i);
                i += md5sum.Length;
            }
        }

        protected virtual void initCipher(byte[] iv, bool isCipher)
        {
            if (isCipher)
            {
                _encryptIV = new byte[ivLen];
                Array.Copy(iv, _encryptIV, ivLen);
            }
            else
            {
                _decryptIV = new byte[ivLen];
                Array.Copy(iv, _decryptIV, ivLen);
            }
        }

        protected abstract void cipherUpdate(bool isCipher, int length, byte[] buf, byte[] outbuf);

        protected static void randBytes(byte[] buf, int length)
        {
            RNG.GetBytes(buf, length);
        }

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (!_encryptIVSent)
            {
                // Generate IV
                randBytes(outbuf, ivLen);
                initCipher(outbuf, true);
                _encryptIVSent = true;
                lock (tempbuf)
                {
                    cipherUpdate(true, length, buf, tempbuf);
                    outlength = length + ivLen;
                    Buffer.BlockCopy(tempbuf, 0, outbuf, ivLen, length);
                }
            }
            else
            {
                outlength = length;
                cipherUpdate(true, length, buf, outbuf);
            }
        }

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Generate IV
            randBytes(outbuf, ivLen);
            initCipher(outbuf, true);
            lock (tempbuf)
            {
                cipherUpdate(true, length, buf, tempbuf);
                outlength = length + ivLen;
                Buffer.BlockCopy(tempbuf, 0, outbuf, ivLen, length);
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (!_decryptIVReceived)
            {
                _decryptIVReceived = true;
                // Get IV from first packet
                initCipher(buf, false);
                outlength = length - ivLen;
                lock (tempbuf)
                {
                    // C# could be multi-threaded
                    Buffer.BlockCopy(buf, ivLen, tempbuf, 0, length - ivLen);
                    cipherUpdate(false, length - ivLen, tempbuf, outbuf);
                }
            }
            else
            {
                outlength = length;
                cipherUpdate(false, length, buf, outbuf);
            }
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            // Get IV from first pos
            initCipher(buf, false);
            outlength = length - ivLen;
            lock (tempbuf)
            {
                // C# could be multi-threaded
                Buffer.BlockCopy(buf, ivLen, tempbuf, 0, length - ivLen);
                cipherUpdate(false, length - ivLen, tempbuf, outbuf);
            }
        }
    }
}