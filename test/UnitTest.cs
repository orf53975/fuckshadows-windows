using System;
using Fuckshadows.Controller;
using Fuckshadows.Encryption;
using Fuckshadows.Encryption.Stream;
using GlobalHotKey;
using System.Windows.Input;
using System.Threading;
using System.Collections.Generic;
using System.Text;
using Fuckshadows.Controller.Hotkeys;
using Fuckshadows.Encryption.AEAD;
using NUnit.Framework;

namespace test
{
    [TestFixture]
    public class UnitTest
    {
        #region Test helper

        [TearDown]
        public void TearDown()
        {
            // reset flag in case they interfere each other
            encryptionFailed = false;
        }

        [OneTimeSetUp]
        public void OneTimeSetup()
        {
            _random = new Random();
        }

        private Random _random = null;
        private static bool encryptionFailed = false;
        private static byte[] abufBytes = { 3, 14, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 1, 187 };
        private static int abufLength = abufBytes.Length;

        #endregion

        private void RunStreamEncryptionRound(IEncryptor encryptor, IEncryptor decryptor)
        {
            byte[] plain = new byte[16384];
            const int IV = 16;
            byte[] cipher = new byte[plain.Length + IV];
            byte[] plain2 = new byte[plain.Length + IV];
            int outLen = 0;
            int outLen2 = 0;

            _random.NextBytes(plain);
            encryptor.Encrypt(plain, plain.Length, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(plain.Length, outLen2);
            for (int j = 0; j < plain.Length; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 1000, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(1000, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 12333, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(12333, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
        }

        private void RunAEADEncryptionRound(IEncryptor encryptor, IEncryptor decryptor)
        {
            byte[] plain = new byte[16384];
            const int Salt = 32;
            // make the cipher array large enough to hold chunks
            byte[] cipher = new byte[plain.Length * 2 + Salt];
            byte[] plain2 = new byte[plain.Length + Salt];
            int outLen = 0;
            int outLen2 = 0;

            _random.NextBytes(plain);
            // make sure we have initialized the address buffer
            Buffer.BlockCopy(abufBytes, 0, plain, 0, abufLength);
            encryptor.Encrypt(plain, plain.Length, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(plain.Length, outLen2);
            for (int j = 0; j < plain.Length; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 1000, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(1000, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
            encryptor.Encrypt(plain, 12333, cipher, out outLen);
            decryptor.Decrypt(cipher, outLen, plain2, out outLen2);
            Assert.AreEqual(12333, outLen2);
            for (int j = 0; j < outLen2; j++)
            {
                Assert.AreEqual(plain[j], plain2[j]);
            }
        }

        [Test]
        public void TestCompareVersion()
        {
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("2.3.1.0", "2.3.1") == 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.2", "1.3") < 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3", "1.2") > 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3", "1.3") == 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.2.1", "1.2") > 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("2.3.1", "2.4") < 0);
            Assert.IsTrue(UpdateChecker.Asset.CompareVersion("1.3.2", "1.3.1") > 0);
        }

        [Test]
        public void TestHotKey2Str()
        {
            Assert.AreEqual("Ctrl+A", HotKeys.HotKey2Str(Key.A, ModifierKeys.Control));
            Assert.AreEqual("Ctrl+Alt+D2", HotKeys.HotKey2Str(Key.D2, (ModifierKeys.Alt | ModifierKeys.Control)));
            Assert.AreEqual("Ctrl+Alt+Shift+NumPad7",
                HotKeys.HotKey2Str(Key.NumPad7, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
            Assert.AreEqual("Ctrl+Alt+Shift+F6",
                HotKeys.HotKey2Str(Key.F6, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
            Assert.AreNotEqual("Ctrl+Shift+Alt+F6",
                HotKeys.HotKey2Str(Key.F6, (ModifierKeys.Alt | ModifierKeys.Control | ModifierKeys.Shift)));
        }

        [Test]
        public void TestStr2HotKey()
        {
            Assert.IsTrue(HotKeys.Str2HotKey("Ctrl+A").Equals(new HotKey(Key.A, ModifierKeys.Control)));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Alt+A").Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Alt))));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Shift+A")
                    .Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Shift))));
            Assert.IsTrue(
                HotKeys.Str2HotKey("Ctrl+Alt+Shift+A")
                    .Equals(new HotKey(Key.A, (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey0 = HotKeys.Str2HotKey("Ctrl+Alt+Shift+A");
            Assert.IsTrue(testKey0 != null &&
                          testKey0.Equals(new HotKey(Key.A,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey1 = HotKeys.Str2HotKey("Ctrl+Alt+Shift+F2");
            Assert.IsTrue(testKey1 != null &&
                          testKey1.Equals(new HotKey(Key.F2,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey2 = HotKeys.Str2HotKey("Ctrl+Shift+Alt+D7");
            Assert.IsTrue(testKey2 != null &&
                          testKey2.Equals(new HotKey(Key.D7,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
            HotKey testKey3 = HotKeys.Str2HotKey("Ctrl+Shift+Alt+NumPad7");
            Assert.IsTrue(testKey3 != null &&
                          testKey3.Equals(new HotKey(Key.NumPad7,
                              (ModifierKeys.Control | ModifierKeys.Alt | ModifierKeys.Shift))));
        }

        [Test]
        public void TestMD5()
        {
            for (int len = 1; len < 64; len++)
            {
                System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
                byte[] bytes = new byte[len];
                _random.NextBytes(bytes);
                string md5str = Convert.ToBase64String(md5.ComputeHash(bytes));
                string md5str2 = Convert.ToBase64String(MbedTLS.MD5(bytes));
                Assert.IsTrue(md5str == md5str2);
            }
        }

        #region MbedTLS

        [Test]
        public void TestStreamMbedTLSEncryption()
        {
            bool encryptionFailed = false;
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleStreamMbedTLSEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleStreamMbedTLSEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamMbedTLSEncryptor("aes-256-cfb", "barfoo!");
                    IEncryptor decryptor = new StreamMbedTLSEncryptor("aes-256-cfb", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [Test]
        public void TestAEADMbedTLSEncryption()
        {
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleAEADMbedTLSEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleAEADMbedTLSEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new AEADMbedTLSEncryptor("aes-256-gcm", "barfoo!");
                    IEncryptor decryptor = new AEADMbedTLSEncryptor("aes-256-gcm", "barfoo!");
                    encryptor.AddrBufLength = abufLength;
                    RunAEADEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        #endregion

        #region OpenSSL

        [Test]
        public void TestStreamOpenSSLEncryption()
        {
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleStreamOpenSSLEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleStreamOpenSSLEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor1 = new StreamOpenSSLEncryptor("aes-256-cfb", "barfoo!");
                    IEncryptor decryptor1 = new StreamOpenSSLEncryptor("aes-256-cfb", "barfoo!");
                    RunStreamEncryptionRound(encryptor1, decryptor1);

                    //IEncryptor encryptor2 = new StreamOpenSSLEncryptor("rc4-md5", "barfoo!");
                    //IEncryptor decryptor2 = new StreamOpenSSLEncryptor("rc4-md5", "barfoo!");
                    //RunStreamEncryptionRound(encryptor2, decryptor2);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [Test]
        public void TestAEADOpenSSLEncryption()
        {
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleAEADOpenSSLEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleAEADOpenSSLEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor1 = new AEADOpenSSLEncryptor("aes-256-gcm", "barfoo!");
                    IEncryptor decryptor1 = new AEADOpenSSLEncryptor("aes-256-gcm", "barfoo!");
                    encryptor1.AddrBufLength = abufLength;
                    RunAEADEncryptionRound(encryptor1, decryptor1);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        #endregion

        [Test]
        public void TestRC4Encryption()
        {
            // run it once before the multi-threading test to initialize global tables
            RunSingleRC4EncryptionThread();
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleRC4EncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleRC4EncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamMbedTLSEncryptor("rc4-md5", "barfoo!");
                    IEncryptor decryptor = new StreamMbedTLSEncryptor("rc4-md5", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [Test]
        public void TestStreamSodiumEncryption()
        {
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleStreamSodiumEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleStreamSodiumEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new StreamSodiumEncryptor("salsa20", "barfoo!");
                    IEncryptor decryptor = new StreamSodiumEncryptor("salsa20", "barfoo!");
                    RunStreamEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

#if !DEBUG
        // Disable AEAD sodium test when building DEBUG version
        // until it will no longer looping itself infinitely
        [Test]
#endif
        public void TestAEADSodiumEncryption()
        {
            List<Thread> threads = new List<Thread>();
            for (int i = 0; i < 10; i++)
            {
                Thread t = new Thread(RunSingleAEADSodiumEncryptionThread);
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }
            Assert.IsFalse(encryptionFailed);
        }

        private void RunSingleAEADSodiumEncryptionThread()
        {
            try
            {
                for (int i = 0; i < 100; i++)
                {
                    IEncryptor encryptor = new AEADSodiumEncryptor("chacha20-poly1305", "barfoo!");
                    IEncryptor decryptor = new AEADSodiumEncryptor("chacha20-poly1305", "barfoo!");
                    encryptor.AddrBufLength = abufLength;
                    RunAEADEncryptionRound(encryptor, decryptor);
                }
            }
            catch
            {
                encryptionFailed = true;
                throw;
            }
        }

        [Test]
        public void TestLegacyDeriveKey()
        {
            string pass = "test-legacy";
            byte[] passBytes = Encoding.UTF8.GetBytes(pass);
            byte[] key1 = new byte[32];
            StreamEncryptor.LegacyDeriveKey(passBytes, key1, 32);
            byte[] key2 =
            {
                0x7b, 0x14, 0xff, 0x93, 0xd6, 0x63, 0x27, 0xfa, 0xd4, 0xdc, 0x37, 0x86, 0x46, 0x86, 0x3f,
                0xc4, 0x53, 0x04, 0xd0, 0xdb, 0xf3, 0x79, 0xbd, 0xb5, 0x54, 0x44, 0xf9, 0x91, 0x80, 0x50, 0x7e, 0xa2
            };
            string key1str = Convert.ToBase64String(key1);
            string key2str = Convert.ToBase64String(key2);
            Assert.IsTrue(key1str == key2str);
        }

        [Test]
        public void TestDeriveKey()
        {
            string pass = "test-aead-derive-key";
            byte[] passBytes = Encoding.UTF8.GetBytes(pass);
            byte[] key_test = new byte[32];
            AEADSodiumEncryptor encryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", pass);
            encryptor.DeriveKey(passBytes, key_test, 32);
            byte[] key_ref =
            {
                0xb5, 0x02, 0xe1, 0x43, 0x31, 0x6e, 0xea, 0xad, 0x3d, 0x9d, 0xd2, 0x9f, 0x1c, 0xdc, 0x1a,
                0xe9, 0xbd, 0x48, 0x2c, 0xda, 0xa8, 0x21, 0x99, 0x3b, 0x85, 0x45, 0x22, 0x34, 0x9a, 0x91, 0x33, 0xfd
            };
            string key1str = Convert.ToBase64String(key_test);
            string key2str = Convert.ToBase64String(key_ref);
            Assert.IsTrue(key1str == key2str);
        }

        [Test]
        public void TestDeriveSessionKey()
        {
            string pass = "test-aead-derive-session-key";
            byte[] skey_test = new byte[32];
            byte[] saltBytes =
            {
                0x8c, 0xfe, 0x67, 0x9a, 0x4c, 0x05, 0xfe, 0x36, 0xca, 0x00, 0x9c, 0x90, 0xe9, 0x66, 0x5b,
                0x48, 0x35, 0x1c, 0x07, 0x55, 0x18, 0x94, 0x32, 0x72, 0xc8, 0x40, 0xd2, 0xfd, 0x1f, 0xd4, 0xf1, 0x22
            };
            byte[] masterKeyBytes =
            {
                0x4d, 0x79, 0xd4, 0x6e, 0x63, 0x7d, 0xb5, 0x0d, 0xd1, 0x7b, 0x24, 0xe3, 0xb8, 0xdf,
                0xf3, 0xb5, 0xde, 0xba, 0x42, 0xaf, 0x3a, 0x2e, 0x94, 0xbf, 0xb2, 0xf4, 0x37, 0x91, 0xae, 0xd4, 0x65,
                0x04
            };
            byte[] skey_ref =
            {
                0x60, 0xc7, 0xa8, 0xe5, 0x59, 0x6b, 0x7a, 0xcd, 0x65, 0xd8, 0xe5, 0x54, 0x31, 0x57, 0x89,
                0xf2, 0x39, 0xa7, 0xf8, 0x96, 0x37, 0x88, 0x90, 0x9e, 0xc1, 0xe1, 0xc2, 0xb7, 0xf0, 0x9f, 0x6f, 0xd9
            };
            AEADSodiumEncryptor encryptor = new AEADSodiumEncryptor("chacha20-ietf-poly1305", pass);
            encryptor.DeriveSessionKey(saltBytes, masterKeyBytes, skey_test);
            string skey1str = Convert.ToBase64String(skey_test);
            string skey2str = Convert.ToBase64String(skey_ref);
            Assert.IsTrue(skey1str == skey2str);
        }

        [Test]
        public void TestAEADudp()
        {
            string pass = "test-aead-derive-session-key";
            byte[] saltBytes =
            {
                0x8c, 0xfe, 0x67, 0x9a, 0x4c, 0x05, 0xfe, 0x36, 0xca, 0x00, 0x9c, 0x90, 0xe9, 0x66, 0x5b,
                0x48, 0x35, 0x1c, 0x07, 0x55, 0x18, 0x94, 0x32, 0x72, 0xc8, 0x40, 0xd2, 0xfd, 0x1f, 0xd4, 0xf1, 0x22
            };
            AEADEncryptor encryptor = new AEADMbedTLSEncryptor("aes-256-gcm", pass);
            AEADEncryptor decryptor = new AEADMbedTLSEncryptor("aes-256-gcm", pass);
            byte[] plain = new byte[4096];
            byte[] cipher = new byte[8192];
            byte[] plain2 = new byte[4096];
            int cipherLen;
            int plain2Len;
            _random.NextBytes(plain);
            encryptor.InitCipher(saltBytes, true, true);
            encryptor.EncryptUDP(plain, 4096, cipher, out cipherLen);
            decryptor.InitCipher(saltBytes, false, true);
            decryptor.DecryptUDP(cipher, cipherLen, plain2, out plain2Len);
            Assert.IsTrue(plain2Len == 4096);
            for (int i = 0; i < 4096; i++)
            {
                Assert.AreEqual(plain[i], plain2[i]);
            }
        }

        [Test]
        public void TestLib_chacha20poly1305()
        {
            byte[] firstkey =
            {
                0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07
            };

            byte[] m
                = {0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca};
            byte[] nonce
                = {0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a};
            byte[] ad
                = {0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0};
            byte[] c_ref =
            {
                0xe3, 0xe4, 0x46, 0xf7, 0xed, 0xe9, 0xa1, 0x9b
                , 0x62, 0xa4, 0x67, 0x7d, 0xab, 0xf4, 0xe3, 0xd2
                , 0x4b, 0x87, 0x6b, 0xb2, 0x84, 0x75, 0x38, 0x96
                , 0xe1, 0xd6
            };
            byte[] c = new byte[m.Length + 16];
            byte[] m2 = new byte[m.Length];
            ulong found_clen = 0;
            ulong m2len = 0;
            Sodium.crypto_aead_chacha20poly1305_encrypt(c, ref found_clen, m, (ulong) m.Length,
                ad, (ulong) ad.Length,
                null, nonce, firstkey);
            for (int i = 0; i < c.Length; i++)
            {
                Assert.AreEqual(c_ref[i], c[i]);
            }

            Sodium.crypto_aead_chacha20poly1305_decrypt(m2, ref m2len, null, c, (ulong) c.Length,
                ad, (ulong) ad.Length,
                nonce, firstkey);
            Assert.AreEqual(m2len, m.Length);
        }
    }
}