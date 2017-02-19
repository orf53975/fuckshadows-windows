using System;
using System.IO;
using System.Runtime.InteropServices;
using Fuckshadows.Controller;
using Fuckshadows.Properties;
using Fuckshadows.Util;

namespace Fuckshadows.Encryption
{
    public static class Sodium
    {
#if _X64
        private const string DLLNAME = "libfscrypto64.dll";
#else
        private const string DLLNAME = "libfscrypto.dll";
#endif

        private static bool _initialized = false;
        private static readonly object _initLock = new object();

        static Sodium()
        {
            string dllPath = Utils.GetTempPath(DLLNAME);
            try
            {
#if _X64
                FileManager.UncompressFile(dllPath, Resources.libfscrypto64_dll);
#else
                FileManager.UncompressFile(dllPath, Resources.libfscrypto_dll);
#endif
            }
            catch (IOException)
            {
            }
            catch (System.Exception e)
            {
                Logging.LogUsefulException(e);
            }
            LoadLibrary(dllPath);

            lock (_initLock)
            {
                if (!_initialized)
                {
                    int ret = sodium_init();
                    if (ret == -1)
                    {
                        throw new System.Exception("Failed to initialize sodium");
                    }
                    else /* 1 means already initialized; 0 means success */
                    {
                        _initialized = true;
                    }
                }
            }
        }

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibrary(string path);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_init();

        #region AEAD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_increment(byte[] n, int nlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_generichash(byte[] outbuf, int outlen, byte[] inbuf, ulong inlen, byte[] key,
            int keylen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_generichash_blake2b_salt_personal(byte[] outArr, int outlen, byte[] inArr,
            ulong inlen, byte[] key, int keylen, byte[] salt, byte[] personal);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_ietf_encrypt(byte[] c, ref ulong clen_p, byte[] m,
            ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_ietf_decrypt(byte[] m, ref ulong mlen_p,
            byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_encrypt(byte[] c, ref ulong clen_p, byte[] m, ulong mlen,
            byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_decrypt(byte[] m, ref ulong mlen_p, byte[] nsec, byte[] c,
            ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(byte[] c, ref ulong clen_p, byte[] m, ulong mlen,
            byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(byte[] m, ref ulong mlen_p, byte[] nsec, byte[] c,
            ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

        #endregion

        #region Stream

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_stream_salsa20_xor_ic(byte[] c, byte[] m, ulong mlen, byte[] n, ulong ic,
            byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_stream_chacha20_xor_ic(byte[] c, byte[] m, ulong mlen, byte[] n, ulong ic,
            byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_stream_chacha20_ietf_xor_ic(byte[] c, byte[] m, ulong mlen, byte[] n, uint ic,
            byte[] k);

        #endregion
    }
}