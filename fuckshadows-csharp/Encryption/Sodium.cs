using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
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

        public static bool AES256GCMAvailable { get; private set; } = false;

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
                    if (sodium_init() == -1)
                    {
                        throw new System.Exception("Failed to initialize sodium");
                    }
                    else /* 1 means already initialized; 0 means success */
                    {
                        _initialized = true;
                    }

                    AES256GCMAvailable = crypto_aead_aes256gcm_is_available() == 1;
                    Logging.Debug($"sodium: AES256GCMAvailable is {AES256GCMAvailable}");
                }
            }
        }

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibrary(string path);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_init();

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_aead_aes256gcm_is_available();

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe void randombytes_buf(byte* buf, int size);

        #region AEAD

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int sodium_increment(byte* n, int nlen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_generichash(byte[] outbuf, int outlen, byte[] inbuf, ulong inlen, byte[] key,
            int keylen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_generichash_blake2b_salt_personal(byte[] outArr, int outlen, byte[] inArr,
            ulong inlen, byte[] key, int keylen, byte[] salt, byte[] personal);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_chacha20poly1305_ietf_encrypt(byte* c, ref ulong clen_p, byte* m,
            ulong mlen, byte* ad, ulong adlen, byte* nsec, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_chacha20poly1305_ietf_decrypt(byte* m, ref ulong mlen_p,
            byte* nsec, byte* c, ulong clen, byte* ad, ulong adlen, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_chacha20poly1305_encrypt(byte* c, ref ulong clen_p, byte* m,
            ulong mlen, byte* ad, ulong adlen, byte* nsec, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_chacha20poly1305_decrypt(byte* m, ref ulong mlen_p,
            byte* nsec, byte* c, ulong clen, byte* ad, ulong adlen, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_xchacha20poly1305_ietf_encrypt(byte* c, ref ulong clen_p, byte* m,
            ulong mlen, byte* ad, ulong adlen, byte* nsec, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_xchacha20poly1305_ietf_decrypt(byte* m, ref ulong mlen_p,
            byte* nsec, byte* c, ulong clen, byte* ad, ulong adlen, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_aes256gcm_encrypt(byte* c, ref ulong clen_p, byte* m,
            ulong mlen, byte* ad, ulong adlen, byte* nsec, byte* npub, byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_aead_aes256gcm_decrypt(byte* m, ref ulong mlen_p,
            byte* nsec, byte* c, ulong clen, byte* ad, ulong adlen, byte* npub, byte* k);

        #endregion

        #region Stream

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_stream_salsa20_xor_ic(byte* c, byte* m, ulong mlen, byte* n, ulong ic,
            byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_stream_chacha20_xor_ic(byte* c, byte* m, ulong mlen, byte* n, ulong ic,
            byte* k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int crypto_stream_chacha20_ietf_xor_ic(byte* c, byte* m, ulong mlen, byte* n, uint ic,
            byte* k);

        #endregion
    }
}