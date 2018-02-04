using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using Fuckshadows.Controller;
using Fuckshadows.Properties;
using Fuckshadows.Util;

namespace Fuckshadows.Encryption
{
    public static class MbedTLS
    {
#if _X64
        private const string DLLNAME = "libfscrypto64.dll";
#else
        private const string DLLNAME = "libfscrypto.dll";
#endif

        public const int MBEDTLS_ENCRYPT = 1;
        public const int MBEDTLS_DECRYPT = 0;

        static MbedTLS()
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
        }

        public static byte[] MD5(byte[] input)
        {
            byte[] output = new byte[16];
            md5(input, (uint) input.Length, output);
            return output;
        }

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibrary(string path);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void md5(byte[] input, uint ilen, byte[] output);

        /// <summary>
        /// Get cipher ctx size for unmanaged memory allocation
        /// </summary>
        /// <returns></returns>
        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_get_size_ex();

        #region Cipher layer wrappers

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cipher_info_from_string(string cipher_name);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void cipher_init(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_setup(IntPtr ctx, IntPtr cipher_info);

        // XXX: Check operation before using it
        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_setkey(IntPtr ctx, byte[] key, int key_bitlen, int operation);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_set_iv(IntPtr ctx, byte[] iv, int iv_len);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_reset(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_update(IntPtr ctx, byte[] input, int ilen, byte[] output, ref int olen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void cipher_free(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_auth_encrypt(IntPtr ctx,
            byte[] iv, uint iv_len,
            IntPtr ad, uint ad_len,
            byte[] input, uint ilen,
            byte[] output, ref uint olen,
            byte[] tag, uint tag_len);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int cipher_auth_decrypt(IntPtr ctx,
            byte[] iv, uint iv_len,
            IntPtr ad, uint ad_len,
            byte[] input, uint ilen,
            byte[] output, ref uint olen,
            byte[] tag, uint tag_len);

        #endregion
    }
}