using System;

namespace Fuckshadows.Encryption
{
    public static class RNG
    {
        public static void GetBytes(byte[] buf)
        {
            unsafe
            {
                fixed (byte* ptr = buf)
                {
                    Sodium.randombytes_buf(ptr, buf.Length);
                }
            }
        }

        public static void GetBytes(byte[] data, int offset, int count)
        {
            unsafe
            {
                fixed (byte* ptr = &data[offset])
                {
                    Sodium.randombytes_buf(ptr, count);
                }
            }
        }

        public static void GetBytes(byte[] buf, int len)
        {
            unsafe
            {
                fixed (byte* ptr = buf)
                {
                    Sodium.randombytes_buf(ptr, len);
                }
            }
        }
    }
}