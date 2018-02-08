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
            if (offset + count > data.Length) throw new InvalidOperationException("out bound");
            unsafe
            {
                fixed (byte* ptr = data)
                {
                    Sodium.randombytes_buf(ptr + offset, count);
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