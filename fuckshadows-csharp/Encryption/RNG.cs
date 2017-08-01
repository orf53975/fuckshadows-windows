using System;

namespace Fuckshadows.Encryption
{
    public static class RNG
    {
        public static void GetBytes(byte[] buf)
        {
            Sodium.randombytes_buf(buf, buf.Length);
        }

        public static void GetBytes(byte[] data, int offset, int count)
        {
            byte[] tmp = new byte[count];
            Sodium.randombytes_buf(tmp, count);
            Buffer.BlockCopy(tmp, 0, data, offset, count);
        }

        public static void GetBytes(byte[] buf, int len)
        {
            Sodium.randombytes_buf(buf, len);
        }
    }
}