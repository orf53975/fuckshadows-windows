using System;
using Fuckshadows.Util.Sockets.Buffer;

namespace Fuckshadows.Encryption
{
    public interface IEncryptor : IDisposable
    {
        /* length == -1 means not used */
        int AddrBufLength { set; get; }
        void Encrypt(ISegmentBufferManager bufferManager,
            ArraySegment<byte> buf, int length,
            ArraySegment<byte> outbuf, out int outlength);

        void Decrypt(ISegmentBufferManager bufferManager,
            ArraySegment<byte> buf, int length,
            ArraySegment<byte> outbuf, out int outlength);

        void EncryptUDP(ISegmentBufferManager bufferManager,
            ArraySegment<byte> buf, int length,
            ArraySegment<byte> outbuf, out int outlength);

        void DecryptUDP(ISegmentBufferManager bufferManager,
            ArraySegment<byte> buf, int length,
            ArraySegment<byte> outbuf, out int outlength);
    }
}
