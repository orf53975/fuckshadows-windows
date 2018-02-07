using System;
using static Fuckshadows.Util.Utils;

namespace Fuckshadows.Util.Sockets.Buffer
{
    /// <summary>
    /// Provides extension methods for <see cref="ArraySegment{T}"/>.
    /// </summary>
    public static class ArraySegmentExtensions
    {
        /// <summary>
        /// Creates an array segment referencing this array.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="array">The array.</param>
        /// <param name="offset">The offset in this array where the segment begins. Must be in the range <c>[0, <paramref name="array"/>.Length]</c>.</param>
        /// <param name="count">The length of the segment. Must be in the range <c>[0, <paramref name="array"/>.Length - <paramref name="offset"/>]</c>.</param>
        /// <returns>A new array segment.</returns>
        public static ArraySegment<T> AsArraySegment<T>(this T[] array, int offset, int count) => new ArraySegment<T>(array, offset, count);

        /// <summary>
        /// Creates an array segment referencing this array.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="array">The array.</param>
        /// <param name="offset">The offset in this array where the segment begins. Defaults to <c>0</c> (the beginning of the array). Must be in the range <c>[0, <paramref name="array"/>.Length]</c>.</param>
        /// <returns>A new array segment.</returns>
        public static ArraySegment<T> AsArraySegment<T>(this T[] array, int offset = 0) => new ArraySegment<T>(array, offset, array.Length - offset);

        /// <summary>
        /// Creates a new array segment by taking a number of elements from the beginning of this array segment.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="segment">The array segment.</param>
        /// <param name="count">The number of elements in the new array segment. This must be in the range <c>[0, <paramref name="segment"/>.Count]</c>.</param>
        /// <returns>The new array segment.</returns>
        public static ArraySegment<T> Take<T>(this ArraySegment<T> segment, int count) => new ArraySegment<T>(segment.Array, segment.Offset, count);

        /// <summary>
        /// Creates a new array segment by skipping a number of elements from the beginning of this array segment.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="segment">The array segment.</param>
        /// <param name="count">The number of elements to skip. This must be in the range <c>[0, <paramref name="segment"/>.Count]</c>.</param>
        /// <returns>The new array segment.</returns>
        public static ArraySegment<T> Skip<T>(this ArraySegment<T> segment, int count) =>
            new ArraySegment<T>(segment.Array, segment.Offset + count, segment.Count - count);

        /// <summary>
        /// Creates a new array segment by skipping a number of elements and then taking a number of elements from this array segment.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="segment">The array segment.</param>
        /// <param name="skipCount">The number of elements to skip. This must be in the range <c>[0, <paramref name="segment"/>.Count]</c>.</param>
        /// <param name="takeCount">The number of elements in the new array segment. This must be in the range <c>[0, <paramref name="segment"/>.Count - <paramref name="skipCount"/>]</c>.</param>
        /// <returns>The new array segment.</returns>
        public static ArraySegment<T> Slice<T>(this ArraySegment<T> segment, int skipCount, int takeCount) =>
            new ArraySegment<T>(segment.Array, segment.Offset + skipCount, takeCount);

        /// <summary>
        /// Creates a new array segment by taking a number of elements from the end of this array segment.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="segment">The array segment.</param>
        /// <param name="count">The number of elements in the new array segment. This must be in the range <c>[0, <paramref name="segment"/>.Count]</c>.</param>
        /// <returns>The new array segment.</returns>
        public static ArraySegment<T> TakeLast<T>(this ArraySegment<T> segment, int count) => segment.Skip(segment.Count - count);

        /// <summary>
        /// Creates a new array segment by skipping a number of elements from the end of this array segment.
        /// </summary>
        /// <typeparam name="T">The type of elements contained in the array.</typeparam>
        /// <param name="segment">The array segment.</param>
        /// <param name="count">The number of elements to skip. This must be in the range <c>[0, <paramref name="segment"/>.Count]</c>.</param>
        /// <returns>The new array segment.</returns>
        public static ArraySegment<T> SkipLast<T>(this ArraySegment<T> segment, int count) => segment.Take(segment.Count - count);

        /// <summary>
        /// Creates a new array containing the elements in this byte array segment.
        /// </summary>
        /// <param name="segment">The byte array segment.</param>
        /// <returns>The new array.</returns>
        public static byte[] ToByteArray(this ArraySegment<byte> segment)
        {
            return ToByteArray(segment, segment.Count);
        }

        public static byte[] ToByteArray(this ArraySegment<byte> segment, int count)
        {
            var realCount = count <= segment.Count ? count : segment.Count;
            var ret = new byte[realCount];
            PerfByteCopy(segment.Array, segment.Offset, ret, 0, realCount);
            return ret;
        }

        public static bool EqualsWithCount(ArraySegment<byte> src, int srcOff, ArraySegment<byte> dst, int dstOff, int count)
        {
            var arrMin = Math.Min(src.Count - srcOff, dst.Count - dstOff);
            if (count > arrMin) throw new InvalidOperationException("no enough space");
            for (var i = 0; i < count; i++)
            {
                if (dst.Array[dst.Offset + dstOff + i] != src.Array[src.Offset + srcOff + i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Copy bytes between two <see cref="ArraySegment{T}"/>
        /// </summary>
        /// <param name="src"></param>
        /// <param name="srcOff">Offset based on <see cref="ArraySegment{T}"/>'s view, not the offset based on underlying array</param>
        /// <param name="dst"></param>
        /// <param name="dstOff">Offset based on <see cref="ArraySegment{T}"/>'s view, not the offset based on underlying array</param>
        /// <param name="count">bytes to copy</param>
        public static void BlockCopy(ArraySegment<byte> src, int srcOff, ArraySegment<byte> dst, int dstOff, int count)
        {
            var arrMin = Math.Min(src.Count - srcOff, dst.Count - dstOff);
            if (count > arrMin) throw new InvalidOperationException("no enough space");
            PerfByteCopy(src.Array, src.Offset + srcOff, dst.Array, dst.Offset + dstOff,
                count);
        }
    }
}
