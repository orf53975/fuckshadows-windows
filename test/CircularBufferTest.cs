using System;
using FluentAssertions;
using NUnit.Framework;
using Fuckshadows.Encryption.CircularBuffer;

namespace test
{
    [TestFixture]
    public class CircularBufferTests
    {
        #region  Tests

        [Test]
        public void CapacityExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expected;

            expected = 3;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Put(4);

            // act & assert
            Assert.That(() => target.Capacity = expected, Throws.TypeOf<ArgumentOutOfRangeException>());

        }

        [Test]
        public void CapacityExistingItemsTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedCapacity;
            byte[] expectedItems;
            int expectedSize;

            expectedCapacity = 10;
            expectedSize = 2;
            expectedItems = new byte[]
                            {
                        1,
                        2
                      };

            target = new ByteCircularBuffer(3);
            target.Put(1);
            target.Put(2);

            // act
            target.Capacity = expectedCapacity;

            // assert
            target.Capacity.Should().
                   Be(expectedCapacity);
            target.Size.Should().
                   Be(expectedSize);
            target.ToArray().
                   Should().
                   Equal(expectedItems);
        }

        [Test]
        public void CapacitySmallerTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expected;

            expected = 3;

            target = new ByteCircularBuffer(10);

            // act
            target.Capacity = expected;

            // assert
            target.Capacity.Should().
                   Be(expected);
        }

        [Test]
        public void CapacityTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expected;

            expected = 10;

            target = new ByteCircularBuffer(3);

            // act
            target.Capacity = expected;

            // assert
            target.Capacity.Should().
                   Be(expected);
        }

        [Test]
        public void ClearTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;

            expectedHead = 0;
            expectedSize = 0;
            expectedTail = 0;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            target.Clear();

            // assert
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void ConstructorCapacityExceptionTest()
        {
            // act & assert
            Assert.That(() => new ByteCircularBuffer(-1), Throws.TypeOf<ArgumentException>());
        }

        [Test]
        public void ContainsAfterGetTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            target.Get();

            // act
            actual = target.Contains(1);

            // assert
            actual.Should().
                   BeFalse();
        }

        [Test]
        public void ContainsNegativeTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actual = target.Contains(4);

            // assert
            actual.Should().
                   BeFalse();
        }

        [Test]
        public void ContainsTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actual = target.Contains(1);

            // assert
            actual.Should().
                   BeTrue();
        }

        [Test]
        public void CopyToArrayWithOffsetAndCountTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedHead;
            byte[] expected;
            byte[] actual;
            int offset;
            int count;
            int index;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   5,
                   1,
                   2,
                   7
                 };
            actual = new byte[]
                     {
                 5,
                 0,
                 0,
                 7
               };

            expectedHead = 0;
            index = 0;
            offset = 1;
            count = 2;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            target.CopyTo(index, actual, offset, count);

            // assert
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeTrue();
            target.Contains(2).
                   Should().
                   BeTrue();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
        }

        [Test]
        public void CopyToArrayWithOffsetTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedHead;
            byte[] expected;
            byte[] actual;
            int offset;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   5,
                   1,
                   2,
                   3
                 };
            actual = new byte[]
                     {
                 5,
                 0,
                 0,
                 0
               };

            expectedHead = 0;
            offset = 1;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            target.CopyTo(actual, offset);

            // assert
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeTrue();
            target.Contains(2).
                   Should().
                   BeTrue();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
        }

        [Test]
        public void CopyToArrayWithStartingIndexOffsetAndCountTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedHead;
            byte[] expected;
            byte[] actual;
            int offset;
            int count;
            int index;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   5,
                   2,
                   3,
                   7
                 };
            actual = new byte[]
                     {
                 5,
                 0,
                 0,
                 7
               };

            expectedHead = 0;
            index = 1;
            offset = 1;
            count = 2;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            target.CopyTo(index, actual, offset, count);

            // assert
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeTrue();
            target.Contains(2).
                   Should().
                   BeTrue();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
        }

        [Test]
        public void CopyToExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte[] actual;
            int offset;
            int count;
            int index;

            target = new ByteCircularBuffer(10);
            actual = new byte[target.Capacity];

            index = 0;
            offset = 0;
            count = 4;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act & assert
            Assert.That(() => target.CopyTo(index, actual, offset, count), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void CopyToTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedHead;
            byte[] expected;
            byte[] actual;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   1,
                   2,
                   3
                 };
            expectedHead = 0;

            actual = new byte[3];

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            target.CopyTo(actual);

            // assert
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeTrue();
            target.Contains(2).
                   Should().
                   BeTrue();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
        }

        [Test]
        public void EmptyBufferTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte[] expected;
            byte[] actual;

            expected = this.GenerateRandomData(100);

            target = new ByteCircularBuffer(expected.Length);
            target.Put(expected);

            actual = new byte[target.Size];

            // act
            target.Get(actual);

            // assert
            actual.Should().
                   Equal(expected);
            target.Size.Should().
                   Be(0);
        }

        [Test]
        public void GetEmptyExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Get();
            target.Get();
            target.Get();

            // act & assert
            Assert.That(() => target.Get(), Throws.TypeOf<InvalidOperationException>());
        }

        

        [Test]
        public void GetNextTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte expected;
            byte actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Get();

            expected = 2;

            // act
            actual = target.Get();

            // assert
            actual.Should().
                   Be(expected);
        }

        [Test]
        public void GetResetHeadAtCapacityTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte expected;
            byte actual;
            int expectedHead;

            target = new ByteCircularBuffer(3);

            expected = 3;
            expectedHead = 0;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            target.Get();
            target.Get();

            // act
            actual = target.Get();

            // assert
            actual.Should().
                   Be(expected);
            target.Head.Should().
                   Be(expectedHead);
        }

        [Test]
        public void GetTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            byte expected;
            byte actual;

            target = new ByteCircularBuffer(10);

            expected = 1;
            expectedHead = 1;
            expectedSize = 2;
            expectedTail = 3;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actual = target.Get();

            // assert
            actual.Should().
                   Be(expected);
            target.Contains(1).
                   Should().
                   BeFalse();
            target.Contains(2).
                   Should().
                   BeTrue();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void GetWithArrayAndOffsetTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            int expectedElements;
            int actualElements;
            byte[] expected;
            byte[] actual;
            int offset;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   0,
                   1,
                   2
                 };
            expectedHead = 2;
            expectedSize = 2;
            expectedTail = 4;
            expectedElements = 2;

            offset = 1;

            actual = new byte[3];

            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Put(4);

            // act
            actualElements = target.Get(actual, offset, expectedElements);

            // assert
            actualElements.Should().
                           Be(expectedElements);
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeFalse();
            target.Contains(2).
                   Should().
                   BeFalse();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Contains(4).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void GetWithArrayTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            int expectedElements;
            int actualElements;
            byte[] expected;
            byte[] actual;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   1,
                   2
                 };
            expectedHead = 2;
            expectedSize = 1;
            expectedTail = 3;
            expectedElements = 2;

            actual = new byte[expectedElements];

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actualElements = target.Get(actual);

            // assert
            actualElements.Should().
                           Be(expectedElements);
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeFalse();
            target.Contains(2).
                   Should().
                   BeFalse();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void GetWithCountTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            byte[] expected;
            byte[] actual;

            target = new ByteCircularBuffer(10);

            expected = new byte[]
                       {
                   1,
                   2
                 };
            expectedHead = 2;
            expectedSize = 1;
            expectedTail = 3;

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actual = target.Get(2);

            // assert
            actual.Should().
                   Equal(expected);
            target.Contains(1).
                   Should().
                   BeFalse();
            target.Contains(2).
                   Should().
                   BeFalse();
            target.Contains(3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void IsEmptyNegativeTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);

            // act
            actual = target.IsEmpty;

            // assert
            actual.Should().
                   BeTrue();
        }

        [Test]
        public void IsEmptyTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);

            target.Put(1);

            // act
            actual = target.IsEmpty;

            // assert
            actual.Should().
                   BeFalse();
        }

        [Test]
        public void IsFullNegativeTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(10);

            target.Put(1);

            // act
            actual = target.IsFull;

            // assert
            actual.Should().
                   BeFalse();
        }

        [Test]
        public void IsFullTest()
        {
            // arrange
            ByteCircularBuffer target;
            bool actual;

            target = new ByteCircularBuffer(3);

            target.Put(1);
            target.Put(2);
            target.Put(3);

            // act
            actual = target.IsFull;

            // assert
            actual.Should().
                   BeTrue();
        }


        [Test]
        public void PeekArrayEmptyExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;

            target = new ByteCircularBuffer(10);

            // act & assert
            Assert.That(() => target.Peek(2), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void PeekArrayTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte[] expected;
            byte[] actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            expected = new byte[]
                       {
                   1,
                   2
                 };

            // act
            actual = target.Peek(2);

            // assert
            actual.Should().
                   Equal(expected);
        }

        [Test]
        public void PeekEmptyExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;

            target = new ByteCircularBuffer(10);

            // act & assert
            Assert.That(() => target.Peek(), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void PeekLastEmptyExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;

            target = new ByteCircularBuffer(10);

            // act & assert
            Assert.That(() => target.PeekLast(), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void PeekLastTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte expected;
            byte actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            expected = 3;

            // act
            actual = target.PeekLast();

            // assert
            actual.Should().
                   Be(expected);
        }

        [Test]
        public void PeekLastWrapBufferTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte expected;
            byte actual;

            target = new ByteCircularBuffer(3);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            expected = 3;

            // act
            actual = target.PeekLast();

            // assert
            actual.Should().
                   Be(expected);
        }

        [Test]
        public void PeekTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte expected;
            byte actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            expected = 1;

            // act
            actual = target.Peek();

            // assert
            actual.Should().
                   Be(expected);
        }

        [Test]
        public void PutArrayExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte[] expected;

            expected = this.GenerateRandomData(100);

            target = new ByteCircularBuffer(expected.Length);
            target.Put(byte.MaxValue);

            // act & assert
            Assert.That(() => target.Put(expected), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void PutArrayTest()
        {
            // arrange

            byte[] expected = this.GenerateRandomData(100);

            ByteCircularBuffer target = new ByteCircularBuffer(expected.Length);

            // act
            target.Put(expected);

            // assert
            target.ToArray().
                   Should().
                   Equal(expected);
        }

        [Test]
        public void PutBufferFullExceptionTest()
        {
            // arrange
            ByteCircularBuffer target;

            target = new ByteCircularBuffer(2);

            target.Put(1);
            target.Put(2);

            // act & assert
            Assert.That(() => target.Put(3), Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void PutMultipleTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            byte expected1;
            byte expected2;
            byte expected3;

            target = new ByteCircularBuffer(10);

            expected1 = 1;
            expected2 = 2;
            expected3 = 3;
            expectedHead = 0;
            expectedSize = 3;
            expectedTail = 3;

            // act
            target.Put(expected1);
            target.Put(expected2);
            target.Put(expected3);

            // assert
            target.Contains(expected1).
                   Should().
                   BeTrue();
            target.Contains(expected2).
                   Should().
                   BeTrue();
            target.Contains(expected3).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void PutTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expectedSize;
            int expectedHead;
            int expectedTail;
            byte expected;

            target = new ByteCircularBuffer(10);

            expected = 1;
            expectedHead = 0;
            expectedSize = 1;
            expectedTail = 1;

            // act
            target.Put(expected);

            // assert
            target.Contains(expected).
                   Should().
                   BeTrue();
            target.Head.Should().
                   Be(expectedHead);
            target.Tail.Should().
                   Be(expectedTail);
            target.Size.Should().
                   Be(expectedSize);
        }

        [Test]
        public void SizeTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expected;
            int actual;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);

            expected = 3;

            // act
            actual = target.Size;

            // assert
            actual.Should().
                   Be(expected);
        }

        [Test]
        public void SkipTest()
        {
            // arrange
            ByteCircularBuffer target;
            int expected;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Put(4);

            expected = 2;

            // act
            target.Skip(2);

            // assert
            target.Head.Should().
                   Be(expected);
        }



        [Test]
        public void ToArrayTest()
        {
            // arrange
            ByteCircularBuffer target;
            byte[] actual;
            byte[] expected;

            target = new ByteCircularBuffer(10);
            target.Put(1);
            target.Put(2);
            target.Put(3);
            target.Put(4);

            expected = new byte[]
                       {
                   1,
                   2,
                   3,
                   4
                 };

            // act
            actual = target.ToArray();

            // assert
            actual.Should().
                   Equal(expected);
        }

        #endregion

        #region Test Helpers

        private Random _random;

        [OneTimeTearDown]
        public void CleanUp()
        {
            _random = null;
        }

        [OneTimeSetUp]
        public void Setup()
        {
            _random = new Random();
        }

        protected byte[] GenerateRandomData(int length)
        {
            var result = new byte[length];
            _random.NextBytes(result);

            return result;
        }

        #endregion
    }
}
