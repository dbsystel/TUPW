package dbsnumberlib;

public class SimplePseudoRandomNumberGenerator {
   public long nextLong() {
      throw new UnsupportedOperationException();
   }  // This method *must* be overridden

   public int nextInt() {
      return (int) (this.nextLong() >>> 32);
   }

   public short nextShort() {
      return (short) (this.nextLong() >>> 48);
   }

   public byte nextByte() {
      return (byte) (this.nextLong() >>> 56);
   }

   /**
    * Get a pseudo-random long in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public long nextLong(long fromInclusive, long toInclusive) {
      long result;

      // Calculate the size of the interval that should be returned
      final long size = toInclusive - fromInclusive + 1L;  // This may be negative
      final long maxValue = size - 1L;  // This may be negative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = (this.nextLong() & maxValue);
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         long mask = -1L;
         mask >>>= Long.numberOfLeadingZeros(maxValue | 1L);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = (this.nextLong() & mask);
         } while (Long.compareUnsigned(result, maxValue) > 0);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return result + fromInclusive;
   }

   /**
    * Get a pseudo-random int in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public int nextInt(int fromInclusive, int toInclusive) {
      long result;

      // Calculate the size of the interval that should be returned
      final long size = (long) toInclusive - (long) fromInclusive + 1L;  // This is always nonnegative
      final long maxValue = size - 1L;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = this.nextInt() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         long mask = -1;
         mask >>>= Long.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextInt() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (int) (result + fromInclusive);
   }

   /**
    * Get a pseudo-random short in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public short nextShort(short fromInclusive, short toInclusive) {
      int result;

      // Calculate the size of the interval that should be returned
      final int size = toInclusive - fromInclusive + 1;  // This is always nonnegative
      final int maxValue = size - 1;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = this.nextShort() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         int mask = -1;
         mask >>>= Integer.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextShort() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (short) (result + fromInclusive);
   }

   /**
    * Get a pseudo-random byte in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public byte nextByte(byte fromInclusive, byte toInclusive) {
      int result;

      // Calculate the size of the interval that should be returned
      final int size = toInclusive - fromInclusive + 1;  // This is always nonnegative
      final int maxValue = size - 1;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = this.nextByte() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         int mask = -1;
         mask >>>= Integer.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextByte() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (byte) (result + fromInclusive);
   }
}
