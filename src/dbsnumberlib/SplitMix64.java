/*
 * This is an implementation of the Splitmix64 pseudo-random number generator
 * written in 2015 by Sebastiano Vigna.
 *
 * It is taken from the C source code at http://xoroshiro.di.unimi.it/splitmix64.c.
 *
 * The source code there has the following comment which is reproduced here:
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/>.
 *
 * This is a fixed-increment version of Java 8's SplittableRandom generator
 * See http://dx.doi.org/10.1145/2714064.2660195 and
 * http://docs.oracle.com/javase/8/docs/api/java/util/SplittableRandom.html
 *
 * It is a very fast generator passing BigCrush, and it can be useful if
 * for some reason you absolutely want 64 bits of state.
 */

package dbsnumberlib;

/**
 * Splitmix64 pseudo-random number generator
 *
 * @author Frank Schwab
 * @version 1.0.0
 */
public class SplitMix64 extends SimplePseudoRandomNumberGenerator {
   /**
    * State
    */
   private long m_State;

   /**
    * Creates a new instance.
    *
    * @param seed Initial seed.
    */
   public SplitMix64(final long seed) {
      m_State = seed;
   }

   /**
    * Creates a new instance.
    *
    * @param seed Initial seed.
    */
   public SplitMix64(final Long seed) {
      this(seed.longValue());
   }

   /**
    * Get next pseudo-random long value
    *
    * @return Pseudo-random long
    */
   @Override
   public long nextLong() {
      long z = (m_State += 0x9e3779b97f4a7c15L);
      z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
      z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
      return z ^ (z >>> 31);
   }

   @Override
   public int nextInt() {
      return super.nextInt();
   }

   @Override
   public short nextShort() {
      return super.nextShort();
   }

   @Override
   public byte nextByte() {
      return super.nextByte();
   }

   @Override
   public long nextLong(long fromInclusive, long toInclusive) { return super.nextLong(fromInclusive, toInclusive); }

   @Override
   public int nextInt(int fromInclusive, int toInclusive) { return super.nextInt(fromInclusive, toInclusive); }

   @Override
   public short nextShort(short fromInclusive, short toInclusive) { return super.nextShort(fromInclusive, toInclusive); }

   @Override
   public byte nextByte(byte fromInclusive, byte toInclusive) { return super.nextByte(fromInclusive, toInclusive); }
}