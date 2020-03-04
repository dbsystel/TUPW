/*
 * This is an implementation of the Xoroshiro128plusplus pseudo-random number generator
 * written in 2019 by David Blackman and Sebastiano Vigna.
 *
 * It is taken from the C source code at http://prng.di.unimi.it/xoroshiro128plusplus.c.
 *
 * The source code there has the following comment which is reproduced here:
 *
 * Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/>.
 *
 * This is xoroshiro128++ 1.0, one of our all-purpose, rock-solid,
 * small-state generators. It is extremely (sub-ns) fast and it passes all
 * tests we are aware of, but its state space is large enough only for
 * mild parallelism.
 *
 * For generating just floating-point numbers, xoroshiro128+ is even
 * faster (but it has a very mild bias, see notes in the comments).
 *
 * The state must be seeded so that it is not everywhere zero. If you have
 * a 64-bit seed, we suggest to seed a splitmix64 generator and use its
 * output to fill s.
 */

package dbsnumberlib;

/**
 * Xoroshiro128plusplus pseudo-random number generator
 *
 * @author Frank Schwab
 * @version 1.0.0
 */
@SuppressWarnings("UnusedAssignment")
public class Xoroshiro128plusplus extends SimplePseudoRandomNumberGenerator {
   /**
    * The state variables
    */
   long m_State0 = -1L;
   long m_State1 = 1L;

   /**
    * Constructor for Xoroshiro128plusplus with seed
    *
    * @param seed Initial seed
    */
   public Xoroshiro128plusplus(final long seed) {
      SplitMix64 sm64 = new SplitMix64(seed);

      m_State0 = sm64.nextLong();
      m_State1 = sm64.nextLong();
   }

   /**
    * Constructor for Xoroshiro128plusplus with seed
    *
    * @param seed Initial seed
    */
   public Xoroshiro128plusplus(final Long seed) {
      this(seed.longValue());
   }

   @Override
   public long nextLong() {
      final long s0 = m_State0;
      long s1 = m_State1;

      long result = s0 + s1;
      result = (result << 17 | result >>> 47) + s0;

      s1 ^= s0;

      m_State0 = (s0 << 49 | s0 >>> 15) ^ s1 ^ (s1 << 21);
      m_State1 = (s1 << 28 | s1 >>> 36);

      return result;
   }

   @Override
   public int nextInt() { return super.nextInt(); }

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
