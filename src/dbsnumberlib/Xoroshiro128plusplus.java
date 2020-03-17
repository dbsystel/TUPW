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
 *
 * Changes:
 *     2020-02-27: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Check for null. fhs
 */

package dbsnumberlib;

import java.util.Objects;

/**
 * Xoroshiro128plusplus pseudo-random number generator
 *
 * @author Frank Schwab
 * @version 1.1.0
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
      initializeState(seed);
   }

   /**
    * Constructor for Xoroshiro128plusplus with seed
    *
    * @param seed Initial seed
    * @throws NullPointerException if {@code seed} is null
    */
   public Xoroshiro128plusplus(final Long seed) throws NullPointerException {
      Objects.requireNonNull(seed, "Seed is null");

      // In a real object oriented language one would place "this(seed.longValue());"
      // here. But this is Java, so it is not possible to do this.
      initializeState(seed.longValue());
   }

   /**
    * Unnecessary constructor method to initialize the state
    */
   private void initializeState(final long seed) {
      SplitMix64 sm64 = new SplitMix64(seed);

      m_State0 = sm64.nextLong();
      m_State1 = sm64.nextLong();
   }

   /*
    * Public methods
    */

   /**
    * Get next {@code long} pseudo-random number
    *
    * @return next pseudo-random long value
    */
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
}
