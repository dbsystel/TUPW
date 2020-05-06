/*
 * This is an implementation of the Splitmix64 pseudo-random number generator
 * written in 2015 by Sebastiano Vigna.
 *
 * It is derived from the C source code at http://xoroshiro.di.unimi.it/splitmix64.c.
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
 *
 * Changes:
 *     2020-02-27: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Check for null. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 */

package de.db.bcm.tupw.numbers;

import java.util.Objects;

/**
 * Splitmix64 pseudo-random number generator
 *
 * <p>It is derived from the <a href="http://xoroshiro.di.unimi.it/splitmix64.c">C source code</a>.</p>
 *
 * @author Frank Schwab
 * @version 1.2.0
 */
public class SplitMix64 extends SimplePseudoRandomNumberGenerator {
   //******************************************************************
   // Instance variables
   //******************************************************************

   /**
    * State
    */
   private long m_State;


   //******************************************************************
   // Constructors
   //******************************************************************

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
    * @throws NullPointerException if {@code seed} is null
    */
   public SplitMix64(final Long seed) throws NullPointerException {
      Objects.requireNonNull(seed, "Seed is null");

      // In a real object oriented language one would place "this(seed.longValue());"
      // here. But this is Java, so it is not possible to do this.
      m_State = seed.longValue();
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get next pseudo-random {@code long} value
    *
    * @return Pseudo-random {@code long}
    */
   @Override
   public long nextLong() {
      long z = m_State += 0x9e3779b97f4a7c15L;
      z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
      z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
      return z ^ (z >>> 31);
   }
}
