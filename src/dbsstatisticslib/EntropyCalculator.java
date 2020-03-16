/*
 * Copyright (c) 2020, DB Systel GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2020-02-28: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Handle null arguments. fhs
 */

package dbsstatisticslib;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class to calculate the entropy of byte arrays
 *
 * @author Frank Schwab
 * @version 1.0.0
 */
public class EntropyCalculator {

   /*
    * Constants
    */
   private final double LOG_2 = Math.log(2);

   /*
    * Instance variables
    */
   private final int[] m_Counter = new int[256];  // Array of how many times a specific byte value was counted
   private int m_ByteCount = 0;             // Number of bytes that have been added to the statistic

   /**
    * Reset the entropy statistics
    */
   public void reset() {
      Arrays.fill(m_Counter, 0);

      m_ByteCount = 0;
   }

   /**
    * Add bytes of a byte array to the entropy calculation starting from a specified index and
    * ending at another specified index
    *
    * <p>Here we use the strange and counterintuitive Java habit to specify the last index
    * as the one that should <b>not</b> be included.</p>
    *
    * @param aByteArray Byte array to add to the calculation
    * @param fromIndex  Start index (inclusive)
    * @param toIndex    End index (exclusive)
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public void addBytes(final byte[] aByteArray, final int fromIndex, final int toIndex) throws NullPointerException {
      Objects.requireNonNull(aByteArray, "Byte array is null");

      byte aByte;
      int  counterIndex;

      for (int i = fromIndex; i < toIndex; i++) {
         counterIndex = aByteArray[i] & 0xff; // Explicitly calculate the index ...

         m_Counter[counterIndex]++;   // ... as the compiler converts this to "m_Counter[counterIndex] = m_Counter[counterIndex] + 1"
      }

      m_ByteCount += toIndex - fromIndex;
   }

   /**
    * Add bytes of a byte array to entropy calculation starting from a specified index
    *
    * @param aByteArray Byte array to add to the calculation
    * @param fromIndex  Start index (inclusive)
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public void addBytes(final byte[] aByteArray, final int fromIndex) throws NullPointerException {
      addBytes(aByteArray, fromIndex, aByteArray.length);
   }

   /**
    * Add all bytes of a byte array to the entropy calculation
    *
    * @param aByteArray Byte array to add to the calculation
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public void addBytes(final byte[] aByteArray) throws NullPointerException {
      addBytes(aByteArray, 0, aByteArray.length);
   }

   /**
    * Get the entropy per byte
    *
    * @return Entropy per byte
    */
   public double getEntropy() {
      double result = 0.0;

      if (m_ByteCount > 0) {
         final double inverseByteCount = 1.0 / m_ByteCount;

         double p;

         for (int value : m_Counter) {
            p = value * inverseByteCount;

            if (p != 0.0)
               result -= p * Math.log(p);
         }
      }

      return result / LOG_2;
   }

   /**
    * Get the relative entropy
    *
    * <p>The relative entropy is a value between 0.0 and 1.0 that says how much of the
    * maximum possible entropy the actual entropy value is.</p>
    *
    * @return Relative entropy
    * @throws UnsupportedOperationException if there are not enough bytes sampled
    */
   public double getRelativeEntropy() throws UnsupportedOperationException {
      if (m_ByteCount > 1)
         return getEntropy() / Math.log(m_ByteCount) * LOG_2;
      else
         throw new UnsupportedOperationException("At least 2 bytes are needed to calculate the relative entropy");
   }

   /**
    * Gets the information content in bits
    *
    * <P>Information content is the entropy per byte times the number of bytes</P>
    *
    * @return Information content in bits
    */
   public int getInformationInBits() {
      int result = 0;

      if (m_ByteCount > 0)
         result = (int) Math.round((getEntropy() * m_ByteCount));

      return result;
   }
}
