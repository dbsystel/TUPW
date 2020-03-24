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
 *     2018-06-13: V1.0.0: Created. fhs
 *     2018-06-18: V1.0.1: A few more comments and a small optimization. fhs
 *     2018-08-15: V1.0.2: Added a few "finals". fhs
 *     2020-03-23: V1.1.0: Restructured source code according to DBS programming guidelines. fhs
 */
package dbscryptolib;

import java.util.Objects;

/**
 * Implement cryptographically safe array operations
 *
 * @author FrankSchwab, DB Systel GmbH
 * @version 1.1.0
 */
public final class SafeArrays {
   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Constant time byte array compare.
    *
    * <p>This method takes a constant time to compare two byte arrays, i.e. it will
    * take the same time to run if the arrays are equal and if they are not
    * equal. This makes it impossible to attack a cryptographic operation by
    * measuring the time it takes to complete a compare operation.</p>
    *
    * @param a First byte array to compare
    * @param b Second byte array to compare
    * @return {@code true}, if both byte arrays are equal, {@code false}, if not
    */
   public static boolean constantTimeEquals(final byte[] a, final byte[] b) throws NullPointerException {
      Objects.requireNonNull(a, "First byte array is null");
      Objects.requireNonNull(b, "Second byte array is null");

      // diff starts with a possible difference in the lengths
      int diff = a.length ^ b.length;

      final int minArrayLength = Math.min(a.length, b.length);

      // Now compare each and every byte with no shortcut and collect differences in diff
      for (int i = 0; i < minArrayLength; i++)
         diff |= a[i] ^ b[i];

      // Diff will only be 0 if bytes and lenghts were equal
      return diff == 0;
   }
}
