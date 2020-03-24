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
 *     2018-08-16: V1.0.0: Created. fhs
 *     2019-08-06: V1.0.2: Use SecureRandomFactory. fhs
 *     2019-08-23: V1.0.3: Use SecureRandom singleton. fhs
 *     2020-02-11: V1.1.0: Strengthen blinding length tests. fhs
 *     2020-03-13: V1.2.0: Added checks for null. fhs
 *     2020-03-19: V1.3.0: Removed ByteArrayOutputStream. fhs
 *     2020-03-20: V1.4.0: Refactored blinded bytes build process. fhs
 *     2020-03-23: V1.5.0: Restructured source code according to DBS programming guidelines. fhs
 */
package dbscryptolib;

import dbsnumberlib.PackedUnsignedInteger;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements blinding for byte arrays
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.5.0
 */
public class ByteArrayBlinding {
   //******************************************************************
   // Private constants
   //******************************************************************

   /**
    * Class level secure pseudo random number generator
    */
   private final static SecureRandom SECURE_PRNG = SecureRandomFactory.getSensibleSingleton();

   /*
    * Constants for error messages
    */
   private final static String ERROR_MESSAGE_INVALID_ARRAY = "Invalid blinded byte array";
   private final static String ERROR_MESSAGE_INVALID_MIN_LENGTH = "Invalid minimum length";

   /*
    * Constants for indexing and lengths
    */
   private final static int INDEX_LENGTHS_PREFIX_LENGTH = 0;
   private final static int INDEX_LENGTHS_POSTFIX_LENGTH = 1;
   private final static int LENGTHS_LENGTH = 2;

   private final static int INDEX_SOURCE_PREFIX_LENGTH = 0;
   private final static int INDEX_SOURCE_POSTFIX_LENGTH = 1;
   private final static int INDEX_SOURCE_PACKED_LENGTH = 2;

   private final static int MAX_NORMAL_SINGLE_BLINDING_LENGTH = 15;   // This needs to be a power of 2 minus 1

   private final static int MAX_MINIMUM_LENGTH = 256;


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Add blinders to a byte array
    *
    * <p>Note: There may be no blinding, at all! I.e. the "blinded" array is the same, as the source array
    * This behaviour is intentional. So an attacker will not known, whether there was blinding, or not.</p>
    *
    * @param sourceBytes   Source bytes to blinding
    * @param minimumLength Minimum length of blinded array
    * @return Blinded byte array
    * @throws IllegalArgumentException if minimum length is too small or too large
    */
   public static byte[] buildBlindedByteArray(final byte[] sourceBytes, final int minimumLength) throws IllegalArgumentException {
      checkMinimumLength(minimumLength);

      final byte[] packedSourceLength = PackedUnsignedInteger.fromInteger(sourceBytes.length);

      final int[] blindingLength = getBalancedBlindingLengths(packedSourceLength.length, sourceBytes.length, minimumLength);

      final byte[] prefixBlinding = createBlinding(blindingLength[INDEX_LENGTHS_PREFIX_LENGTH]);
      final byte[] postfixBlinding = createBlinding(blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH]);

      final int resultLength = 2 + packedSourceLength.length + prefixBlinding.length + sourceBytes.length + postfixBlinding.length;

      final byte[] result = new byte[resultLength];

      result[0] = (byte) prefixBlinding.length;
      result[1] = (byte) postfixBlinding.length;

      int resultIndex = 2;

      resultIndex += copyByteArrayAndZapSource(packedSourceLength, result, resultIndex);

      resultIndex += copyByteArrayAndZapSource(prefixBlinding, result, resultIndex);

      resultIndex += copyByteArray(sourceBytes, result, resultIndex);

      copyByteArrayAndZapSource(postfixBlinding, result, resultIndex);

      return result;
   }

   /**
    * Remove blinders from a byte array
    *
    * @param sourceBytes Blinded byte array
    * @return Byte array without blinders
    * @throws IllegalArgumentException if the source byte array is not correctly formatted
    * @throws NullPointerException     if {@code sourceBytes} is {@code null}
    */
   public static byte[] unBlindByteArray(final byte[] sourceBytes) throws IllegalArgumentException, NullPointerException {
      Objects.requireNonNull(sourceBytes, "Source bytes is null");

      if (sourceBytes.length > LENGTHS_LENGTH) {
         final int packedNumberLength = PackedUnsignedInteger.getExpectedLength(sourceBytes[INDEX_SOURCE_PACKED_LENGTH]);

         if (sourceBytes[INDEX_SOURCE_PREFIX_LENGTH] >= 0) {
            // No. of bytes to skip is the blinding prefix length plus the two length bytes plus the source length
            final int prefixBlindingLength = sourceBytes[INDEX_SOURCE_PREFIX_LENGTH] + 2 + packedNumberLength;

            if (sourceBytes[INDEX_SOURCE_POSTFIX_LENGTH] >= 0) {
               final int postfixBlindingLength = sourceBytes[INDEX_SOURCE_POSTFIX_LENGTH];

               final int totalBlindingsLength = prefixBlindingLength + postfixBlindingLength;
               final int dataLength = PackedUnsignedInteger.toIntegerFromArray(sourceBytes, INDEX_SOURCE_PACKED_LENGTH);

               // The largest number in the following addition can only be just over 1073741823
               // This can never overflow into negative values
               if ((totalBlindingsLength + dataLength) <= sourceBytes.length)
                  return Arrays.copyOfRange(sourceBytes, prefixBlindingLength, dataLength + prefixBlindingLength);
            }
         }
      }

      throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_ARRAY);
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Check the validity of the requested minimum length
    *
    * @param minimumLength Requested minimum length
    * @throws IllegalArgumentException if minimum length is too small or too large
    */
   private static void checkMinimumLength(final int minimumLength) throws IllegalArgumentException {
      if (minimumLength < 0)
         throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_MIN_LENGTH);
      else if (minimumLength > MAX_MINIMUM_LENGTH)
         throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_MIN_LENGTH);
   }

   /**
    * Get the length for a blinding part
    *
    * @return Length for blinding
    */
   private static int getBlindingLength() {
      return SECURE_PRNG.nextInt() & MAX_NORMAL_SINGLE_BLINDING_LENGTH;
   }

   /**
    * Adapt blinding lengths to minimum length
    *
    * <p>The result will be returned in the array of blinding lengths</p>
    * <p>This may be much larger than MAX_NORMAL_SINGLE_BLINDING_LENGTH and is always smaller
    * than (MAX_MINIMUM_LENGTH >>> 1).</p>
    *
    * @param blindingLength Array of blinding lengths (just because Java is unable to have return parameters)
    * @param sourceLengthLength Length of the source length
    * @param sourceLength       Length of source
    * @param minimumLength      Required minimum length
    */
   private static void adaptBlindingLengthsToMinimumLength(final int[] blindingLength, final int sourceLengthLength, final int sourceLength, final int minimumLength) {
      final int combinedLength = 2 + sourceLengthLength + blindingLength[INDEX_LENGTHS_PREFIX_LENGTH] + sourceLength + blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH];

      if (combinedLength < minimumLength) {
         final int diff = minimumLength - combinedLength;
         final int halfDiff = diff >>> 1;

         blindingLength[INDEX_LENGTHS_PREFIX_LENGTH] += halfDiff;
         blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH] += halfDiff;

         // Adjust for odd difference
         if ((diff & 1) != 0)
            if ((diff & 2) != 0)
               blindingLength[INDEX_LENGTHS_PREFIX_LENGTH]++;
            else
               blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH]++;
      }
   }

   /**
    * Create blinding lengths so that their combined lengths are at least minimum length
    *
    * @param sourceLengthLength Length of the source length
    * @param sourceLength       Length of source
    * @param minimumLength      Required minimum length
    */
   private static int[] getBalancedBlindingLengths(final int sourceLengthLength, final int sourceLength, final int minimumLength) {
      // Java is unable to return multiple values, so an array has to be used to return them
      final int[] result = new int[LENGTHS_LENGTH];

      result[INDEX_LENGTHS_PREFIX_LENGTH] = getBlindingLength();
      result[INDEX_LENGTHS_POSTFIX_LENGTH] = getBlindingLength();

      // If minimumLength is greater than 0 adapt blinding lengths to be at least minimum length when combined.
      if (minimumLength > 0)
         adaptBlindingLengthsToMinimumLength(result, sourceLengthLength, sourceLength, minimumLength);

      return result;
   }

   /**
    * Copy a byte array into another byte array
    *
    * @param sourceBytes      Source byte array
    * @param destinationBytes Destination byte array
    * @param startToIndex     Start index in the destination byte array
    * @return Length of the source bytes
    */
   private static int copyByteArray(final byte[] sourceBytes, final byte[] destinationBytes, final int startToIndex) {
      System.arraycopy(sourceBytes, 0, destinationBytes, startToIndex, sourceBytes.length);

      return sourceBytes.length;
   }

   /**
    * Copy a byte array into another byte array and fill the source byte array with 0s
    *
    * @param sourceBytes      Source byte array
    * @param destinationBytes Destination byte array
    * @param startToIndex     Start index in the destination byte array
    * @return Length of the source bytes
    */
   private static int copyByteArrayAndZapSource(final byte[] sourceBytes, final byte[] destinationBytes, final int startToIndex) {
      final int result = copyByteArray(sourceBytes, destinationBytes, startToIndex);

      Arrays.fill(sourceBytes, (byte) 0);

      return result;
   }

   /**
    * Create a blinding array
    *
    * @return New blinding array
    */
   private static byte[] createBlinding(final int blindingLength) {
      final byte[] result = new byte[blindingLength];

      SECURE_PRNG.nextBytes(result);

      return result;
   }
}
