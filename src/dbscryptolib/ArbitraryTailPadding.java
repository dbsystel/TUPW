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
 *     2017-12-19: V1.0.0: Created. fhs
 *     2017-12-21: V2.0.0: Pad to block size. fhs
 *     2018-06-11: V2.0.1: Block size must be greater than zero. fhs
 *     2018-08-15: V2.0.2: Added some "finals". fhs
 *     2019-05-17: V2.0.3: Added a missing "final". fhs
 *     2019-08-06: V2.0.4: Use SecureRandomFactory. fhs
 *     2019-08-23: V2.0.5: Use SecureRandom singleton. fhs
 *     2020-03-13: V2.1.0: Added checks for null. fhs
 */
package dbscryptolib;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements arbitrary tail padding for block ciphers
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 2.1.0
 */
public class ArbitraryTailPadding {

   /*
    * Private constants
    */

   /**
    * Maximum block size (64 KiB)
    */
   private static final int MAX_BLOCK_SIZE = 64 * 1024;

   /*
    * Private variables
    */

   /**
    * Instance of secure random number generator
    * <p>
    * This is placed here so the expensive instantiation of the SecureRandom
    * class is done only once.
    */
   private static final SecureRandom SECURE_PRNG = SecureRandomFactory.getSensibleSingleton();

   /*
    * Private methods
    */

   /**
    * Check block size
    *
    * @param blockSize Block size
    * @throws java.lang.IllegalArgumentException if block size is too small or too large
    */
   private static void checkBlockSize(final int blockSize) throws IllegalArgumentException {
      if (blockSize <= 0)
         throw new IllegalArgumentException("Block size must be greater than 0");

      if (blockSize > MAX_BLOCK_SIZE)
         throw new IllegalArgumentException("Block size must not be greater than " + MAX_BLOCK_SIZE);
   }

   /**
    * Get a random value as the padding byte
    * <p>
    * The padding byte must not have the same value as the last data byte
    *
    * @param unpaddedSourceData Unpadded source data (may be empty)
    * @return Random byte to be used as the padding byte
    */
   private static byte getPaddingByteValue(final byte[] unpaddedSourceData) {
      final byte[] padByte = new byte[1];

      if (unpaddedSourceData.length > 0) {
         final byte lastByte = unpaddedSourceData[unpaddedSourceData.length - 1];

         do
            SECURE_PRNG.nextBytes(padByte);
         while (padByte[0] == lastByte);
      } else
         SECURE_PRNG.nextBytes(padByte);

      return padByte[0];
   }

   /**
    * Calculate the padding length
    * <p>
    * If the unpadded data already have a length that is a multiple of blockSize
    * an additional block with only padding bytes is added.
    *
    * @param unpaddedLength Length of the unpadded data
    * @param blockSize      Block size of which the padding size has to be a multiple
    * @return Padding length that brings the total length to a multiple of {@code blockSize}
    */
   private static int getPaddingLength(final int unpaddedLength, final int blockSize) {
      return (blockSize - (unpaddedLength % blockSize));
   }

   /**
    * Get length of unpadded data
    *
    * @param paddedSourceData Padded source data
    * @return Length of unpadded data
    */
   private static int getUnpaddedDataLength(final byte[] paddedSourceData) {
      int result = paddedSourceData.length;

      if (result > 0) {
         result--;

         final byte padByte = paddedSourceData[result];

         while (result > 0) {
            result--;

            if (paddedSourceData[result] != padByte) {
               result++;
               break;
            }
         }
      }

      return result;
   }

   /*
    * Public methods
    */

   /**
    * Add padding bytes to source data
    *
    * @param unpaddedSourceData Data to be padded
    * @param blockSize          Block size in bytes
    * @return Data with padding bytes added
    * @throws IllegalArgumentException if block size is too small or too large
    * @throws NullPointerException     if {@code unpaddedSourceData} is {@code null}
    */
   public static byte[] addPadding(final byte[] unpaddedSourceData, final int blockSize) throws IllegalArgumentException, NullPointerException {
      Objects.requireNonNull(unpaddedSourceData, "Unpadded source data is null");

      // Check parameter validity
      checkBlockSize(blockSize);

      // Get pad byte value
      final byte padByte = getPaddingByteValue(unpaddedSourceData);

      // Get padding size
      final int paddingLength = getPaddingLength(unpaddedSourceData.length, blockSize);

      // Create padded byte array
      final byte[] result = Arrays.copyOf(unpaddedSourceData, unpaddedSourceData.length + paddingLength);

      // Add padding bytes
      Arrays.fill(result, unpaddedSourceData.length, result.length, padByte);

      return result;
   }

   /**
    * Remove padding bytes from source data
    *
    * @param paddedSourceData Data with padding bytes
    * @return Data without padding bytes
    * @throws NullPointerException if {@code paddedSourceData} is {@code null}
    */
   public static byte[] removePadding(final byte[] paddedSourceData) throws NullPointerException {
      Objects.requireNonNull(paddedSourceData, "Padded source data is null");

      // Return unpadded data
      return Arrays.copyOf(paddedSourceData, getUnpaddedDataLength(paddedSourceData));
   }
}
