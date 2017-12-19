/*
 * Copyright (c) 2017, DB Systel GmbH
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes: 
 *     2017-12-19: V1.0.0: Created. fhs
 */
package dbscryptolib;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implements arbitrary tail padding for block ciphers
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class ArbitraryTailPadding {

   /*
    * Private constants
    */
   /**
    * Instance of secure random number generator
    *
    * This is placed here so the expensive instantiation of the SecureRandom
    * class is done only once.
    */
   private static final SecureRandom SECURE_PRNG = new SecureRandom();

   private static final int MAX_MAX_PADDING_LENGTH = 10000;

   /*
    * Private methods
    */
   
   /**
    * Check padding limits
    * 
    * @param minPaddingLength Minimum padding length
    * @param maxPaddingLength Maximum padding length
    * @throws java.lang.IllegalArgumentException 
    */
   private static void checkPaddingLengthLimits(final int minPaddingLength, final int maxPaddingLength) throws IllegalArgumentException {
      if (minPaddingLength < 0) {
         throw new IllegalArgumentException("Minimum padding length must not be less than 0");
      }

      if (maxPaddingLength < minPaddingLength) {
         throw new IllegalArgumentException("Maximum padding length must not be less than minimum padding length");
      }

      if (maxPaddingLength > MAX_MAX_PADDING_LENGTH) {
         throw new IllegalArgumentException("Maximum padding length must not be greater than " + Integer.toString(MAX_MAX_PADDING_LENGTH));
      }
   }

   /**
    * Get a random value as the padding byte
    * 
    * The padding byte must not have the same value as the last data byte
    * 
    * @param lastByte Last data byte
    * @return Random byte to be used as the padding byte
    */
   private static byte getPaddingByteValue(final byte lastByte) {
      byte[] padByte = new byte[1];

      do {
         SECURE_PRNG.nextBytes(padByte);
      } while (padByte[0] == lastByte);

      return padByte[0];
   }

   /**
    * Calculate the padding length
    * 
    * @param minPaddingLength Minimum padding length
    * @param maxPaddingLength Maximum padding length
    * @return 
    */
   private static int getPaddingLength(final int minPaddingLength, final int maxPaddingLength) {
      return SECURE_PRNG.nextInt(maxPaddingLength - minPaddingLength + 1) + minPaddingLength;
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
    * @param minPaddingLength Maximum padding length
    * @param maxPaddingLength Maximum padding length
    * @return Data with padding bytes added
    * @throws java.lang.IllegalArgumentException
    */
   public static byte[] addPadding(final byte[] unpaddedSourceData, final int minPaddingLength, final int maxPaddingLength) throws IllegalArgumentException {
      // Check parameter validity
      checkPaddingLengthLimits(minPaddingLength, maxPaddingLength);

      // Get pad byte value
      final byte padByte = getPaddingByteValue(unpaddedSourceData[unpaddedSourceData.length - 1]);

      // Get padding size
      final int paddingLength = getPaddingLength(minPaddingLength, maxPaddingLength);

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
    */
   public static byte[] removePadding(byte[] paddedSourceData) {
      // Return unpadded data
      return Arrays.copyOf(paddedSourceData, getUnpaddedDataLength(paddedSourceData));
   }
}
