/*
 * Copyright (c) 2018, DB Systel GmbH
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
 */
package dbsnumberlib;

import java.util.Arrays;

/**
 * Converts integers from and to an unsigned packed byte array
 * 
 * @author FrankSchwab
 * @version 1.0.0
 */
public class PackedUnsignedInteger {

   /**
    * Convert an integer into a packed decimal byte array
    * 
    * Valid integers range from 0 to 1073741823.
    * All other numbers throw an IllegalArgumentException
    * 
    * @param aNumber Integer to convert
    * @return Packed decimal byte array with integer as value 
    * @throws IllegalArgumentException
    */
   public static byte[] fromInteger(final int aNumber) throws IllegalArgumentException {
      byte[] result;

      if (aNumber >= 0)
         if (aNumber <= 0x3f) {
            result = new byte[1];
            result[0] = (byte) (aNumber & 0x3f);
         } else if (aNumber <= 0x3fff) {
            result = new byte[2];
            result[1] = (byte) (aNumber & 0xff);
            result[0] = (byte) (0x40 | (aNumber >>> 8));
         } else if (aNumber <= 0x3fffff) {
            result = new byte[3];
            result[2] = (byte) (aNumber & 0xff);
            result[1] = (byte) ((aNumber >>> 8) & 0xff);
            result[0] = (byte) (0x80 | (aNumber >>> 16));
         } else if (aNumber <= 0x3fffffff) {
            result = new byte[4];
            result[3] = (byte) (aNumber & 0xff);
            result[2] = (byte) ((aNumber >>> 8) & 0xff);
            result[1] = (byte) ((aNumber >>> 16) & 0xff);
            result[0] = (byte) (0xc0 | (aNumber >>> 24));
         } else
            throw new IllegalArgumentException();
      else
         throw new IllegalArgumentException();

      return result;
   }

   /**
    * Get expected length of packed decimal byte array from first byte
    * 
    * @param firstByteOfPackedNumber First byte of packed decimal integer
    * @return Expected length (1 to 4)
    */
   public static int getExpectedLength(final byte firstByteOfPackedNumber) {
      return ((firstByteOfPackedNumber >>> 6) & 0x03) + 1;
   }

   /**
    * Convert a packed decimal byte array itno an integer
    * 
    * @param packedNumber Packed decimal byte array
    * @return Converted integer
    * @throws IllegalArgumentException
    */
   public static int toInteger(final byte[] packedNumber) throws IllegalArgumentException {
      int result = 0;

      final int expectedLength = getExpectedLength(packedNumber[0]);

      if (expectedLength == packedNumber.length)
         switch (expectedLength) {
            case 1:
               result = (int) (packedNumber[0] & 0x3f);
               break;

            case 2:
               result = (int) (((packedNumber[0] & 0x3f) << 8) | (packedNumber[1] & 0xff));
               break;

            case 3:
               result = (int) (((packedNumber[0] & 0x3f) << 16) | ((packedNumber[1] & 0xff) << 8) | (packedNumber[2] & 0xff));
               break;

            case 4:
               result = (int) (((packedNumber[0] & 0x3f) << 24) | ((packedNumber[1] & 0xff) << 16) | ((packedNumber[2] & 0xff) << 8) | (packedNumber[3] & 0xff));
               break;

            default:
               throw new IllegalArgumentException();
         }
      else
         throw new IllegalArgumentException();

      return result;
   }

   /**
    * Convert a packed decimal byte array in a larger array to an integer
    * 
    * @param arrayWithPackedNumber Array where the packed decimal byte array resides
    * @param startIndex Start index of decimal byte array
    * @return Converted integer
    * @throws IllegalArgumentException 
    */
   public static int toIntegerFromArray(final byte[] arrayWithPackedNumber, final int startIndex) throws IllegalArgumentException {
      final int expectedLength = getExpectedLength(arrayWithPackedNumber[startIndex]);

      if ((startIndex + expectedLength) <= arrayWithPackedNumber.length)
         return toInteger(Arrays.copyOfRange(arrayWithPackedNumber, startIndex, startIndex + expectedLength));
      else
         throw new IllegalArgumentException();
   }

}
