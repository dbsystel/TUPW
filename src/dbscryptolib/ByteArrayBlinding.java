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
package dbscryptolib;

import dbsnumberlib.PackedUnsignedInteger;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implements blinding for byte arrays
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class ByteArrayBlinding {

   /**
    * Class level secure pseudo random number generator
    */
   private final static SecureRandom SECURE_PRNG = new SecureRandom();

   private final static String ERROR_MESSAGE_INVALID_ARRAY = "Invalid blinded byte array";
   private final static String ERROR_MESSAGE_INVALID_MIN_LENGTH = "Invalid minimum length";

   private final static int INDEX_PREFIX = 0;
   private final static int INDEX_POSTFIX = 1;
   private final static int INDEX_SOURCE_LENGTH = 2;
   
   private final static int MAX_MINIMUM_LENGTH = 256;

   /**
    * Check the validity of the requsted minimum length
    * 
    * @param minimumLength Requested minimum length
    * @throws IllegalArgumentException 
    */
   private static void checkMinimumLength(final int minimumLength) throws IllegalArgumentException {
      if (minimumLength < 0)
         throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_MIN_LENGTH);
      else
         if (minimumLength > MAX_MINIMUM_LENGTH)
            throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_MIN_LENGTH);
   }

   /**
    * Adapt blinding lengths so that the result will have at least minimum length
    * 
    * <p>The result will be returned in the array of blinding lengths</p>
    * 
    * @param blindingLength Array of the two blinding lengths
    * @param sourceLengthLength Length of the source length
    * @param sourceLength Length of source
    * @param minimumLength Required minimum length
    */
   private static void adaptBlindLengthsToMinimumLength (int [] blindingLength, final int sourceLengthLength, final int sourceLength, final int minimumLength) {
      final int combinedLength = 2 + sourceLengthLength + blindingLength[INDEX_PREFIX] + sourceLength +  blindingLength[INDEX_POSTFIX];

      if (combinedLength < minimumLength) {
         final int diff = minimumLength - combinedLength;
         final int halfDiff = diff >>> 1;

         blindingLength[INDEX_PREFIX] += halfDiff;
         blindingLength[INDEX_POSTFIX] += halfDiff;

         // Adjust for odd difference
         if ((diff & 1) != 0)
            if ((diff & 2) != 0)
               blindingLength[INDEX_PREFIX]++;
            else
               blindingLength[INDEX_POSTFIX]++;
      }
   }
   
   /**
    * Add blinders to a byte array
    *
    * <p>Note: There may be no blinding, at all! I.e. the "blinded" array is the same, as the source array
    * This behaviour is intentional. So an attacker will not known, whether there was blinding, or not.</p>
    * 
    * @param sourceBytes Source bytes to blinding
    * @param minimumLength Minimum length of blinded array
    * @return Blinded byte array
    * @throws IllegalArgumentException
    * @throws IOException
    */
   public static byte[] buildBlindedByteArray(final byte[] sourceBytes, final int minimumLength) throws IllegalArgumentException, IOException {
      checkMinimumLength(minimumLength);
      
      final int [] blindingLength = new int[2];
      
      // Max. length of blindings is 15 bytes, each.
      blindingLength[INDEX_PREFIX] = SECURE_PRNG.nextInt() & 0x0f;
      blindingLength[INDEX_POSTFIX] = SECURE_PRNG.nextInt() & 0x0f;

      final byte [] packedSourceLength = PackedUnsignedInteger.fromInteger(sourceBytes.length);
      
      // Adapt blinding lengths to be at least minimum length
      if (minimumLength > 0)
         adaptBlindLengthsToMinimumLength (blindingLength, packedSourceLength.length, sourceBytes.length, minimumLength);
      
      final byte[] prefixBlinding = new byte[blindingLength[INDEX_PREFIX]];
      final byte[] postfixBlinding = new byte[blindingLength[INDEX_POSTFIX]];

      SECURE_PRNG.nextBytes(prefixBlinding);
      SECURE_PRNG.nextBytes(postfixBlinding);

      final int resultLength = 2 + packedSourceLength.length + prefixBlinding.length + sourceBytes.length + postfixBlinding.length;

      ByteArrayOutputStream resultStream = new ByteArrayOutputStream(resultLength);

      resultStream.write(blindingLength[INDEX_PREFIX]);
      resultStream.write(blindingLength[INDEX_POSTFIX]);
      resultStream.write(packedSourceLength);
      resultStream.write(prefixBlinding);
      resultStream.write(sourceBytes);
      resultStream.write(postfixBlinding);

      Arrays.fill(prefixBlinding, (byte) 0);
      Arrays.fill(postfixBlinding, (byte) 0);

      final byte[] result = resultStream.toByteArray();

      /*
       Now clear the byte stream
       */
      resultStream.reset();

      resultStream.write(0);
      resultStream.write(0);

      Arrays.fill(packedSourceLength, (byte) 0);
      resultStream.write(packedSourceLength);

      resultStream.write(prefixBlinding);

      byte[] filler = new byte[sourceBytes.length];
      resultStream.write(filler);

      resultStream.write(postfixBlinding);

      return result;
   }

   /**
    * Remove blinders from a byte array
    *
    * @param sourceBytes Blinded byte array
    * @return Byte array without blinders
    * @throws IllegalArgumentException
    * @throws IOException
    */
   public static byte[] unBlindByteArray(final byte[] sourceBytes) throws IllegalArgumentException, IOException {
      if (sourceBytes.length > INDEX_SOURCE_LENGTH) {
         final int packedNumberLength = PackedUnsignedInteger.getExpectedLength(sourceBytes[INDEX_SOURCE_LENGTH]);

         final int prefixBlindingLength = sourceBytes[0] + 2 + packedNumberLength;
         final int postfixBlindingLength = sourceBytes[1];
         
         final int totalBlindingsLength = prefixBlindingLength + postfixBlindingLength;
         final int dataLength = PackedUnsignedInteger.toIntegerFromArray(sourceBytes, INDEX_SOURCE_LENGTH);

         // The largest number in the following addition can only be just over 1073741823
         // This can never overflow into negative values
         if ((totalBlindingsLength + dataLength) <= sourceBytes.length)
            return Arrays.copyOfRange(sourceBytes, prefixBlindingLength, dataLength + prefixBlindingLength);
      }
      
      throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_ARRAY);
   }

}
