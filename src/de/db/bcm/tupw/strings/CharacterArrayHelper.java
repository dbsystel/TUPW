/*
 * Copyright (c) 2020, DB Systel GmbH
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2020-03-25: V1.0.0: Created. fhs
 */
package de.db.bcm.tupw.strings;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.Arrays;

/**
 * Class to convert between character and byte arrays
 *
 * <p>This is a class that should not exist, but in Java there is absolutely no easy way to convert between character
 * and byte arrays. One has to use this complicated, unintuitive and strange buffer conversion stuff implemented here.</p>
 */
public class CharacterArrayHelper {
   //******************************************************************
   // Constants
   //******************************************************************
   final private static char FILL_CHAR = '\0';
   final private static byte FILL_BYTE = (byte) 0;


   //******************************************************************
   // Class variables
   //******************************************************************
   final private static CharsetDecoder UTF8_DECODER = StandardCharsets.UTF_8.newDecoder();
   final private static CharsetEncoder UTF8_ENCODER = StandardCharsets.UTF_8.newEncoder();


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Convert a character array into an UTF-8 encoded byte array
    *
    * @param sourceCharacterArray character array to encode
    * @return UTF-8 encoded byte array of the characters in {@code sourceCharacterArray}
    */
   public static byte[] convertCharacterArrayToUTF8ByteArray(final char[] sourceCharacterArray)  {
      byte[] result = null;

      if (sourceCharacterArray != null) {
         final CharBuffer tempCharBuffer = CharBuffer.wrap(sourceCharacterArray);

         ByteBuffer tempByteBuffer = null;
         try {
            tempByteBuffer = UTF8_ENCODER.encode(tempCharBuffer);
         } catch (Exception e) {
            // As UTF-8 can always encode *every* Unicode character an CharacterCodingException exception can never happen.
            // With this try-statement the unnecessary declaration of "throws CharacterCodingException"
            // in the method signature is suppressed.
         }

         result = Arrays.copyOf(tempByteBuffer.array(), tempByteBuffer.limit());
         Arrays.fill(tempByteBuffer.array(), FILL_BYTE);
      }

      return result;
   }

   /**
    * Convert an UTF-8 encoded byte array into a character array
    *
    * @param sourceByteArray (Hopefully) UTF-8 encoded byte array
    * @return Character array from the UTF-8 encoded {@code sourceByteArray}
    * @throws CharacterCodingException if a byte sequence is malformed
    */
   public static char[] convertUTF8ByteArrayToCharacterArray(final byte[] sourceByteArray) throws CharacterCodingException {
      char[] result = null;

      if (sourceByteArray != null) {
         final ByteBuffer tempByteBuffer = ByteBuffer.wrap(sourceByteArray);
         final CharBuffer tempCharBuffer = UTF8_DECODER.decode(tempByteBuffer);

         result = Arrays.copyOf(tempCharBuffer.array(), tempCharBuffer.limit());
         Arrays.fill(tempCharBuffer.array(), FILL_CHAR);
      }

      return result;
   }
}
