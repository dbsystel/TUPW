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
 *     2017-03-30: V1.0.0: Created. fhs
 *     2017-04-12: V1.0.1: Moved secure random number generator to class constant. fhs
 *     2017-05-23: V1.0.2: Corrected spelling of "aesCipher". fhs
 *     2017-06-01: V1.0.3: Modified StringSplitter. fhs
 *     2017-11-09: V1.0.4: Use CFB modus to thwart padding oracle attacks. fhs
 *     2017-12-19: V2.0.0: Use CFB8 modus and arbitrary tail padding to thwart padding oracle attacks,
 *                         Refactored interface to encryption and decryption. fhs
 *     2017-12-20: V2.1.0: Encrypt/decrypt only one item. fhs
 *     2018-01-30: V3.0.0: Only plain output, input also from stdin to make the program usable in a pipe. fhs
 *     2018-02-01: V3.0.1: Input from stdin must not exceed 50 MB. fhs
 *     2018-05-17: V3.1.0: Use CTR mode to squash ciphertext manipulation attacks. fhs
 *     2018-06-13: V3.2.0: Use constant time HMAC compare to squash timing attacks. fhs
 *     2018-08-07: V3.2.1: Some small improvements. fhs
 *     2018-08-16: V3.2.2: Added some "finals". fhs
 *     2018-08-17: V3.3.0: Use blinding and random padding. fhs
 *     2019-03-06: V3.3.1: Minor changes in SecureSecretKeySpec. fhs
 *     2019-03-07: V4.0.0: Add a "subject" to the command line that will change the encryption key. fhs
 *     2019-03-07: V4.0.1: Strengthen test for invalid blinding data. fhs
 *     2019-03-07: V4.1.0: Correct handling of keys with subject parameter. fhs
 */
package TUPW;

import dbscryptolib.FileAndKeyEncryption;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Example program to calculate the encryption of user and password for
 * technical users. To be called from the command line.
 *
 * Returns with the following exit codes:
 *    0: Data converted
 *    1: Error during conversion
 *    2: Not enough arguments
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 4.1.0
 */
public class TUPW {
   private static final int MAX_INPUT_BYTES = 50000000;
   private static final int READ_BLOCK_SIZE = 4096;
   
   public static void main(final String[] args) {
      // This is the static HMAC key which is only known to the program
      // TODO: Do not use this constant byte array. Roll your own!!!!
      final byte[] HMAC_KEY = {(byte) 0x53, (byte) 0x67, (byte) 0xC3, (byte) 0x59,
         (byte) 0x4B, (byte) 0x46, (byte) 0x0F, (byte) 0xFA,
         (byte) 0x15, (byte) 0x21, (byte) 0x13, (byte) 0x6C,
         (byte) 0x7F, (byte) 0xDD, (byte) 0x33, (byte) 0x57,
         (byte) 0x26, (byte) 0xF3, (byte) 0x10, (byte) 0xA0,
         (byte) 0xE9, (byte) 0x16, (byte) 0xA4, (byte) 0x2E,
         (byte) 0x9E, (byte) 0x15, (byte) 0x8E, (byte) 0xF4,
         (byte) 0x03, (byte) 0x04, (byte) 0xAA, (byte) 0x2C};

      if (args.length >= 3) {
         try (FileAndKeyEncryption MyEncryptor = new FileAndKeyEncryption(HMAC_KEY, args[1])) {
            String subject = "";
            int itemIndex = 2;

            if (args.length >= 4) {
               subject = args[2];
               itemIndex++;
            }

            if (args[0].substring(0, 1).toLowerCase().equals("e")) {
               System.out.println(MyEncryptor.encryptData(getInputFromWhereEver(args[itemIndex]), subject));
            } else {
               System.out.println(MyEncryptor.decryptData(getInputFromWhereEver(args[itemIndex]), subject));
            }

            System.exit(0);
         } catch (final Exception e) {
            e.printStackTrace();
            System.exit(1);
         }
      } else {
         System.err.println("Not enough arguments.");
         System.err.println();
         System.err.println("Usage:");
         System.err.println("   tupw.jar encrypt {keyfile} [subject] {clearItem}");
         System.err.println("   tupw.jar decrypt {keyfile} [subject] {encryptedItem}");
         System.err.println();
         System.err.println("If {clearItem}, or {encryptedItem} is '-' input is read from stdin.");
         System.err.println("This makes it possible to use the program in a pipe.");
         
         System.exit(2);
      }
   }

   /**
    * Get input either from the command line, or from stdin if third argument
    * is "-"
    *
    * @param anArgument The command line argument that is either the data,
    * or "-"
    * @return Data to process
    * @throws IllegalArgumentException
    * @throws IOException
    */
   static String getInputFromWhereEver(final String anArgument) throws IllegalArgumentException, IOException {
      String result;

      // Get input from System.in, if third argument is "-", or from the 
      // third command line argument, if it is something else
      if (anArgument.equals("-")) {
         result = getInputStreamAsString(System.in);
      } else {
         result = anArgument;
      }

      return result;
   }

   /**
    * Convert an <code>InputStream</code> to a <code>String</code>
    *
    * @param inputStream InputStream to convert
    * @return Content of InputStream as String
    * @throws IllegalArgumentException
    * @throws IOException
    */
   static String getInputStreamAsString(final InputStream inputStream) throws IllegalArgumentException, IOException {
      final ByteArrayOutputStream result = new ByteArrayOutputStream();
      final byte[] buffer = new byte[READ_BLOCK_SIZE];
      int length;

      while ((length = inputStream.read(buffer)) != -1) {
         result.write(buffer, 0, length);

         if (result.size() > MAX_INPUT_BYTES) 
            throw new IllegalArgumentException("Input from input stream is larger than " + String.format("%,d",  MAX_INPUT_BYTES) + " bytes");
      }

      // Convert to String with Java file encoding
      return result.toString(System.getProperty("file.encoding")).trim(); // Need trim here as pipes append an unnecessary newline
   }
}
