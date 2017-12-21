/*
 * Copyright (c) 2017, DB Systel GmbH
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
 *     2015-12-20: V1.0.0: Created
 */
package TUPW;

import dbscryptolib.FileAndKeyEncryption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestFileAndKeyEncryption {

   /*
    * Private constants
    */
   /**
    * File name for the nonradom bytes
    */
   private static final String NOT_RANDOM_FILE_NAME = "_not_random_file_.bin";

   /**
    * HMAC key to be used for encryption
    *
    * This is the static HMAC key which is only known to the program TODO: Do
    * not use this constant byte array. Roll your own!!!!
    */
   private static final byte[] HMAC_KEY = {(byte) 0xC1, (byte) 0xC2, (byte) 0xC8, (byte) 0x0F,
      (byte) 0xDE, (byte) 0x75, (byte) 0xD7, (byte) 0xA9,
      (byte) 0xFC, (byte) 0x92, (byte) 0x56, (byte) 0xEA,
      (byte) 0x3C, (byte) 0x0C, (byte) 0x7A, (byte) 0x08,
      (byte) 0x8A, (byte) 0x6E, (byte) 0xB5, (byte) 0x78,
      (byte) 0x15, (byte) 0x79, (byte) 0xCF, (byte) 0xB4,
      (byte) 0x02, (byte) 0x0F, (byte) 0x38, (byte) 0x3C,
      (byte) 0x61, (byte) 0x4F, (byte) 0x9D, (byte) 0xDB};

   /**
    * Known clear text to encrypt
    */
   private static final String CLEAR_TEXT = "This is a clear Text";

   /**
    * Known encrypted text to decrypt
    */
   private static final String ENCRYPTED_TEXT = "1$JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with invalid HMAC
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_HMAC = "1$JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26i3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with invalid encryption
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION = "1$JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDhP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with invalid IV
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_IV = "1$JuqVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with unknown format id
    */
   private static final String ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID = "99$JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with invalid format id
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID = "q$JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with missing format id
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID = "JumVT3xH5OQofQ/Ne6eV3w==$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /**
    * Known encrypted text to decrypt with missing IV
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_IV = "1$iXucAXVZpyDgP/MuNUoBy0B54jVnzOBrNqE/maFfz3rzQ2JVlLUjflxV3vqjJlJPaw==$ER6iskk97jIPcOmcT0m0TVicCcgW26m3Q2xcdfDm7Y4=";

   /*
    * Public methods
    */
   public TestFileAndKeyEncryption() {
   }

   @BeforeClass
   public static void setUpClass() {
   }

   @AfterClass
   public static void tearDownClass() {
   }

   /**
    * Create nonrandom key file before the test
    */
   @Before
   public void setUp() {
      //
      // This is *not* a secure random generator.
      // In fact it is used here so that the random data
      // are reproducible and predictable.
      // Do *not* use Random as the source of your random file!
      //
      Random rnd = new Random(0);

      byte[] notRandomBytes = new byte[100000];

      rnd.nextBytes(notRandomBytes);

      Path path = Paths.get(NOT_RANDOM_FILE_NAME);

      try {
         Files.write(path, notRandomBytes);
      } catch (Exception e) {
         System.err.print("Could not write to file '" + NOT_RANDOM_FILE_NAME + ": " + e.toString());
      }
   }

   /**
    * Delete nonrandom key file after the test
    */
   @After
   public void tearDown() {
      Path path = Paths.get(NOT_RANDOM_FILE_NAME);

      try {
         Files.deleteIfExists(path);
      } catch (Exception e) {
         System.err.print("Could not delete file '" + NOT_RANDOM_FILE_NAME + ": " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryption() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT);

         String decryptedText = myEncryptor.decryptData(encryptedText);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEmptyEncryptionDecryption() {
      try {
         final String emptyString = "";

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(emptyString);

         String decryptedText = myEncryptor.decryptData(encryptedText);

         assertEquals("Decrypted text is not the same as encrypted text", emptyString, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text is correctly decrypted.
    */
   @Test
   public void TestKnownDecryption() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text with an invalid HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidHMAC() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_HMAC);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Checksums do not match", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid encryption throws an
    * exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidEncryption() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Checksums do not match", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid IV throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidIV() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Checksums do not match", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an unknown format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithUnknownFormatId() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Unknown format id", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidFormatId() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Invalid format id", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with a missing format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithMissingFormatId() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Invalid format id", e.getMessage());
      }
   }
   /**
    * Test if a given encrypted text with a missing format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithMissingIV() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_MISSING_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
      }
   }

   /**
    * Test if an empty HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithEmptyHMAC() {
      try {
         byte[] emptyHMAC = new byte[0];

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(emptyHMAC, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "The HMAC key does not have a length of 32 bytes", e.getMessage());
      }
   }

}
