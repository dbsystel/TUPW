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
 *     2015-12-20: V1.0.0: Created. fhs
 *     2015-12-21: V1.1.0: Change to correct padding format. fhs
 *     2018-08-21: V1.2.0: Test format 3 and use predictable file. fhs
 *     2020-02-12: V1.3.0: More tests with subject and different versions. fhs
 *     2020-02-27: V1.4.0: Added tests with invalid parameters. fhs
 *     2020-02-28: V1.5.0: Added test with not enough information in source bytes. fhs
 *     2020-03-04: V1.6.0: Split test cases for "FileAndKeyEncryption" and "SplitKeyEncryption". fhs
 *     2020-03-20: V1.7.0: Test new interfaces for byte and character arrays. fhs
 *     2020-05-14: V1.8.0: Correct usage of close interface. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.*;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.8.0
 */
public class TestFileAndKeyEncryption {

   /*
    * Private constants
    */
   /**
    * File name for the non-random bytes
    */
   private static final String NOT_RANDOM_FILE_NAME = "_not_random_file_.bin";

   /**
    * HMAC key to be used for encryption
    *
    * This is the static HMAC key which is only known to the program
    * TODO: Do not use this constant byte array. Roll your own!!!!
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
   private static final String CLEAR_TEXT_V5 = "This#”s?a§StR4nGé€PàS!Wörd9";

   /**
    * Known encrypted text to decrypt
    */
   private static final String SUBJECT = "strangeness+charm";


   /*
    * Public methods
    */
   public TestFileAndKeyEncryption() {
   }

   /**
    * Create nonrandom key file before the test
    */
   @BeforeClass
   public static void setUpClass() {
      //
      // Generate a nonrandom key file with a predictable content, so the tests are reproducible.
      //
      byte[] notRandomBytes = new byte[100000];

      for(int i=0; i < notRandomBytes.length; i++)
         notRandomBytes[i] = (byte) (0xff - (i & 0xff));

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
   @AfterClass
   public static void tearDownClass() {
      Path path = Paths.get(NOT_RANDOM_FILE_NAME);

      try {
         Files.deleteIfExists(path);
      } catch (Exception e) {
         System.err.print("Could not delete file '" + NOT_RANDOM_FILE_NAME + ": " + e.toString());
      }
   }

   @Before
   public void setUp() {
   }

   @After
   public void tearDown() {
   }

   /**
    * Test if the encryption of a given byte array is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryptionForByteArray() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         final byte[] testByteArray = new byte[256];

         for (int i = 0; i < testByteArray.length; i++)
            testByteArray[i] = (byte) (0xff - i);

         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(testByteArray);

         byte[] decryptedByteArray = myEncryptor.decryptDataAsByteArray(encryptedText);

         myEncryptor.close();

         assertArrayEquals("Decrypted byte array is not the same as original byte array", testByteArray, decryptedByteArray);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given character array is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryptionForCharacterArray() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};

         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(testCharArray);

         char[] decryptedCharArray = myEncryptor.decryptDataAsCharacterArray(encryptedText);

         myEncryptor.close();

         assertArrayEquals("Decrypted character array is not the same as original character array", testCharArray, decryptedCharArray);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryption() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText);

         myEncryptor.close();

         assertEquals("Decrypted text is not the same as original text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted with a subject present.
    */
   @Test
   public void TestEncryptionDecryptionWithSubject() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5, SUBJECT);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText, SUBJECT);

         myEncryptor.close();

         assertEquals("Decrypted text is not the same as original text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }
   /**
    * Test if the decryption of a byte array throws an exception if decrypted as a character array.
    */
   @Test
   public void TestDecryptionToCharArrayWithInvalidByteArray() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         final byte[] testByteArray = new byte[256];

         for (int i = 0; i < testByteArray.length; i++)
            testByteArray[i] = (byte) (0xff - i);

         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsCharacterArray(encryptedText);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         String message = e.toString();
         assertTrue("Unexpected exception: " + message, message.contains("MalformedInputException"));
      }
   }

   /**
    * Test if the decryption of a byte array throws an exception if decrypted as a string.
    */
   @Test
   public void TestDecryptionToStringWithInvalidByteArray() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         final byte[] testByteArray = new byte[256];

         for (int i = 0; i < testByteArray.length; i++)
            testByteArray[i] = (byte) (0xff - i);

         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsString(encryptedText);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         String message = e.toString();
         assertTrue("Unexpected exception: " + message, message.contains("MalformedInputException"));
      }
   }

   /**
    * Test if a file that does not exist is correctly handled.
    */
   @Test
   public void TestFileDoesNotExist() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, "/does/not/exist.txt");

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (IllegalArgumentException e) {
         if (myEncryptor != null)
            myEncryptor.close();

         String exceptionMessage = e.getMessage();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("does not exist"));
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if invalid file name throws an exception.
    */
   @Test
   public void TestFileNameWithInvalidCharacters() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         String anInvalidFileName = "|<>&";

         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, anInvalidFileName);

         String decryptedText = myEncryptor.decryptDataAsString(NOT_RANDOM_FILE_NAME);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("Key file path is invalid: "));
      }
   }

   /**
    * Test if null file name throws an exception.
    */
   @Test
   public void TestNullFileName() {
      FileAndKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new FileAndKeyEncryption(HMAC_KEY, null);

         String decryptedText = myEncryptor.decryptDataAsString(NOT_RANDOM_FILE_NAME);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "Key file path is null", e.getMessage());
      }
   }

}
