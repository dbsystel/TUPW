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
 */
package TUPW;

import dbscryptolib.FileAndKeyEncryption;
import org.junit.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.*;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.7.0
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
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryption() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         String decryptedText = myEncryptor.decryptData(encryptedText);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted with a subject present.
    */
   @Test
   public void TestEncryptionDecryptionWithSubject() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5, SUBJECT);

         String decryptedText = myEncryptor.decryptData(encryptedText, SUBJECT);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a file that does not exist is correctly handled.
    */
   @Test
   public void TestFileDoesNotExist() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, "/does/not/exist.txt");

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         fail("Expected exception not thrown");
      } catch (IllegalArgumentException e) {
         String exceptionMessage = e.getMessage();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("does not exist"));
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if invalid file name throws an exception.
    */
   @Test
   public void TestFileNameWithInvalidCharacters() {
      try {
         String anInvalidFileName = "|<>&";

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, anInvalidFileName);

         String decryptedText = myEncryptor.decryptData(NOT_RANDOM_FILE_NAME);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("Key file path is invalid: "));
      }
   }

   /**
    * Test if null file name throws an exception.
    */
   @Test
   public void TestNullFileName() {
      try {
         String aFileName = null;

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, aFileName);

         String decryptedText = myEncryptor.decryptData(NOT_RANDOM_FILE_NAME);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Key file path is null", e.getMessage());
      }
   }

}
