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
 * @version 1.5.0
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
   private static final String CLEAR_TEXT_V3 = "This is a clear Text";
   private static final String CLEAR_TEXT_V5 = "This#”s?a§StR4nGé€PàS!Wörd9";

   /**
    * Known encrypted text to decrypt
    */
   private static final String ENCRYPTED_TEXT_V3 = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";
   private static final String SUBJECT = "maven_repo_pass";
   private static final String WRONG_SUBJECT = "maven_repo_paxx";
   private static final String ENCRYPTED_TEXT_V5 = "5$Qs6C7prscyK5/OiJRsjWtw$bobPzPN6BJI0Od9pMSUWrSXp5hm/U+0ihzrWH30wMhrZGFPGsnNl/Mv3xJLdHdE03PpD1CW99AK2IZKk006hVA$nP3mG9F4eKvYJoFEiOhMguzMbgpo7XR+JkNJnA6qdhQ";

   /**
    * Known encrypted text to decrypt with invalid HMAC
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_HMAC = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXQ=";

   /**
    * Known encrypted text to decrypt with invalid encryption
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1Q$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with invalid IV
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_IV = "3$J/LJT9XGjwfmsKsvHzFefz==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with unknown format id
    */
   private static final String ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID = "99$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with invalid format id
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID = "Q$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with missing format id
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID = "J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with empty IV
    */
   private static final String ENCRYPTED_TEXT_WITH_EMPTY_IV = "3$$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with missing IV
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_IV = "3$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Checksum error message
    */
   private static final String CHECKSUM_ERROR_MESSAGE = "Checksum does not match data";

   /**
    * Invalid format id error message
    */
   private static final String INVALID_FORMAT_ID_ERROR_MESSAGE = "Invalid format id";


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
      // Generate a file with a predictable content, so the tests are reproducible.
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

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         String decryptedText = myEncryptor.decryptData(encryptedText);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
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
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEmptyEncryptionDecryption() {
      try {
         final String emptyString = "";

         final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         final String encryptedText = myEncryptor.encryptData(emptyString);

         final String decryptedText = myEncryptor.decryptData(encryptedText);

         assertEquals("Decrypted text is not the same as encrypted text", emptyString, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEmptyEncryptionDecryptionWithSubject() {
      try {
         final String emptyString = "";

         final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         final String encryptedText = myEncryptor.encryptData(emptyString, SUBJECT);

         final String decryptedText = myEncryptor.decryptData(encryptedText, SUBJECT);

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

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_V3);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT_V3, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text is correctly decrypted.
    */
   @Test
   public void TestKnownDecryptionWithSubject() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_V5, SUBJECT);

         assertEquals("Decrypted text is not the same as encrypted text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text with an invalid HMAC throws an exception.
    */
   @Test
   public void TestDecryptionWithWrongSubject() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_V5, WRONG_SUBJECT);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
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
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
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
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
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
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
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
         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
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
         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an empty format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithEmptyIV() {
      try {
         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_EMPTY_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
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
         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too short HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithShortHMAC() {
      try {
         byte[] shortHMAC = new byte[10];

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(shortHMAC, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too large HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithTooLargeHMAC() {
      try {
         byte[] largeHMAC = new byte[70];

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(largeHMAC, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key length is larger than 32", e.getMessage());
      }
   }

   /**
    * Test if null HMAC key throws an exception.
    */
   @Test
   public void TestNullHMACKey() {
      try {
         byte[] aHMACKey = null;

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(aHMACKey, NOT_RANDOM_FILE_NAME);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key is null", e.getMessage());
      }
   }

   /**
    * Test if invalid file name throws an exception.
    */
   @Test
   public void TestInvalidFileName() {
      try {
         String anInvalidFileName = "|<>&";

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, anInvalidFileName);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

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

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Key file path is null", e.getMessage());
      }
   }

   /**
    * Test if one null source byte array throws an exception.
    */
   @Test
   public void TestOneNullByteArray() {
      try {
         byte[] aSourceByteArray = null;

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "1. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception.
    */
   @Test
   public void TestAnotherNullByteArray() {
      try {
         byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
         byte[] anotherSourceByteArray = null;

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, aSourceByteArray, anotherSourceByteArray);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "2. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception.
    */
   @Test
   public void TestShortSourceBytes() {
      try {
         byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};

         FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptData(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("not enough information provided"));
      }
   }

}
