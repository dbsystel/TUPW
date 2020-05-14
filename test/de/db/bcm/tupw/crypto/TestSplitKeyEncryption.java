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
 *     2020-03-04: V1.0.0: Created. fhs
 *     2020-03-09: V1.0.1: Test 0 length source byte array. fhs
 *     2020-03-20: V1.1.0: Test new interfaces for byte and character arrays. fhs
 *     2020-05-14: V1.2.0: More tests for basic encryption/decryption and usage of the close interface. fhs
 */
package de.db.bcm.tupw.crypto;

import de.db.bcm.tupw.numbers.Xoroshiro128plusplus;
import org.junit.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.2.0
 */
public class TestSplitKeyEncryption {

   /*
    * Private constants
    */
   /**
    * HMAC key to be used for encryption
    *
    * This is the static HMAC key which is only known to the program
    * TODO: Do not use this constant byte array. Roll your own!!!!
    */
   private static final byte[] CONSTANT_HMAC_KEY = {
           (byte) 0xC1, (byte) 0xC2, (byte) 0xC8, (byte) 0x0F,
           (byte) 0xDE, (byte) 0x75, (byte) 0xD7, (byte) 0xA9,
           (byte) 0xFC, (byte) 0x92, (byte) 0x56, (byte) 0xEA,
           (byte) 0x3C, (byte) 0x0C, (byte) 0x7A, (byte) 0x08,
           (byte) 0x8A, (byte) 0x6E, (byte) 0xB5, (byte) 0x78,
           (byte) 0x15, (byte) 0x79, (byte) 0xCF, (byte) 0xB4,
           (byte) 0x02, (byte) 0x0F, (byte) 0x38, (byte) 0x3C,
           (byte) 0x61, (byte) 0x4F, (byte) 0x9D, (byte) 0xDB};

   /**
    * HMAC key to be used for encryption
    *
    * <p>This is the static HMAC key which is only known to the program</p>
    */
   private static final byte[] COMPUTED_HMAC_KEY = new byte[32];

   /**
    * Default character set for string to byte conversion
    */
   private static final String GET_BYTES_CHARACTER_SET = "UTF-8";

   /*
    * Error message constants
    */
   private static final String TEXT_DECRYPTION_MISMATCH_MESSAGE = "Decrypted text is not the same as original text";

   /**
    * Some key elements.
    *
    * <p>For the sake of repeatable tests the source bytes are constants in this test file.
    * In real use use one <b>must never</b> use values that originate <em>in</em> the program.
    * All source <b>are required</b> to originate from <em>outside</em> the program!</p>
    */
   private static final String SOURCE_TEXT_1 = "The quick brown fox jumped over the lazy dog";
   private static final String SOURCE_TEXT_2 = "314159265358979323846264338327952718281828459045235360287471352722459157718361045473427152204544";
   private static final String SOURCE_TEXT_3 = "The answer to the Ultimate Question of Life, the Universe, and Everything";
   private static byte[] SOURCE_BYTES_1;
   private static byte[] SOURCE_BYTES_2;
   private static byte[] SOURCE_BYTES_3;
   private static final byte[] SOURCE_BYTES_4 = new byte[2000];
   private static final byte[] NON_RANDOM_SOURCE_BYTES = new byte[100000];

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
   public TestSplitKeyEncryption() {
   }

   /**
    * Create keys and source data before the test
    */
   @BeforeClass
   public static void setUpClass() throws UnsupportedEncodingException {
      /*
       * Create a deterministic HMAC key from a pseudo-random number generator with a fixed key
       */
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0xEBE770CC82F12283L);

      for (int i = 0; i < COMPUTED_HMAC_KEY.length; i++)
         COMPUTED_HMAC_KEY[i] = xs128.nextByte();

      for (int i = 0; i < SOURCE_BYTES_4.length; i++)
         SOURCE_BYTES_4[i] = xs128.nextByte();

      SOURCE_BYTES_1 = SOURCE_TEXT_1.getBytes(GET_BYTES_CHARACTER_SET);
      SOURCE_BYTES_2 = SOURCE_TEXT_3.getBytes(GET_BYTES_CHARACTER_SET);
      SOURCE_BYTES_3 = SOURCE_TEXT_2.getBytes(GET_BYTES_CHARACTER_SET);

      for(int i=0; i < NON_RANDOM_SOURCE_BYTES.length; i++)
         NON_RANDOM_SOURCE_BYTES[i] = (byte) (0xff - (i & 0xff));
   }

   /**
    * Delete nonrandom key file after the test
    */
   @AfterClass
   public static void tearDownClass() {
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
      Random rnd = new Random();

      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         for (int i = 1; i <= 100; i++) {
            final byte[] testByteArray = new byte[rnd.nextInt(501)];

            rnd.nextBytes(testByteArray);

            String encryptedText = myEncryptor.encryptData(testByteArray);

            byte[] decryptedByteArray = myEncryptor.decryptDataAsByteArray(encryptedText);

            assertArrayEquals("Decrypted byte array is not the same as original byte array", testByteArray, decryptedByteArray);
         }

         myEncryptor.close();
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
      SplitKeyEncryption myEncryptor = null;

      try {
         final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

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
    * Test if the encryption of a given string is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryptionForString() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V5, decryptedText);
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
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5, SUBJECT);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText, SUBJECT);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of an empty string is correctly decrypted.
    */
   @Test
   public void TestEmptyEncryptionDecryption() {
      SplitKeyEncryption myEncryptor = null;

      try {
         final String emptyString = "";

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         final String encryptedText = myEncryptor.encryptData(emptyString);

         final String decryptedText = myEncryptor.decryptDataAsString(encryptedText);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, emptyString, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of an empty string is correctly decrypted with a subject present.
    */
   @Test
   public void TestEmptyEncryptionDecryptionWithSubject() {
      SplitKeyEncryption myEncryptor = null;

      try {
         final String emptyString = "";

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         final String encryptedText = myEncryptor.encryptData(emptyString, SUBJECT);

         final String decryptedText = myEncryptor.decryptDataAsString(encryptedText, SUBJECT);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, emptyString, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a known encrypted text is correctly decrypted.
    */
   @Test
   public void TestKnownDecryption() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_V3);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V3, decryptedText);
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text is correctly decrypted.
    */
   @Test
   public void TestKnownDecryptionWithSubject() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_V5, SUBJECT);

         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V5, decryptedText);
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
      SplitKeyEncryption myEncryptor = null;

      try {
         final byte[] testByteArray = new byte[256];

         for (int i = 0; i < testByteArray.length; i++)
            testByteArray[i] = (byte) (0xff - i);

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsCharacterArray(encryptedText);

         if (myEncryptor != null)
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
      SplitKeyEncryption myEncryptor = null;

      try {
         final byte[] testByteArray = new byte[256];

         for (int i = 0; i < testByteArray.length; i++)
            testByteArray[i] = (byte) (0xff - i);

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsString(encryptedText);

         if (myEncryptor != null)
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
    * Test if a given encrypted text with the wrong subject throws an exception.
    */
   @Test
   public void TestDecryptionWithWrongSubject() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_V5, WRONG_SUBJECT);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidHMAC() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_HMAC);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid encryption throws an
    * exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidEncryption() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid IV throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidIV() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_IV);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an unknown format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithUnknownFormatId() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "Unknown format id", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithInvalidFormatId() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with a missing format id throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithMissingFormatId() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an empty IV throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithEmptyIV() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_EMPTY_IV);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with a missing IV throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithMissingIV() {
      SplitKeyEncryption myEncryptor = null;

      try {
         myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_MISSING_IV);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
      }
   }

   /**
    * Test if an empty HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithEmptyHMAC() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] emptyHMAC = new byte[0];

         myEncryptor = new SplitKeyEncryption(emptyHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too short HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithShortHMAC() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] shortHMAC = new byte[10];

         myEncryptor = new SplitKeyEncryption(shortHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too large HMAC throws an exception.
    */
   @Test
   public void TestKnownDecryptionWithTooLargeHMAC() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] largeHMAC = new byte[70];

         myEncryptor = new SplitKeyEncryption(largeHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "HMAC key length is larger than 32", e.getMessage());
      }
   }

   /**
    * Test if null HMAC key throws an exception.
    */
   @Test
   public void TestNullHMACKey() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aNullHMACKey = null;

         myEncryptor = new SplitKeyEncryption(aNullHMACKey, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "HMAC key is null", e.getMessage());
      }
   }

   /**
    * Test if one null source byte array throws an exception.
    */
   @Test
   public void TestOneNullByteArray() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = null;

         //noinspection ConstantConditions
         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "1. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception.
    */
   @Test
   public void TestAnotherNullByteArray() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
         byte[] anotherSourceByteArray = null;

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray, anotherSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "2. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception.
    */
   @Test
   public void TestZeroLengthByteArray() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
         byte[] anotherSourceByteArray = {};

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray, anotherSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         assertEquals("Exception: " + e.toString(), "2. source byte array has 0 length", e.getMessage());
      }
   }

   /**
    * Test if a very short source byte array throws an exception.
    */
   @Test
   public void TestShortSourceBytes() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC};

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("not enough information provided"));
      }
   }

   /**
    * Test if a uniform source byte array throws an exception.
    */
   @Test
   public void TestUniformSourceBytes() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = new byte[300];

         Arrays.fill(aSourceByteArray, (byte) 0xAA);

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("no information provided"));
      }
   }

   /**
    * Test if a nearly uniform source byte array throws an exception.
    */
   @Test
   public void TestNearlyUniformSourceBytes() {
      SplitKeyEncryption myEncryptor = null;

      try {
         byte[] aSourceByteArray = new byte[100];

         for(int i = 0; i < aSourceByteArray.length; i++) {
            if ((i & 1) != 0)
               aSourceByteArray[i] = (byte) 0x55;
            else
               aSourceByteArray[i] = (byte) 0xAA;
         }

         myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray);

         String decryptedText = myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         if (myEncryptor != null)
            myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         if (myEncryptor != null)
            myEncryptor.close();

         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("at least 129"));
      }
   }
}
