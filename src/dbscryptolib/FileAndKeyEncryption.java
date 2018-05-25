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
 *     2017-12-19: V1.0.0: Created. fhs
 *     2017-12-21: V1.0.1: Corrected comments, added safe data deletion in decryption interface. fhs
 *     2017-12-21: V1.1.0: Correct AByt padding to use cipher block size. fhs
 *     2018-05-17: V1.2.0: Use CTR mode instead of CFB. fhs
 *     2018-05-24: V1.2.1: Put encryption specifications in an array for easier handling. fhs
 *     2018-05-25: V1.2.2: A few changes to enhance readability
 */
package dbscryptolib;

import dbsstringlib.StringSplitter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Implement encryption by key generated from file and key
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.2.2
 */
public class FileAndKeyEncryption implements AutoCloseable {

   /*
    * Private constants
    */
   /**
    * Format id
    */
   private static final byte FORMAT_1_ID = (byte) 1;
   private static final byte FORMAT_2_ID = (byte) 2;

   /**
    * HMAC algorithm to be used
    */
   private static final String FORMAT_1_HMAC_ALGORITHM = "HmacSHA256";

   /**
    * Length of key for HMAC algorithm
    */
   private static final int FORMAT_1_HMAC_KEY_LENGTH = 32;

   /**
    * Encryption algorithm
    */
   private static final String FORMAT_1_ENCRYPTION_ALGORITHM = "AES";

   /**
    * Encrpytion specification with algorithm, mode and padding
    */
   private static final String[] ENCRYPTION_SPECIFICATION = {"Invalid",
                                                             FORMAT_1_ENCRYPTION_ALGORITHM + "/CFB/NoPadding",
                                                             FORMAT_1_ENCRYPTION_ALGORITHM + "/CTR/NoPadding"};

   /**
    * String encoding to be used for encrypted data strings
    */
   private static final String STRING_ENCODING_FOR_DATA = "UTF-8";

   /**
    * Maximum key file size
    */
   private static final int MAX_KEYFILE_SIZE = 10000000;

   /**
    * Instance of secure random number generator
    *
    * This is placed here so the expensive instantiation of the SecureRandom
    * class is done only once.
    */
   private final SecureRandom SECURE_PRNG = new SecureRandom();

   /**
    * Instance of HMAC calculator
    *
    * This is placed here so the expensive instantiation of the Mac class is
    * done only once.
    *
    * Unfortunately it can not be made final as the instantiator of this class
    * may throw an exception.
    */
   private Mac HMAC_INSTANCE;

   /**
    * Helper class to store encryption parameters
    */
   private class EncryptionParts {

      public byte formatId;
      public byte[] iv;
      public byte[] encryptedData;
      public byte[] checksum;

      public void zap() {
         formatId = (byte) 0;

         if (iv != null) {
            Arrays.fill(iv, (byte) 0);
         }

         if (encryptedData != null) {
            Arrays.fill(encryptedData, (byte) 0);
         }

         if (checksum != null) {
            Arrays.fill(checksum, (byte) 0);
         }
      }
   }

   /*
    * Instance variables
    */
   private SecureSecretKeySpec m_EncryptionKey;
   private SecureSecretKeySpec m_HMACKey;

   /*
    * Private methods
    */
   /**
    * Get instance of HMAC
    *
    * @return HMAC instance
    * @throws NoSuchAlgorithmException
    */
   private Mac getHMACInstance() throws NoSuchAlgorithmException {
      if (HMAC_INSTANCE == null) {
         HMAC_INSTANCE = Mac.getInstance(FORMAT_1_HMAC_ALGORITHM);
      }

      return HMAC_INSTANCE;
   }

   /*
    * Check methods
    */
   /**
    * Check HMAC key size
    *
    * @param aHMACKey
    * @throws java.lang.IllegalArgumentException
    */
   private void checkHMACKey(final byte[] aHMACKey) throws IllegalArgumentException {
      if (aHMACKey.length != FORMAT_1_HMAC_KEY_LENGTH) {
         throw new IllegalArgumentException("The HMAC key does not have a length of " + Integer.toString(FORMAT_1_HMAC_KEY_LENGTH) + " bytes");
      }
   }

   /**
    * Check size of key file
    *
    * @param keyFile Path of key file
    * @throws IllegalArgumentException
    * @throws IOException
    */
   private void checkKeyFileSize(final Path keyFile) throws IllegalArgumentException, IOException {
      final long keyFileSize = Files.size(keyFile);

      if (keyFileSize <= 0) {
         throw new IllegalArgumentException("Key file is empty");
      }

      if (keyFileSize > MAX_KEYFILE_SIZE) {
         throw new IllegalArgumentException("Key file is larger than " + Integer.toString(MAX_KEYFILE_SIZE) + " bytes");
      }
   }

   /**
    * Convert an encrypted text into it's parts
    *
    * @param encryptionText Text to be decrypted
    * @return Encryption parameters as <code>EncryptionParts</code> object
    * @throws IllegalArgumentException
    */
   private EncryptionParts getPartsFromPrintableString(final String encryptionText) throws IllegalArgumentException {
      String[] parts;

      parts = StringSplitter.split(encryptionText, "$");  // Use my own string splitter to avoid Java's RegEx inefficiency
//        parts = encryptionText.split("\\Q$\\E");   // This should have been just "$". But Java stays true to it's motto: Why make it simple when there's a complicated way to do it?

      EncryptionParts result = new EncryptionParts();

      try {
         result.formatId = Byte.parseByte(parts[0]);
      } catch (NumberFormatException e) {
         throw new IllegalArgumentException("Invalid format id");
      }

      switch (result.formatId) {
         case FORMAT_2_ID:
         case FORMAT_1_ID:
            if (parts.length == 4) {
               Base64.Decoder b64Decoder = Base64.getDecoder();

               result.iv = b64Decoder.decode(parts[1]);
               result.encryptedData = b64Decoder.decode(parts[2]);
               result.checksum = b64Decoder.decode(parts[3]);
            } else {
               throw new IllegalArgumentException("Number of '$' separated parts in encrypted text is not 4");
            }
         break;
         
         default:
            throw new IllegalArgumentException("Unknown format id");         
      }

      return result;
   }

   /**
    * Decrypt data that have been created by the corresponding encryption
    *
    * @param encryptionParts The encryption parts of the data
    * @return Decrypted data as string
    * @throws dbscryptolib.DataIntegrityException
    * @throws javax.crypto.BadPaddingException
    * @throws javax.crypto.IllegalBlockSizeException
    * @throws java.security.InvalidAlgorithmParameterException
    * @throws java.security.InvalidKeyException
    * @throws java.security.NoSuchAlgorithmException
    * @throws javax.crypto.NoSuchPaddingException
    * @throws java.io.UnsupportedEncodingException
    */
   private String rawDecryptData(final EncryptionParts encryptionParts) throws DataIntegrityException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_SPECIFICATION[encryptionParts.formatId]);

      String result;

      aesCipher.init(Cipher.DECRYPT_MODE, this.m_EncryptionKey, new IvParameterSpec(encryptionParts.iv));

      final byte[] paddedDecodedStringBytes = aesCipher.doFinal(encryptionParts.encryptedData);

      final byte[] unpaddedDecodedStringBytes = ArbitraryTailPadding.removePadding(paddedDecodedStringBytes);

      Arrays.fill(paddedDecodedStringBytes, (byte) 0);

      result = new String(unpaddedDecodedStringBytes, STRING_ENCODING_FOR_DATA);

      Arrays.fill(unpaddedDecodedStringBytes, (byte) 0);

      return result;
   }

   /**
    * Build a printable string from the encrypted parts
    *
    * @param encryptionParts Parts to be printed
    * @return Printable string of the encrypted parts
    */
   private String makePrintableStringFromEncryptionParts(final EncryptionParts encryptionParts) {
      Base64.Encoder b64Encoder = Base64.getEncoder();
      StringBuilder myStringBuilder = new StringBuilder();

      myStringBuilder.append(Byte.toString(encryptionParts.formatId));
      myStringBuilder.append("$");
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.iv));
      myStringBuilder.append("$");
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.encryptedData));
      myStringBuilder.append("$");
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.checksum));

      return myStringBuilder.toString();
   }

   /**
    * Calculate the HMAC of the encrypted parts
    *
    * @param encryptionParts Encrypted parts to calculate the checksum for
    * @return Checksum of the encrypted parts
    * @throws InvalidKeyException
    * @throws NoSuchAlgorithmException
    */
   private byte[] getChecksumForEncryptionParts(EncryptionParts encryptionParts) throws InvalidKeyException, NoSuchAlgorithmException {
      final Mac hmac = getHMACInstance();

      hmac.init(this.m_HMACKey);
      hmac.update(encryptionParts.formatId);
      hmac.update(encryptionParts.iv);

      return hmac.doFinal(encryptionParts.encryptedData);
   }

   /**
    * Check the checksum of the encrypted parts that have been read
    *
    * @param encryptionParts Parts to be checked
    * @throws DataIntegrityException
    * @throws InvalidKeyException
    * @throws NoSuchAlgorithmException
    */
   private void checkChecksumForEncryptionParts(EncryptionParts encryptionParts) throws DataIntegrityException, InvalidKeyException, NoSuchAlgorithmException {
      final byte[] calculatedChecksum = getChecksumForEncryptionParts(encryptionParts);

      if (!Arrays.equals(calculatedChecksum, encryptionParts.checksum)) {
         throw new DataIntegrityException("Checksums do not match");
      }
   }

   /**
    * Encrypt string data
    *
    * @param sourceString Some string that will be encrypted
    * @return Encrypted data and iv as EncryptionParts object
    * @throws javax.crypto.BadPaddingException
    * @throws java.lang.IllegalArgumentException
    * @throws javax.crypto.IllegalBlockSizeException
    * @throws java.security.InvalidAlgorithmParameterException
    * @throws java.security.InvalidKeyException
    * @throws java.security.NoSuchAlgorithmException
    * @throws javax.crypto.NoSuchPaddingException
    * @throws java.io.UnsupportedEncodingException
    */
   private EncryptionParts rawDataEncryption(final String sourceString) throws BadPaddingException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      EncryptionParts result = new EncryptionParts();

      // Set format id
      result.formatId = FORMAT_2_ID;

      Cipher aesCipher = Cipher.getInstance(ENCRYPTION_SPECIFICATION[result.formatId]);

      // Get a random iv
      result.iv = new byte[aesCipher.getBlockSize()];

      SECURE_PRNG.nextBytes(result.iv);

      // Encrypt the source string with the iv
      aesCipher.init(Cipher.ENCRYPT_MODE, this.m_EncryptionKey, new IvParameterSpec(result.iv));

      final byte[] unpaddedEncodedStringBytes = sourceString.getBytes(STRING_ENCODING_FOR_DATA);

      final byte[] paddedEncodedStringBytes = ArbitraryTailPadding.addPadding(unpaddedEncodedStringBytes, aesCipher.getBlockSize());

      Arrays.fill(unpaddedEncodedStringBytes, (byte) 0);

      result.encryptedData = aesCipher.doFinal(paddedEncodedStringBytes);

      Arrays.fill(paddedEncodedStringBytes, (byte) 0);

      return result;
   }

   /**
    * Get HMAC value of a byte array
    *
    * @param key The key for the HMAC
    * @param data The data to be hashed
    * @return HMAC value of the specified data with specified key
    * @throws java.security.InvalidKeyException
    * @throws java.security.NoSuchAlgorithmException
    */
   private byte[] getHmacValueForBytes(final byte[] key, final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
      final Mac hmac = getHMACInstance();
      byte[] result;

      try (SecureSecretKeySpec hmacKey = new SecureSecretKeySpec(key, FORMAT_1_HMAC_ALGORITHM)) {
         hmac.init(hmacKey);
         result = hmac.doFinal(data);
      }

      return result;
   }

   /**
    * Set the keys of this instance from a key file and a HMAC key
    *
    * @param hmacKey HMAC key to be used
    * @param keyFile Key file to be used
    * @throws InvalidKeyException
    * @throws IOException
    * @throws NoSuchAlgorithmException
    */
   private void setKeysFromKeyAndFile(final byte[] hmacKey, final Path keyFile) throws InvalidKeyException, IOException, NoSuchAlgorithmException {
      final byte[] hmacOfKeyFile = getHmacValueForBytes(hmacKey, Files.readAllBytes(keyFile));

      byte[] keyPart;

      // 1. half of file HMAC is used as the encryption key of this instance
      keyPart = Arrays.copyOfRange(hmacOfKeyFile, 0, 16);
      this.m_EncryptionKey = new SecureSecretKeySpec(keyPart, FORMAT_1_ENCRYPTION_ALGORITHM);
      Arrays.fill(keyPart, (byte) 0);

      // 2. half of file HMAC is used as the HMAC key of this instance
      keyPart = Arrays.copyOfRange(hmacOfKeyFile, 16, 32);
      this.m_HMACKey = new SecureSecretKeySpec(keyPart, FORMAT_1_HMAC_ALGORITHM);
      Arrays.fill(keyPart, (byte) 0);

      Arrays.fill(hmacOfKeyFile, (byte) 0);
   }


   /*
    * Public methods
    */
   /**
    * Constructor for this instance
    *
    * @param hmacKey Key for the HMAC of the file
    * @param keyFilePath Key file path
    * @throws IllegalArgumentException
    * @throws InvalidKeyException
    * @throws IOException
    * @throws NoSuchAlgorithmException
    */
   public FileAndKeyEncryption(final byte[] hmacKey, final String keyFilePath) throws IllegalArgumentException, InvalidKeyException, IOException, NoSuchAlgorithmException {
      checkHMACKey(hmacKey);

      final Path keyFile = Paths.get(keyFilePath);

      checkKeyFileSize(keyFile);

      setKeysFromKeyAndFile(hmacKey, keyFile);
   }

   /**
    * Encrypt a string
    *
    * @param stringToEncrypt String to encrypt
    * @return Printable form of the encrypted string
    * @throws BadPaddingException
    * @throws IllegalArgumentException
    * @throws IllegalBlockSizeException
    * @throws InvalidAlgorithmParameterException
    * @throws InvalidKeyException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchPaddingException
    * @throws UnsupportedEncodingException
    */
   public String encryptData(final String stringToEncrypt) throws BadPaddingException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      EncryptionParts encryptionParts = rawDataEncryption(stringToEncrypt);

      encryptionParts.checksum = getChecksumForEncryptionParts(encryptionParts);

      String result = makePrintableStringFromEncryptionParts(encryptionParts);

      encryptionParts.zap();

      return result;
   }

   /**
    * Decrypt an encrypted string
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string
    * @throws BadPaddingException
    * @throws DataIntegrityException
    * @throws IllegalArgumentException
    * @throws IllegalBlockSizeException
    * @throws InvalidAlgorithmParameterException
    * @throws InvalidKeyException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchPaddingException
    * @throws UnsupportedEncodingException
    */
   public String decryptData(final String stringToDecrypt) throws BadPaddingException, DataIntegrityException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      EncryptionParts encryptionParts = getPartsFromPrintableString(stringToDecrypt);

      String result = null;

      switch (encryptionParts.formatId) {
         case FORMAT_2_ID:
         case FORMAT_1_ID:
            checkChecksumForEncryptionParts(encryptionParts);

            result = rawDecryptData(encryptionParts);

            encryptionParts.zap();
         break;

         default:
            encryptionParts.zap();

            throw new IllegalArgumentException("Unknown format id");
      }

      return result;
   }

   /*
    * Method for AutoCloseable interface
    */
   /**
    * Secure deletion of keys
    *
    * This method is idempotent and never throws an exception.
    */
   @Override
   public void close() {
      this.m_EncryptionKey.close();
      this.m_HMACKey.close();
   }
}
