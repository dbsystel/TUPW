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
 *     2017-12-19: V1.0.0: Created. fhs
 *     2017-12-21: V1.0.1: Corrected comments, added safe data deletion in decryption interface. fhs
 *     2017-12-21: V1.1.0: Correct AByt padding to use cipher block size. fhs
 *     2018-05-17: V1.2.0: Use CTR mode instead of CFB. fhs
 *     2018-05-24: V1.2.1: Put encryption specifications in an array for easier handling. fhs
 *     2018-05-25: V1.2.2: A few changes to enhance readability. fhs
 *     2018-06-13: V1.3.0: Use constant time array comparison on HMAC check to thwart
 *                          timing attacks. fhs
 *     2018-06-22: V1.3.1: Use a StringBuilder with sufficient intial capacity. fhs
 *     2018-06-22: V1.3.2: Use dynamic StringBuilder capacity calculation. fhs
 *     2018-06-22: V1.3.3: Rethrow exception if hashing went wrong. fhs
 *     2018-08-07: V1.3.4: Some small improvements. fhs
 *     2018-08-15: V1.3.5: Added some "finals". fhs
 *     2018-08-16: V1.3.6: Moved secure PRNG generation to the one method that needs it. fhs
 *     2018-08-17: V1.4.0: Use blinding and random padding, made PRNG module visible again. fhs
 *     2019-03-07: V2.0.0: Add a "subject" that changes the encryption key. fhs
 *     2019-08-01: V2.1.0: Use CBC mode, as the encrypted part is protected by a HMAC and CBC does
 *                         not suffer from the stream cipher vulnerabilities of CFB and CTR mode.
 *                         Use Base64 encoding without padding. fhs
 *     2019-08-02: V2.1.1: New data integrity exception text. fhs
 *     2019-08-02: V2.2.0: Use strong SPRNG. fhs
 *     2019-08-03: V2.2.1: Refactored SPRNG instantiation. fhs
 *     2019-08-05: V2.2.2: Change method name of SPRNG instantiation. fhs
 *     2019-08-23: V2.2.3: Use SecureRandom singleton. fhs
 *     2020-02-12: V2.3.0: Correct wrong generation of keys with the "subject" parameter. fhs
 *     2020-02-19: V2.3.1: Some more zapping of intermediate key byte arrays. fhs
 *     2020-02-24: V3.0.0: Use any provided bytes as the sources for key derivation, not just
 *                         the contents of a file. fhs
 *     2020-02-27: V3.0.1: Added maximum HMAC key length. fhs
 *     2020-02-27: V3.1.0: Some hardening against null pointers. fhs
 *     2020-02-28: V3.2.0: Check entropy of provided source bytes. fhs
 */
package dbscryptolib;

import dbsstatisticslib.EntropyCalculator;
import dbsstringlib.StringSplitter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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

/**
 * Implement encryption by key generated from file and key
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 3.2.0
 */
public class FileAndKeyEncryption implements AutoCloseable {

   /*
    * Private constants
    */

   /**
    * Boundaries for valid format ids
    */
   private static final byte FORMAT_ID_MIN = 1;
   private static final byte FORMAT_ID_MAX = 5;

   /**
    * HMAC algorithm to be used
    */
   private static final String HMAC_256_ALGORITHM_NAME = "HmacSHA256";

   /**
    * Miniumum length of key for HMAC algorithm
    */
   private static final int MINIMUM_HMAC_KEY_LENGTH = 14;

   /**
    * Maxiumum length of key for HMAC algorithm
    *
    * <p>The HMAC key must not be larger than the block size of the underlying hash algorithm.
    * Here this is 32 bytes (256 bits). If the hash block size changes this constant
    * must be changed, as well.</p>
    */
   private static final int MAXIMUM_HMAC_KEY_LENGTH = 32;

   /**
    * Encryption algorithm
    */
   private static final String AES_ALGORITHM_NAME = "AES";

   /**
    * Encryption specification with algorithm, mode and padding
    *
    * <p>
    * The index of the string in the array corresponds to the format id
    * </p>
    */
   private static final String[] ENCRYPTION_SPECIFICATION = {"Invalid",
           AES_ALGORITHM_NAME + "/CFB/NoPadding",
           AES_ALGORITHM_NAME + "/CTR/NoPadding",
           AES_ALGORITHM_NAME + "/CTR/NoPadding",
           AES_ALGORITHM_NAME + "/CBC/NoPadding",
           AES_ALGORITHM_NAME + "/CBC/NoPadding"};

   /**
    * String encoding to be used for encrypted data strings
    */
   private static final String STRING_ENCODING_FOR_DATA = "UTF-8";

   /**
    * Separator character in key representation
    */
   private static final String PARTS_SEPARATOR = "$";

   /**
    * Minimum source bytes length
    */
   private static final int MINIMUM_SOURCE_BYTES_LENGTH = 100;

   /**
    * Maximum source bytes length
    */
   private static final int MAXIMUM_SOURCE_BYTES_LENGTH = 10000000;

   /**
    * Minimum source bytes information in bits
    */
   private static final int MINIMUM_SOURCE_BITS = 128;

   /**
    * Prefix salt for key modification with a "subject"
    */
   private static final byte[] PREFIX_SALT = {(byte) 84, (byte) 117}; // i.e "Tu"

   /**
    * Postfix salt for key modification with a "subject"
    */
   private static final byte[] POSTFIX_SALT = {(byte) 112, (byte) 87}; // i.e. "pW"


   /**
    * Instance of HMAC calculator
    * <p>
    * This is placed here so the expensive instantiation of the Mac class is
    * done only once.
    * <p>
    * Unfortunately it can not be made final as the constructor of this class
    * may throw an exception.
    */
   private Mac HMAC_INSTANCE;

   /**
    * Instance of SecureRandom pseudo random number generator (PRNG)
    * <p>
    * This is placed here so the expensive instantiation of the SecureRandom class is
    * done only once.
    * <p>
    */
   private SecureRandom SECURE_RANDOM_INSTANCE;

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

         if (iv != null)
            Arrays.fill(iv, (byte) 0);

         if (encryptedData != null)
            Arrays.fill(encryptedData, (byte) 0);

         if (checksum != null)
            Arrays.fill(checksum, (byte) 0);
      }
   }

   /*
    * Instance variables
    */
   private ProtectedByteArray m_EncryptionKey;
   private ProtectedByteArray m_HMACKey;

   /*
    * Private methods
    */

   /**
    * Get instance of HMAC
    *
    * @return HMAC instance
    * @throws NoSuchAlgorithmException if the specified HMAC algorithm is not implemented
    */
   private Mac getHMACInstance() throws NoSuchAlgorithmException {
      if (HMAC_INSTANCE == null)
         HMAC_INSTANCE = Mac.getInstance(HMAC_256_ALGORITHM_NAME);

      return HMAC_INSTANCE;
   }

   /**
    * Get instance of SecureRandom
    *
    * @return SecureRandom instance
    */
   private SecureRandom getSecureRandomInstance() {
      if (SECURE_RANDOM_INSTANCE == null)
         SECURE_RANDOM_INSTANCE = SecureRandomFactory.getSensibleSingleton();

      return SECURE_RANDOM_INSTANCE;
   }

   /*
    * Check methods
    */

   /**
    * Check HMAC key size
    *
    * @param aHMACKey Key for HMAC calculation
    * @throws java.lang.IllegalArgumentException if the HMAC key does not have the correct length
    */
   private void checkHMACKey(final byte[] aHMACKey) throws IllegalArgumentException {
      if (aHMACKey != null) {
         if (aHMACKey.length < MINIMUM_HMAC_KEY_LENGTH)
            throw new IllegalArgumentException("HMAC key length is less than " + Integer.toString(MINIMUM_HMAC_KEY_LENGTH));

         if (aHMACKey.length > MAXIMUM_HMAC_KEY_LENGTH)
            throw new IllegalArgumentException("HMAC key length is larger than " + Integer.toString(MAXIMUM_HMAC_KEY_LENGTH));
      } else
         throw new IllegalArgumentException("HMAC key is null");
   }

   /**
    * Check length of supplied source bytes
    *
    * @param sourceBytes Array of source byte arrays
    */
   private void checkSourceBytes(final byte[]... sourceBytes) {
      int totalLength = 0;

      EntropyCalculator ec = new EntropyCalculator();

      for (int i = 0; i < sourceBytes.length; i++) {
         if (sourceBytes[i] != null) {
            ec.addBytes(sourceBytes[i]);
            totalLength += sourceBytes[i].length;
         } else
            throw new IllegalArgumentException((i + 1) + ". source byte array is null");
      }

      if (ec.getInformationInBits() < MINIMUM_SOURCE_BITS)
         throw new IllegalArgumentException("There is not enough information provided in the source bytes. Try to increase the length by " + (((int) Math.round(MINIMUM_SOURCE_BITS / ec.getEntropy()))- totalLength + 1) + " bytes");

      if (totalLength < MINIMUM_SOURCE_BYTES_LENGTH)
         throw new IllegalArgumentException("There are less than " + MINIMUM_SOURCE_BYTES_LENGTH + " source bytes");

      if (totalLength > MAXIMUM_SOURCE_BYTES_LENGTH)
         throw new IllegalArgumentException("There are more than " + MAXIMUM_SOURCE_BYTES_LENGTH + " source bytes");
   }

   /**
    * Convert an encrypted text into it's parts
    *
    * @param encryptionText Text to be decrypted
    * @return Encryption parameters as <code>EncryptionParts</code> object
    * @throws IllegalArgumentException if the encrypted text has an invalid or unknown format id or not the correct
    *                                  number of '$' separated parts
    */
   private EncryptionParts getPartsFromPrintableString(final String encryptionText) throws IllegalArgumentException {
      final String[] parts = StringSplitter.split(encryptionText, PARTS_SEPARATOR);  // Use my own string splitter to avoid Java's RegEx inefficiency
//        parts = encryptionText.split("\\Q$\\E");   // This should have been just "$". But Java stays true to it's motto: Why make it simple when there's a complicated way to do it?

      final EncryptionParts result = new EncryptionParts();

      try {
         result.formatId = Byte.parseByte(parts[0]);
      } catch (final NumberFormatException e) {
         throw new IllegalArgumentException("Invalid format id");
      }

      if ((result.formatId >= FORMAT_ID_MIN) && (result.formatId <= FORMAT_ID_MAX)) {
         if (parts.length == 4) {
            Base64.Decoder b64Decoder = Base64.getDecoder();

            result.iv = b64Decoder.decode(parts[1]);
            result.encryptedData = b64Decoder.decode(parts[2]);
            result.checksum = b64Decoder.decode(parts[3]);
         } else
            throw new IllegalArgumentException("Number of '$' separated parts in encrypted text is not 4");
      } else
         throw new IllegalArgumentException("Unknown format id");

      return result;
   }

   /**
    * Return unpadded string bytes depending on format id
    *
    * @param formatId                   Format id of data
    * @param paddedDecryptedStringBytes Byte array of padded decrypted bytes
    * @return Unpadded decrypted bytes
    */
   private byte[] getUnpaddedStringBytes(final byte formatId, final byte[] paddedDecryptedStringBytes) {
      // Formats 1 and 2 use padding. Starting from format 3 blinding is used.
      if (formatId >= 3)
         return ByteArrayBlinding.unBlindByteArray(paddedDecryptedStringBytes);
      else
         return ArbitraryTailPadding.removePadding(paddedDecryptedStringBytes);
   }

   /**
    * Get SecureSecretKeySpec with respect to a subject
    *
    * <p>This method returns a 256 bit key, whereas, when there is no subject
    * a 128 bit key is used.</p>
    *
    * @param hmacKey          The key to use for HMAC calculation
    * @param baseKey          The key the subject key is derived from as a byte array
    * @param forAlgorithmName Algorithm name for the SecureSecretKeySpec to create
    * @param subjectBytes     The subject as a byte array
    * @return SecureSecretKeySpec with the specified subject
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForKeyWithSubject(final ProtectedByteArray hmacKey,
                                                                 final ProtectedByteArray baseKey,
                                                                 final String forAlgorithmName,
                                                                 final byte[] subjectBytes) throws InvalidKeyException, NoSuchAlgorithmException {
      final Mac hmac = getHMACInstance();

      final byte[] hmacKeyBytes = hmacKey.getData();
      final SecureSecretKeySpec hmacKeySpec = new SecureSecretKeySpec(hmacKeyBytes, HMAC_256_ALGORITHM_NAME);
      Arrays.fill(hmacKeyBytes, (byte) 0);

      hmac.init(hmacKeySpec);

      final byte[] baseKeyBytes = baseKey.getData();
      hmac.update(baseKeyBytes);
      Arrays.fill(baseKeyBytes, (byte) 0);

      hmac.update(PREFIX_SALT);
      hmac.update(subjectBytes);

      final byte[] computedKey = hmac.doFinal(POSTFIX_SALT);
      final SecureSecretKeySpec result = new SecureSecretKeySpec(computedKey, forAlgorithmName);
      Arrays.fill(computedKey, (byte) 0);

      return result;
   }

   /**
    * Get default SecureSecretKeySpec for key
    *
    * @param baseKey          The key to wrap in a SecureSecretKeySpec
    * @param forAlgorithmName Algorithm name for the SecureSecretKeySpec to create
    * @return SecureSecretKeySpec of specified key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForKey(final ProtectedByteArray baseKey,
                                                             final String forAlgorithmName) {
      final byte[] baseKeyBytes = baseKey.getData();
      final SecureSecretKeySpec result = new SecureSecretKeySpec(baseKeyBytes, forAlgorithmName);
      Arrays.fill(baseKeyBytes, (byte) 0);

      return result;
   }

   /**
    * Get default SecureSecretKeySpec for encryption
    *
    * @return SecureSecretKeySpec for default encryption key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForEncryption() {
      return getDefaultSecretKeySpecForKey(this.m_EncryptionKey, AES_ALGORITHM_NAME);
   }

   /**
    * Get default SecureSecretKeySpec for HMAC calculation
    *
    * @return SecureSecretKeySpec for default HMAC key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForHMAC() {
      return getDefaultSecretKeySpecForKey(this.m_HMACKey, HMAC_256_ALGORITHM_NAME);
   }

   /**
    * Get encryption key depending on whether a subject is present or not
    *
    * @param subjectBytes The subject as a byte array (may have length 0)
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForEncryptionDependingOnSubject(final byte[] subjectBytes) throws InvalidKeyException, NoSuchAlgorithmException {
      if (subjectBytes.length > 0)
         return getSecretKeySpecForKeyWithSubject(this.m_HMACKey, this.m_EncryptionKey, AES_ALGORITHM_NAME, subjectBytes);
      else
         return getDefaultSecretKeySpecForEncryption();
   }

   /**
    * Get HMAC key depending on whether a subject is present or not
    *
    * @param subjectBytes The subject as a byte array (may have length 0)
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForHMACDependingOnSubject(final byte[] subjectBytes) throws InvalidKeyException, NoSuchAlgorithmException {
      if (subjectBytes.length > 0)
         return getSecretKeySpecForKeyWithSubject(this.m_EncryptionKey, this.m_HMACKey, HMAC_256_ALGORITHM_NAME, subjectBytes);
      else
         return getDefaultSecretKeySpecForHMAC();
   }

   /**
    * Decrypt data that have been created by the corresponding encryption
    *
    * @param encryptionParts The encryption parts of the data
    * @param subjectBytes    The subject for this decryption
    * @return Decrypted data as string
    * @throws java.io.UnsupportedEncodingException             if there is no UTF-8 encoding (must never happen)
    * @throws java.security.InvalidAlgorithmParameterException if there was an invalid parameter for the encrpytion algorithm
    * @throws java.security.InvalidKeyException                if the key is not valid for the encryption algorithm (must never happen)
    * @throws java.security.NoSuchAlgorithmException           if there is no AES encryption (must never happen)
    * @throws javax.crypto.BadPaddingException                 if unpadding does not work (must never happen)
    * @throws javax.crypto.IllegalBlockSizeException           if the block size is not valid for the encryption algorithm (must never happen)
    * @throws javax.crypto.NoSuchPaddingException              if there is no NoPadding padding 8must never happen)
    */
   private String rawDataDecryption(final EncryptionParts encryptionParts, final byte[] subjectBytes) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      // "encryptionParts.formatId" has been checked in "decryptData" and does not need to be checked here
      final String encryptionSpecification = ENCRYPTION_SPECIFICATION[encryptionParts.formatId];

      final Cipher aesCipher = Cipher.getInstance(encryptionSpecification);

      final SecureSecretKeySpec decryptionKey = getSecretKeySpecForEncryptionDependingOnSubject(subjectBytes);

      aesCipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(encryptionParts.iv));

      final byte[] paddedDecryptedStringBytes = aesCipher.doFinal(encryptionParts.encryptedData);

      decryptionKey.close();

      final byte[] unpaddedDecryptedStringBytes = getUnpaddedStringBytes(encryptionParts.formatId, paddedDecryptedStringBytes);

      Arrays.fill(paddedDecryptedStringBytes, (byte) 0);

      final String result = new String(unpaddedDecryptedStringBytes, STRING_ENCODING_FOR_DATA);

      Arrays.fill(unpaddedDecryptedStringBytes, (byte) 0);

      return result;
   }

   /**
    * Calculate capacity of StringBuilder for encryption parts
    * <p>
    * The size of the final string is 4 + SumOf(ceil(ArrayLength * 4 / 3)).
    * <p>
    * This is a complicated expression which is overestimated by the easier
    * expression 4 + SumOfArrayLengths * 3 / 2
    *
    * @param encryptionParts Encryption parts to calculate the capacity for
    * @return Slightly overestimated capacity of the StringBuilder for the
    * supplied encryption parts
    */
   private int calculateStringBuilderCapacityForEncryptionParts(final EncryptionParts encryptionParts) {
      final int arrayLengths = encryptionParts.iv.length + encryptionParts.encryptedData.length + encryptionParts.checksum.length;

      return 4 + arrayLengths + (arrayLengths >> 1);
   }

   /**
    * Build a printable string from the encrypted parts
    *
    * @param encryptionParts Parts to be printed
    * @return Printable string of the encrypted parts
    */
   private String makePrintableStringFromEncryptionParts(final EncryptionParts encryptionParts) {
      Base64.Encoder b64Encoder = Base64.getEncoder().withoutPadding();
      StringBuilder myStringBuilder = new StringBuilder(calculateStringBuilderCapacityForEncryptionParts(encryptionParts));

      myStringBuilder.append(Byte.toString(encryptionParts.formatId));
      myStringBuilder.append(PARTS_SEPARATOR);
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.iv));
      myStringBuilder.append(PARTS_SEPARATOR);
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.encryptedData));
      myStringBuilder.append(PARTS_SEPARATOR);
      myStringBuilder.append(b64Encoder.encodeToString(encryptionParts.checksum));

      return myStringBuilder.toString();
   }

   /**
    * Calculate the HMAC of the encrypted parts
    *
    * @param encryptionParts Encrypted parts to calculate the checksum for
    * @return Checksum of the encrypted parts
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private byte[] getChecksumForEncryptionParts(final EncryptionParts encryptionParts, final byte[] subjectBytes) throws InvalidKeyException, NoSuchAlgorithmException {
      final Mac hmac = getHMACInstance();

      if (encryptionParts.formatId >= 5)
         hmac.init(getSecretKeySpecForHMACDependingOnSubject(subjectBytes));
      else
         hmac.init(getDefaultSecretKeySpecForHMAC());

      hmac.update(encryptionParts.formatId);
      hmac.update(encryptionParts.iv);

      return hmac.doFinal(encryptionParts.encryptedData);
   }

   /**
    * Check the checksum of the encrypted parts that have been read
    *
    * @param encryptionParts Parts to be checked
    * @throws DataIntegrityException   if the HMAC of the parts is not correct
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private void checkChecksumForEncryptionParts(final EncryptionParts encryptionParts, final byte[] subjectBytes) throws DataIntegrityException, InvalidKeyException, NoSuchAlgorithmException {
      final byte[] calculatedChecksum = getChecksumForEncryptionParts(encryptionParts, subjectBytes);

      if (!SafeArrays.constantTimeEquals(calculatedChecksum, encryptionParts.checksum))
         throw new DataIntegrityException("Checksum does not match data");
   }

   /**
    * Encrypt string data
    *
    * @param sourceString Some string that will be encrypted
    * @param subjectBytes The subject of this encryption as a byte array
    * @return Encrypted data and iv as EncryptionParts object
    * @throws java.io.IOException
    * @throws java.io.UnsupportedEncodingException             if there is nu "UTF-8" character encoding (must never happen)
    * @throws java.lang.IllegalArgumentException
    * @throws java.security.InvalidAlgorithmParameterException if an invalid encryption parameter was specified (must never happen)
    * @throws java.security.InvalidKeyException                if an invalid encryption key was specified (must never happen)
    * @throws java.security.NoSuchAlgorithmException           if an invalid encryption algorithm was specified (must never happen)
    * @throws javax.crypto.BadPaddingException                 if invalid padding data was specified (must never happen)
    * @throws javax.crypto.IllegalBlockSizeException           if an invalid block size was specified (must never happen)
    * @throws javax.crypto.NoSuchPaddingException              if an invalid padding was specified (must never happen)
    */
   private EncryptionParts rawDataEncryption(final String sourceString, final byte[] subjectBytes) throws BadPaddingException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      EncryptionParts result = new EncryptionParts();

      // Set format id
      result.formatId = FORMAT_ID_MAX;

      final byte[] sourceBytes = sourceString.getBytes(STRING_ENCODING_FOR_DATA);

      final String encryptionSpecification = ENCRYPTION_SPECIFICATION[result.formatId];

      final Cipher aesCipher = Cipher.getInstance(encryptionSpecification);

      // Ensure that blinded array needs at least 2 AES blocks, so the length of the encrypted data
      // can not be inferred to be no longer than block size - 3 bytes (= 13 bytes for AES).
      final byte[] unpaddedEncodedStringBytes = ByteArrayBlinding.buildBlindedByteArray(sourceBytes, aesCipher.getBlockSize() + 1);

      Arrays.fill(sourceBytes, (byte) 0);

      final byte[] paddedEncodedStringBytes = RandomPadding.addPadding(unpaddedEncodedStringBytes, aesCipher.getBlockSize());

      Arrays.fill(unpaddedEncodedStringBytes, (byte) 0);

      // Get a random iv
      result.iv = new byte[aesCipher.getBlockSize()];

      getSecureRandomInstance().nextBytes(result.iv);

      final SecureSecretKeySpec encryptionKey = getSecretKeySpecForEncryptionDependingOnSubject(subjectBytes);

      // Encrypt the source string with the iv
      aesCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(result.iv));

      result.encryptedData = aesCipher.doFinal(paddedEncodedStringBytes);

      Arrays.fill(paddedEncodedStringBytes, (byte) 0);

      encryptionKey.close();

      return result;
   }

   /**
    * Get HMAC value of an array of byte arrays
    *
    * @param key         The key for the HMAC
    * @param sourceBytes The source bytes to be hashed
    * @return HMAC value of the specified data with specified key
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private byte[] getHmacValueOfSourceBytes(final byte[] key, final byte[]... sourceBytes) throws InvalidKeyException, NoSuchAlgorithmException {
      final Mac hmac = getHMACInstance();
      byte[] result = null;

      try (SecureSecretKeySpec hmacKey = new SecureSecretKeySpec(key, HMAC_256_ALGORITHM_NAME)) {
         hmac.init(hmacKey);

         for (int i = 0; i < sourceBytes.length; i++)
            hmac.update(sourceBytes[i]);

         result = hmac.doFinal();
      } catch (final Exception e) {
         throw e; // Rethrow any exception. hmacKey will have been closed by try-with-resources.
      }

      return result;
   }

   /**
    * Get the content of the key file
    *
    * @param keyFile Key file to be used
    * @throws IOException if there is an error reading the key file
    */
   private byte[] getContentOfFile(final Path keyFile) throws IOException {
      final byte[] result = Files.readAllBytes(keyFile);

      return result;
   }

   /**
    * Set the keys of this instance from the supplied byte arrays and a HMAC key
    *
    * @param hmacKey     HMAC key to be used
    * @param sourceBytes bytes to be used for key derivation
    * @throws InvalidKeyException      if the key is not valid for the HMAC algorithm (must never happen)
    * @throws IOException              if there is an error reading the key file
    * @throws NoSuchAlgorithmException if there is no HMAC-256 algorithm (must never happen)
    */
   private void setKeysFromKeyAndSourceBytes(final byte[] hmacKey, final byte[]... sourceBytes) throws InvalidKeyException, IOException, NoSuchAlgorithmException {
      final byte[] hmacOfSourceBytes = getHmacValueOfSourceBytes(hmacKey, sourceBytes);

      // 1. half of file HMAC is used as the encryption key of this instance
      byte[] keyPart = Arrays.copyOfRange(hmacOfSourceBytes, 0, 16);

      this.m_EncryptionKey = new ProtectedByteArray(keyPart);
      Arrays.fill(keyPart, (byte) 0);

      // 2. half of file HMAC is used as the HMAC key of this instance
      keyPart = Arrays.copyOfRange(hmacOfSourceBytes, 16, 32);

      Arrays.fill(hmacOfSourceBytes, (byte) 0);

      this.m_HMACKey = new ProtectedByteArray(keyPart);
      Arrays.fill(keyPart, (byte) 0);
   }


   /*
    * Public methods
    */

   /**
    * Constructor for this instance
    *
    * <p><b>Attention:</b> The caller is responsible for clearing the source byte arrays
    * with {@code Arrays.fill()} after they have been used here.</p>
    *
    * @param hmacKey     Key for the HMAC of the file
    * @param sourceBytes Bytes that the key is derived from
    * @throws IllegalArgumentException The HMAC key or the source bytes are not valid
    * @throws InvalidKeyException      if the key is invalid (must never happen)
    * @throws IOException              if there was an error while reading the key file
    * @throws NoSuchAlgorithmException if the encryption algorithm is invalid (must never happen)
    */
   public FileAndKeyEncryption(final byte[] hmacKey, final byte[]... sourceBytes) throws IllegalArgumentException, InvalidKeyException, IOException, NoSuchAlgorithmException {
      checkHMACKey(hmacKey);

      checkSourceBytes(sourceBytes);

      setKeysFromKeyAndSourceBytes(hmacKey, sourceBytes);
   }

   /**
    * Constructor for this instance
    *
    * @param hmacKey     Key for the HMAC of the file
    * @param keyFilePath Key file path
    * @throws IllegalArgumentException The HMAC key or the size of the key file are not valid
    * @throws InvalidKeyException      if the key is invalid (must never happen)
    * @throws IOException              if there was an error while reading the key file
    * @throws NoSuchAlgorithmException if the encryption algorithm is invalid (must never happen)
    */
   public FileAndKeyEncryption(final byte[] hmacKey, final String keyFilePath) throws IllegalArgumentException, InvalidKeyException, IOException, NoSuchAlgorithmException {
      checkHMACKey(hmacKey);

      Path keyFile;

      try {
         keyFile = Paths.get(keyFilePath);
      } catch (NullPointerException e) {
         throw new IllegalArgumentException("Key file path is null");
      } catch (Exception e) {
         throw new IllegalArgumentException("Key file path is invalid: " + e.getMessage());
      }

      final byte[] keyFileBytes = getContentOfFile(keyFile);

      checkSourceBytes(keyFileBytes);

      setKeysFromKeyAndSourceBytes(hmacKey, keyFileBytes);

      Arrays.fill(keyFileBytes, (byte) 0);
   }

   /**
    * Encrypt a string under a subject
    *
    * @param stringToEncrypt String to encrypt
    * @param subject         The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws BadPaddingException                if there was a bad padding (must never happen)
    * @throws IllegalArgumentException
    * @throws IllegalBlockSizeException          if the block size is invalid (must never happen)
    * @throws InvalidAlgorithmParameterException if an encryption parameter is invalid (must never happen)
    * @throws InvalidKeyException                if the key is invalid (must never happen)
    * @throws NoSuchAlgorithmException           if the encryption algorithm is invalid (must never happen)
    * @throws NoSuchPaddingException             if the padding algorithm is invalid (must never happen)
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String encryptData(final String stringToEncrypt, final String subject) throws BadPaddingException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      final byte[] subjectBytes = subject.getBytes(STRING_ENCODING_FOR_DATA);

      EncryptionParts encryptionParts = rawDataEncryption(stringToEncrypt, subjectBytes);

      encryptionParts.checksum = getChecksumForEncryptionParts(encryptionParts, subjectBytes);

      String result = makePrintableStringFromEncryptionParts(encryptionParts);

      encryptionParts.zap();

      return result;
   }

   /**
    * Encrypt a string
    *
    * @param stringToEncrypt String to encrypt
    * @return Printable form of the encrypted string
    * @throws BadPaddingException                if there was a bad padding (must never happen)
    * @throws IllegalArgumentException
    * @throws IllegalBlockSizeException          if the block size is invalid (must never happen)
    * @throws InvalidAlgorithmParameterException if an encryption parameter is invalid (must never happen)
    * @throws InvalidKeyException                if the key is invalid (must never happen)
    * @throws NoSuchAlgorithmException           if the encryption algorithm is invalid (must never happen)
    * @throws NoSuchPaddingException             if the padding algorithm is invalid (must never happen)
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String encryptData(final String stringToEncrypt) throws BadPaddingException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      return encryptData(stringToEncrypt, "");
   }

   /**
    * Decrypt an encrypted string
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string
    * @throws BadPaddingException                if there was a bad padding (must never happen)
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws IllegalBlockSizeException          if the block size is invalid (must never happen)
    * @throws InvalidAlgorithmParameterException if an encryption parameter is invalid (must never happen)
    * @throws InvalidKeyException                if the key is invalid (must never happen)
    * @throws IOException
    * @throws NoSuchAlgorithmException           if the encryption algorithm is invalid (must never happen)
    * @throws NoSuchPaddingException             if the padding algorithm is invalid (must never happen)
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String decryptData(final String stringToDecrypt, final String subject) throws BadPaddingException, DataIntegrityException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      final byte[] subjectBytes = subject.getBytes(STRING_ENCODING_FOR_DATA);

      final EncryptionParts encryptionParts = getPartsFromPrintableString(stringToDecrypt);

      checkChecksumForEncryptionParts(encryptionParts, subjectBytes);

      final String result = rawDataDecryption(encryptionParts, subjectBytes);

      encryptionParts.zap();

      return result;
   }

   /**
    * Decrypt an encrypted string
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string
    * @throws BadPaddingException                if there was a bad padding (must never happen)
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws IllegalBlockSizeException          if the block size is invalid (must never happen)
    * @throws InvalidAlgorithmParameterException if an encryption parameter is invalid (must never happen)
    * @throws InvalidKeyException                if the key is invalid (must never happen)
    * @throws IOException
    * @throws NoSuchAlgorithmException           if the encryption algorithm is invalid (must never happen)
    * @throws NoSuchPaddingException             if the padding algorithm is invalid (must never happen)
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String decryptData(final String stringToDecrypt) throws BadPaddingException, DataIntegrityException, IllegalArgumentException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
      return decryptData(stringToDecrypt, "");
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of keys
    * <p>
    * This method is idempotent and never throws an exception.
    * </p>
    */
   @Override
   public void close() {
      this.m_EncryptionKey.close();
      this.m_HMACKey.close();
   }
}
