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
 *     2020-03-19: V1.1.0: Consolidated crypto parameter exceptions. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 */
package dbscryptolib;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implement encryption by key generated from a file and a key
 *
 * <p>This class is just a wrapper for the more general "SplitKeyEncryption" class
 * for the special case of a file as the source for the key input.</p>
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.2.0
 */

public class FileAndKeyEncryption implements AutoCloseable {
   //******************************************************************
   // Instance variables
   //******************************************************************

   private SplitKeyEncryption m_SplitKeyEncryption;


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Constructor for this instance
    *
    * @param hmacKey     Key for the HMAC of the file
    * @param keyFilePath Key file path
    * @throws IllegalArgumentException The HMAC key or the size of the key file are not valid
    * @throws InvalidKeyException      if the key is invalid (must never happen)
    * @throws IOException              if there was an error while reading the key file
    * @throws NoSuchAlgorithmException if the encryption algorithm is invalid (must never happen)
    * @throws NullPointerException     if {@code hmacKey} or {@code keyFilePath} is {@code null}
    */
   public FileAndKeyEncryption(final byte[] hmacKey, final String keyFilePath) throws IllegalArgumentException,
            InvalidKeyException,
            IOException,
            NullPointerException,
            NoSuchAlgorithmException {
      Objects.requireNonNull(hmacKey, "HMAC key is null");
      Objects.requireNonNull(keyFilePath, "Key file path is null");

      Path keyFile;

      try {
         keyFile = Paths.get(keyFilePath);
      } catch (Exception e) {
         throw new IllegalArgumentException("Key file path is invalid: " + e.getMessage());
      }

      final byte[] keyFileBytes = getContentOfFile(keyFile);

      m_SplitKeyEncryption = new SplitKeyEncryption(hmacKey, keyFileBytes);

      Arrays.fill(keyFileBytes, (byte) 0);
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Encrypt a string under a subject
    *
    * @param stringToEncrypt String to encrypt
    * @param subject         The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws IllegalArgumentException
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String encryptData(final String stringToEncrypt, final String subject) throws IllegalArgumentException,
            InvalidCryptoParameterException,
            NullPointerException,
            UnsupportedEncodingException {
      return m_SplitKeyEncryption.encryptData(stringToEncrypt, subject);
   }

   /**
    * Encrypt a string
    *
    * @param stringToEncrypt String to encrypt
    * @return Printable form of the encrypted string
    * @throws IllegalArgumentException
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt}is {@code null}
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String encryptData(final String stringToEncrypt) throws IllegalArgumentException,
            InvalidCryptoParameterException,
            NullPointerException,
            UnsupportedEncodingException {
      return encryptData(stringToEncrypt, "");
   }

   /**
    * Decrypt an encrypted string under a subject
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String decryptData(final String stringToDecrypt, final String subject) throws DataIntegrityException,
            IllegalArgumentException,
            InvalidCryptoParameterException,
            NullPointerException,
            UnsupportedEncodingException {
      return m_SplitKeyEncryption.decryptData(stringToDecrypt, subject);
   }

   /**
    * Decrypt an encrypted string
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt}is {@code null}
    * @throws UnsupportedEncodingException       if there is no UTF-8 encoding (must never happen)
    */
   public String decryptData(final String stringToDecrypt) throws DataIntegrityException,
            IllegalArgumentException,
            InvalidCryptoParameterException,
            NullPointerException,
            UnsupportedEncodingException {
      return decryptData(stringToDecrypt, "");
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of keys
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public void close() {
      this.m_SplitKeyEncryption.close();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Get the content of the key file
    *
    * @param keyFile Key file to be used
    * @throws IllegalArgumentException if key file does not exist
    * @throws IOException              if there is an error reading the key file
    */
   private byte[] getContentOfFile(final Path keyFile) throws IllegalArgumentException, IOException {
      final byte[] result;

      if (Files.exists(keyFile))
         result = Files.readAllBytes(keyFile);
      else
         throw new IllegalArgumentException("File '" + keyFile.toAbsolutePath() + "' does not exist");

      return result;
   }
}
