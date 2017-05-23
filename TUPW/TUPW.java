/*
 * Copyright (c) 2017, DB Systel GmbH
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes: 
 *     2017-03-30: V1.0.0: Created. fhs
 *     2017-04-12: V1.0.1: Moved secure random number generator to class constant. fhs
 *     2017-05-23: V1.0.2: Corrected spelling of "aesCipher". fhs
 */
package TUPW;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

import dbscryptolib.SecureSecretKeySpec;

/**
 * Example program to calculate the encryption of user and password for
 * technical users. To be called from the command line.
 *
 * @author Frank Schwab
 * @version 1.0.1
 */
public class TUPW {

    /**
     * Instance of secure random number generator
     * 
     * This is placed here so the expensive instantiation of the SecureRandom
     * class is done only once.
     */
    private static final SecureRandom M_RANDOM = new SecureRandom();

    /**
     * Helper class to store IV and key in one place
     */
    private static class IvAndKey {

        public byte[] iv;
        public byte[] key;

        public void zap() {
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * @param args username and password from the command line
     * @throws java.io.IOException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.BadPaddingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.NoSuchPaddingException
     */
    public static void main(final String[] args) throws IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        if (args.length >= 4) {
            IvAndKey userEncryptionParameters = new IvAndKey();
            IvAndKey passwordEncryptionParameters = new IvAndKey();

            getKeysFromKeyFile(args[1], userEncryptionParameters, passwordEncryptionParameters);

            if (args[0].substring(0, 1).toLowerCase().equals("e")) {
                // Encrypt
                byte[] encryptedUser;
                byte[] encryptedPassword;

                encryptedUser = encryptData(args[2], userEncryptionParameters);
                encryptedPassword = encryptData(args[3], passwordEncryptionParameters);

                printEncryptedData("User", userEncryptionParameters.iv, encryptedUser);
                printEncryptedData("Password", passwordEncryptionParameters.iv, encryptedPassword);
            } else {
                // Decrypt
                byte[] userEncryptedData;
                byte[] passwordEncryptedData;

                userEncryptedData = getEncryptionParametersFromText(args[2], userEncryptionParameters);
                passwordEncryptedData = getEncryptionParametersFromText(args[3], passwordEncryptionParameters);

                String user;
                String password;

                user = decryptData(userEncryptionParameters, userEncryptedData);
                password = decryptData(passwordEncryptionParameters, passwordEncryptedData);

                printDecryptedData("User", user);
                printDecryptedData("Password", password);
            }

            userEncryptionParameters.zap();
            passwordEncryptionParameters.zap();
        } else {
            System.err.println("Not enough arguments");
            System.err.println("Usage:");
            System.err.println("   tupw.jar encrypt {keyfile} {user} {password}");
            System.err.println("   tupw.jar decrypt {keyfile} {encUser} {encPassword}");
        }
    }

    /**
     * Print a key value pair of strings
     * 
     * @param dataName Name of the data
     * @param data     Value of the data
     */
    private static void printDecryptedData(final String dataName, final String data) {
        System.out.print(dataName);
        System.out.print(" = '");
        System.out.print(data);
        System.out.println("'");
    }

    /**
     * Convert an encrypted text into it's parts (i.e. iv and encrypted data)
     * 
     * @param encryptionText       Text produces by encryption
     * @param encryptionParameters Encryption parameters. This methods sets the IV part
     * @return Encrypted data as byte array
     * @throws IllegalArgumentException 
     */
    private static byte[] getEncryptionParametersFromText(final String encryptionText, IvAndKey encryptionParameters) throws IllegalArgumentException {
        String[] parts;
        Base64.Decoder b64Decoder = Base64.getDecoder();

        parts = StringSplitter.split(encryptionText, "$");  // Use my own string splitter to avoid Java's RegEx inefficiency
//        parts = encryptionText.split("\\Q$\\E");   // This should have been just "$". But Java stays true to it's motto: Why make it simple when there's a complicated way to do it?

        if (parts.length == 3) {
            if (parts[0].equals("1")) {
                encryptionParameters.iv = b64Decoder.decode(parts[1]);

                return b64Decoder.decode(parts[2]);
            } else {
                throw new IllegalArgumentException("Format of encrypted text '" + encryptionText + "' is not 1");
            }
        } else {
            throw new IllegalArgumentException("Number of '$' separated parts is not 3 in encrypted text '" + encryptionText + "'");
        }
    }

    /**
     * Decrypt data that have been created by the corresponding encryption
     * 
     * @param encryptionParameters IV and key to be used for decryption
     * @param encryptedData        Encrypted data
     * @return Decrypted data as string
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException 
     */
    private static String decryptData(final IvAndKey encryptionParameters, final byte[] encryptedData) throws BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  // Specifying mode and padding is necessary. Always use CBC and padding!
        String result;

        try (SecureSecretKeySpec aesKey = new SecureSecretKeySpec(encryptionParameters.key, "AES")) {
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(encryptionParameters.iv));

            result = new String(aesCipher.doFinal(encryptedData), "UTF-8"); // Always specify UTF-8 encoding
        }

        return result;
    }

    /**
     * Prints the encrypted data in a legible format (Base64).
     *
     * The output is formatted as fields that are separated by '$' characters:
     * 
     * format: Number denoting the format of the data. 1 = {IV}{AES(128)}
     * iv: IV used to encrypt the data
     * encrpytedData: Encrypted data
     *
     * @param dataName Name of the printed data
     * @param iv Initialization vector
     * @param encryptedData Encrypted data
     */
    private static void printEncryptedData(final String dataName, final byte[] iv, final byte[] encryptedData) {
        Base64.Encoder b64Encoder = Base64.getEncoder();

        System.out.print(dataName);
        System.out.print(" = 1$");
        System.out.print(b64Encoder.encodeToString(iv));
        System.out.print("$");
        System.out.println(b64Encoder.encodeToString(encryptedData));
    }

    /**
     * Encrypt some string data
     *
     * @param stringData Some string that will be encrypted
     * @param encryptionParameters Iv and key for the encryption
     * @return Encrypted data as byte array
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException
     */
    private static byte[] encryptData(final String stringData, IvAndKey encryptionParameters) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  // Specifying mode and padding is necessary. Always use CBC and padding!
        byte[] result;

        // Get a random iv which has the same size as the key
        encryptionParameters.iv = new byte[encryptionParameters.key.length];

        M_RANDOM.nextBytes(encryptionParameters.iv);

        try (SecureSecretKeySpec aesKey = new SecureSecretKeySpec(encryptionParameters.key, "AES")) {
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(encryptionParameters.iv));

            result = aesCipher.doFinal(stringData.getBytes("UTF-8")); // Always specify UTF-8 encoding (Remember that when decrypting!)
        }

        return result;
    }

    /**
     * Get key bytes from key file
     *
     * @param keyFilePath
     * @param userEncryptionParameters
     * @param passwordEncryptionParameters
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static void getKeysFromKeyFile(final String keyFilePath, IvAndKey userEncryptionParameters, IvAndKey passwordEncryptionParameters) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
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

        // Get SHA-256-HMAC of key file
        byte[] hmacOfKeyFile = getHmacSHA256(HMAC_KEY, Files.readAllBytes(Paths.get(keyFilePath)));

        // Split HMAC into two 128 bit keys
        userEncryptionParameters.key = Arrays.copyOfRange(hmacOfKeyFile, 0, 16);
        passwordEncryptionParameters.key = Arrays.copyOfRange(hmacOfKeyFile, 16, 32);

        Arrays.fill(hmacOfKeyFile, (byte) 0);
    }

    /**
     * Get HMAC-SHA-256 of some byte array
     *
     * @param key The key for the HMAC
     * @param data The data to be hashed
     * @return HMAC-SHA-256 value of the specified data with specified key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] getHmacSHA256(final byte[] key, final byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        final String hmacAlgorithm = "HmacSHA256";
        final Mac hmac = Mac.getInstance(hmacAlgorithm);
        byte[] result;

        try (SecureSecretKeySpec hmacKey = new SecureSecretKeySpec(key, hmacAlgorithm)) {
            hmac.init(hmacKey);
            result = hmac.doFinal(data);
        }

        return result;
    }
}
