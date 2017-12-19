/*
 * Copyright (c) 2017, DB Systel GmbH
 * All rights reserved.
 * 
 * Copyright 2017, DB Systel GmbH
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
*                          Refactored interface to encryption and decryption. fhs
 */
package TUPW;

import dbscryptolib.FileAndKeyEncryption;

/**
 * Example program to calculate the encryption of user and password for
 * technical users. To be called from the command line.
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 2.0.0
 */
public class TUPW {

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

      if (args.length >= 4) {
         try (FileAndKeyEncryption MyEncryptor = new FileAndKeyEncryption(HMAC_KEY, args[1])) {
            if (args[0].substring(0, 1).toLowerCase().equals("e")) {
               printData("User", MyEncryptor.encryptData(args[2]));
               printData("Password", MyEncryptor.encryptData(args[3]));
            } else {
               printData("User", MyEncryptor.decryptData(args[2]));
               printData("Password", MyEncryptor.decryptData(args[3]));
            }
         } catch (Exception e) {
            System.err.print(e.toString());
         }
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
    * @param data Value of the data
    */
   private static void printData(final String dataName, final String data) {
      System.out.print(dataName);
      System.out.print(" = '");
      System.out.print(data);
      System.out.println("'");
   }
}
