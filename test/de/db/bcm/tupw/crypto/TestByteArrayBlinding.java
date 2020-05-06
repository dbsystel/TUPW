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
 *     2018-08-16: V1.0.0: Created. fhs
 *     2020-04-27: V1.0.1: Corrected some typos. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Test cases for ByteArrayBlinding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.1
 */
public class TestByteArrayBlinding {

   /*
    * Private constants
    */
   public TestByteArrayBlinding() {
   }

   @BeforeClass
   public static void setUpClass() {
   }

   @AfterClass
   public static void tearDownClass() {
   }

   @Before
   public void setUp() {
   }

   @After
   public void tearDown() {
   }

   @Test
   public void TestBlinding() {
      Random rng = new Random();

      byte[] data0 = new byte[0];
      rng.nextBytes(data0);

      byte[] blindedData = ByteArrayBlinding.buildBlindedByteArray(data0, 17);
      byte[] unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data0.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data0.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data0, unblindedData);

      byte[] data1 = new byte[1];
      rng.nextBytes(data1);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data1, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data1.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data1.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data1, unblindedData);

      byte[] data2 = new byte[16];
      rng.nextBytes(data2);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data2, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data2.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data2.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data2, unblindedData);

      byte[] data3 = new byte[20];
      rng.nextBytes(data3);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data3, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data3.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data3.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data3, unblindedData);

      byte[] data4 = new byte[18000];
      rng.nextBytes(data4);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data4, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data4.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data4.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data4, unblindedData);
   }

   @Test
   public void TestBlindingLoop() {
      SecureRandom rng = SecureRandomFactory.getSensibleInstance();

      byte[] blindedData;
      byte[] unblindedData;

      int minimumLength;

      for (int dataSize = 1; dataSize <= 50; dataSize++) {
         byte[] data1 = new byte[dataSize];
         rng.nextBytes(data1);

         for (int i = 0; i < 256; i++) {
            minimumLength = rng.nextInt(65);

            blindedData = ByteArrayBlinding.buildBlindedByteArray(data1, minimumLength);
            unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);
            assertArrayEquals("Data is not the same after blinding and unblinding", data1, unblindedData);
         }
      }
   }
}
