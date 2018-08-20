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
 */
package dbscryptolib;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.util.Random;

/**
 * Test cases for ByteArrayBlinding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
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
   public void TestBlinding() throws IOException {
      Random rng = new Random();

      byte[] data = new byte[1];
      rng.nextBytes(data);

      byte[] blindedData = ByteArrayBlinding.buildBlindedByteArray(data, 17);
      byte[] unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data.length, unblindedData.length);
      assertArrayEquals("Data ist not the same after blinding and unblinding", data, unblindedData);

      byte[] data2 = new byte[16];
      rng.nextBytes(data2);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data2, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data2.length, unblindedData.length);
      assertArrayEquals("Data ist not the same after blinding and unblinding", data2, unblindedData);

      byte[] data3 = new byte[20];
      rng.nextBytes(data3);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data3, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data3.length, unblindedData.length);
      assertArrayEquals("Data ist not the same after blinding and unblinding", data3, unblindedData);

      byte[] data4 = new byte[18000];
      rng.nextBytes(data4);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data4, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data4.length, unblindedData.length);
      assertArrayEquals("Data ist not the same after blinding and unblinding", data4, unblindedData);
   }

}
