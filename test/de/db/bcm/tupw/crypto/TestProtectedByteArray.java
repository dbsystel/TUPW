/*
 * Copyright (c) 2020, DB Systel GmbH
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2020-03-11: V1.0.0: Created. fhs
 *     2020-04-29: V1.0.1: Removed unnecessary constants. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test cases for SecureSecretKeySpec
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.1
 */
public class TestProtectedByteArray {

   /*
    * Private constants
    */
   static final byte FILL_VALUE = (byte) 0x55;

   static final String EXPECTED_EXCEPTION = "Expected exception not thrown";

   public TestProtectedByteArray() {
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
   public void TestNullArgument() {
      try {
         ProtectedByteArray pba = new ProtectedByteArray(null);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
         assertEquals("Exception: " + e.toString(), "Array to protect is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEmptyArgument() {
      ProtectedByteArray pba = new ProtectedByteArray(new byte[0]);

      byte[] result = pba.getData();

      assertEquals("Empty byte array is retrieved with wrong length", 0, result.length);
   }

   @Test
   public void TestBase() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ProtectedByteArray pba = new ProtectedByteArray(ba);

      assertArrayEquals("Data was not correctly retrieved", ba, pba.getData());
      assertEquals("Retrieved data has different length from stored data", ba.length, pba.length());
   }

   @Test
   public void TestClose() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ProtectedByteArray pba = new ProtectedByteArray(ba);

      pba.close();
      assertFalse("ProtectedByteArray still valid after close", pba.isValid());

      try {
         pba.getData();

         fail(EXPECTED_EXCEPTION);
      }
      catch (IllegalStateException e) {
         final String message = e.getMessage();

         assertEquals("IllegalStateException with wrong message: " + message, "ProtectedByteArray has already been destroyed", message);
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEquals() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      final ProtectedByteArray pba1 = new ProtectedByteArray(ba);
      final ProtectedByteArray pba2 = new ProtectedByteArray(ba);

      assertEquals("ProtectedByteArray are not equal when they should be", pba1, pba2);
      assertEquals("ProtectedByteArray do not have identical hash codes", pba1.hashCode(), pba2.hashCode());

      final ProtectedByteArray pba3 = new ProtectedByteArray(new byte[32]);
      assertNotEquals("ProtectedByteArray are equal when they should not be (different keys)", pba1, pba3);
   }
}
