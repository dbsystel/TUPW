/*
 * Copyright (c) 2019, DB Systel GmbH
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
 *     2019-03-06: V1.1.0: Added missing tests and renamed constants and variables for better readability. fhs
 *     2019-03-06: V1.2.0: Added tests for "toString" method. fhs
 */
package dbsnumberlib;

import org.junit.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


/**
 * Test cases for Packed Unsigned Integer
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.1.0
 */
public class TestPackedUnsignedInteger {

   /*
    * Private constants
    */
   public TestPackedUnsignedInteger() {
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
   public void TestPackedNumber() {
      final int iMin1Byte = 0;
      final int iMax1Byte = 63;
      final int iMin2Bytes = iMax1Byte + 1;
      final int iMax2Bytes = 16447;
      final int iMin3Bytes = iMax2Bytes + 1;
      final int iMax3Bytes = 4210687;
      final int iMin4Bytes = iMax3Bytes + 1;
      final int iMax4Bytes = 1077936127;
      final int iMinOverflow = iMax4Bytes + 1;

      final byte [] piMin1Byte = PackedUnsignedInteger.fromInteger(iMin1Byte);
      final byte [] piMax1Byte = PackedUnsignedInteger.fromInteger(iMax1Byte);
      final byte [] piMin2Bytes = PackedUnsignedInteger.fromInteger(iMin2Bytes);
      final byte [] piMax2Bytes = PackedUnsignedInteger.fromInteger(iMax2Bytes);
      final byte [] piMin3Bytes = PackedUnsignedInteger.fromInteger(iMin3Bytes);
      final byte [] piMax3Bytes = PackedUnsignedInteger.fromInteger(iMax3Bytes);
      final byte [] piMin4Bytes = PackedUnsignedInteger.fromInteger(iMin4Bytes);
      final byte [] piMax4Bytes = PackedUnsignedInteger.fromInteger(iMax4Bytes);
      
      assertEquals("Wrong length of piMin1Byte", 1, piMin1Byte.length);
      assertEquals("Wrong length of piMax1Byte", 1, piMax1Byte.length);
      assertEquals("Wrong length of piMin2Bytes", 2, piMin2Bytes.length);
      assertEquals("Wrong length of piMax2Bytes", 2, piMax2Bytes.length);
      assertEquals("Wrong length of piMin3Bytes", 3, piMin3Bytes.length);
      assertEquals("Wrong length of piMax3Bytes", 3, piMax3Bytes.length);
      assertEquals("Wrong length of piMin4Bytes", 4, piMin4Bytes.length);
      assertEquals("Wrong length of piMax4Bytes", 4, piMax4Bytes.length);

      int test = PackedUnsignedInteger.toInteger(piMin1Byte);
      assertEquals("piMin1Byte is not correctly converted to an integer", iMin1Byte, test);

      test = PackedUnsignedInteger.toInteger(piMax1Byte);
      assertEquals("piMax1Byte is not correctly converted to an integer", iMax1Byte, test);

      test = PackedUnsignedInteger.toInteger(piMin2Bytes);
      assertEquals("piMin2Bytes is not correctly converted to an integer", iMin2Bytes, test);

      test = PackedUnsignedInteger.toInteger(piMax2Bytes);
      assertEquals("piMax2Bytes is not correctly converted to an integer", iMax2Bytes, test);

      test = PackedUnsignedInteger.toInteger(piMin3Bytes);
      assertEquals("piMin3Bytes is not correctly converted to an integer", iMin3Bytes, test);

      test = PackedUnsignedInteger.toInteger(piMax3Bytes);
      assertEquals("piMax3Bytes is not correctly converted to an integer", iMax3Bytes, test);

      test = PackedUnsignedInteger.toInteger(piMin4Bytes);
      assertEquals("piMin4Bytes is not correctly converted to an integer", iMin4Bytes, test);

      test = PackedUnsignedInteger.toInteger(piMax4Bytes);
      assertEquals("piMax4Bytes is not correctly converted to an integer", iMax4Bytes, test);

      try {
         byte [] junk = PackedUnsignedInteger.fromInteger(-1);

         fail("Exception not thrown on fromInteger = -1");
      }
      catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "java.lang.IllegalArgumentException: Integer must not be negative", e.toString());
      }

      try {
         byte [] junk = PackedUnsignedInteger.fromInteger(iMinOverflow);

         fail("Exception not thrown on fromInteger = " + iMinOverflow);
      }
      catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "java.lang.IllegalArgumentException: Integer too large for packed integer", e.toString());
      }

      assertEquals("String representation of piMin1Byte is not correct",
              PackedUnsignedInteger.toString(piMin1Byte),
              Integer.toString(iMin1Byte));

      assertEquals("String representation of piMax4Bytes is not correct",
              PackedUnsignedInteger.toString(piMax4Bytes),
              Integer.toString(iMax4Bytes));
   }
}
