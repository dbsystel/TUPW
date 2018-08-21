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
package dbsnumberlib;

import static org.junit.Assert.*;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 * Test cases for ByteArrayBlinding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
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

      byte [] p0 = PackedUnsignedInteger.fromInteger(0);
      byte [] p63 = PackedUnsignedInteger.fromInteger(63);
      byte [] p64 = PackedUnsignedInteger.fromInteger(64);
      byte [] p16383 = PackedUnsignedInteger.fromInteger(16447);
      byte [] p16384 = PackedUnsignedInteger.fromInteger(16448);
      byte [] p4194303 = PackedUnsignedInteger.fromInteger(4210687);
      byte [] p4194304 = PackedUnsignedInteger.fromInteger(4210688);
      byte [] p1073741823 = PackedUnsignedInteger.fromInteger(1077936127);
      
      assertEquals("Wrong length of p0", 1, p0.length);
      assertEquals("Wrong length of p63", 1, p63.length);
      assertEquals("Wrong length of p64", 2, p64.length);
      assertEquals("Wrong length of p16383", 2, p16383.length);
      assertEquals("Wrong length of p16384", 3, p16384.length);
      assertEquals("Wrong length of p4194303", 3, p4194303.length);
      assertEquals("Wrong length of p4194304", 4, p4194304.length);
      assertEquals("Wrong length of p1073741823", 4, p1073741823.length);

      int test = PackedUnsignedInteger.toInteger(p0);
      assertEquals("P0 can not be converted to integer", 0, test);

      test = PackedUnsignedInteger.toInteger(p64);
      assertEquals("P64 can not be converted to integer", 64, test);

      test = PackedUnsignedInteger.toInteger(p16383);
      assertEquals("P16383 can not be converted to integer", 16447, test);

      test = PackedUnsignedInteger.toInteger(p16384);
      assertEquals("P16384 can not be converted to integer", 16448, test);

      test = PackedUnsignedInteger.toInteger(p4194303);
      assertEquals("P4194303 can not be converted to integer", 4210687, test);

      test = PackedUnsignedInteger.toInteger(p4194304);
      assertEquals("P4194304 can not be converted to integer", 4210688, test);

      test = PackedUnsignedInteger.toInteger(p1073741823);
      assertEquals("P1073741823 can not be converted to integer", 1077936127, test);

      try {
         byte [] junk = PackedUnsignedInteger.fromInteger(-1);
         
         fail("Exception not thrown on fromInteger = -1");
      }
      catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "java.lang.IllegalArgumentException", e.toString());         
      }

   }

}
