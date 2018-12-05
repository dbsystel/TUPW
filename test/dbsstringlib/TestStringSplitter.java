/*
 * Copyright (c) 2018, DB Systel GmbH
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
 *     2018-12-05: V1.0.0: Created. fhs
 */
package dbsstringlib;

import org.junit.*;

import static org.junit.Assert.*;

/**
 * Test cases for arbitrary tail byte padding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestStringSplitter {

   public TestStringSplitter() {
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
   public void TestNormal() {
      // 1. Normal test
      String result[] = StringSplitter.split("ATestString", "S");

      assertEquals("Split result not of length 2", 2, result.length);

      // 2. 1. element empty
      result = StringSplitter.split("SATestString", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("1. element of split is not empty", 0, result[0].length());

      // 3. Last element empty
      result = StringSplitter.split("ATestStringS", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("Last element of split is not empty", 0, result[2].length());

      // 4. Split empty string with non-empty delimiter
      result = StringSplitter.split("", "/");

      assertEquals("Empty string is not split into array with 0 element", 0, result.length);

      // 5. Split empty string with empty delimiter
      result = StringSplitter.split("", "");

      assertEquals("Empty string is not split into array with 0 element", 0, result.length);

      // 6. Split non-empty string with empty delimiter
      result = StringSplitter.split("AnotherTest", "");

      assertEquals("Non-empty string is not split into array with 1 element", 1, result.length);
      assertNotEquals("Non-empty string is not split into non-empty string", 0, result[0].length());
      assertEquals("Non-empty string is not split into original non-empty string", "AnotherTest", result[0]);
   }

}
