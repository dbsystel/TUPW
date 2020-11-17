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
 *     2018-12-05: V1.0.0: Created. fhs
 */
package de.db.bcm.tupw.strings;

import org.junit.*;

import static org.junit.Assert.*;

/**
 * Test cases for string splitter
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
      String[] result = StringSplitter.split("ATestString", "S");

      assertEquals("Split result not of length 2", 2, result.length);
   }

   @Test
   public void TestNullSearchString() {
      String[] result = StringSplitter.split(null, "S");

      assertNull("Null search string yields non-null result", result);
   }

   @Test
   public void TestFirstElementEmpty() {
      String[] result = StringSplitter.split("SATestString", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("1. element of split is not empty", 0, result[0].length());
   }

   @Test
   public void TestLastElementEmpty() {
      String[] result = StringSplitter.split("ATestStringS", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("Last element of split is not empty", 0, result[2].length());
   }

   @Test
   public void TestEmptyStringWithNonEmptyDelimiter() {
      String[] result = StringSplitter.split("", "/");

      assertEquals("Empty string is not split into array with 1 element", 1, result.length);
      assertEquals("Empty string is not split into array with 1 empty element", "", result[0]);
   }

   @Test
   public void TestEmptyStringWithEmptyDelimiter() {
      String[] result = StringSplitter.split("", "");

      assertEquals("Empty string is not split into array with 0 element", 1, result.length);
      assertEquals("Empty string is not split into array with 1 empty element", "", result[0]);
   }

   @Test
   public void TestEmptyStringWithNullDelimiter() {
      String[] result = StringSplitter.split("", null);

      assertEquals("Empty string is not split into array with 1 element", 1, result.length);
      assertEquals("Empty string is not split into array with 1 empty element", "", result[0]);
   }

   @Test
   public void TestNonEmptyStringWithEmptyDelimiter() {
      String[] result = StringSplitter.split("AnotherTest", "");

      assertEquals("Non-empty string is not split into array with 1 element", 1, result.length);
      assertNotEquals("Non-empty string is not split into non-empty string", 0, result[0].length());
      assertEquals("Non-empty string is not split into original non-empty string", "AnotherTest", result[0]);
   }

   @Test
   public void TestNonEmptyStringWithNullDelimiter() {
      String[] result = StringSplitter.split("AnotherTest", null);

      assertEquals("Non-empty string is not split into array with 1 element", 1, result.length);
      assertNotEquals("Non-empty string is not split into non-empty string", 0, result[0].length());
      assertEquals("Non-empty string is not split into original non-empty string", "AnotherTest", result[0]);
   }

}
