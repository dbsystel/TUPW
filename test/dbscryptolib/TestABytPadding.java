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
 *     2015-12-20: V1.0.0: Created. fhs
 */
package dbscryptolib;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Test cases for arbitrary tail byte padding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestABytPadding {
   
   /*
    * Private constants
    */
   
   /**
    * Assumed padding block size
    */
   private static final int BLOCK_SIZE = 32;
   
   public TestABytPadding() {
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
   public void TestABytPaddingWorking0DataSize() {
      byte[] unpaddedSourceData = new byte[0];
      
      byte[] paddedSourceData = ArbitraryTailPadding.addPadding(unpaddedSourceData, BLOCK_SIZE);

      assertTrue("Padded data not longer than unpadded data", paddedSourceData.length > unpaddedSourceData.length);
      assertTrue("Padding length is not multiple of block size: " + paddedSourceData.length, (paddedSourceData.length % BLOCK_SIZE) == 0);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);
      
      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);
      
      
      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingSmallerThanBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE / 4 - 1];
      
      byte[] paddedSourceData = ArbitraryTailPadding.addPadding(unpaddedSourceData, BLOCK_SIZE);

      assertTrue("Padded data not longer than unpadded data", paddedSourceData.length > unpaddedSourceData.length);
      assertTrue("Padding length is not multiple of block size: " + paddedSourceData.length, (paddedSourceData.length % BLOCK_SIZE) == 0);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);
      
      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);
      
      
      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingEqualBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE];
      
      byte[] paddedSourceData = ArbitraryTailPadding.addPadding(unpaddedSourceData, BLOCK_SIZE);

      assertTrue("Padded data not longer than unpadded data", paddedSourceData.length > unpaddedSourceData.length);
      assertTrue("Padding length is not multiple of block size: " + paddedSourceData.length, (paddedSourceData.length % BLOCK_SIZE) == 0);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);
      
      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);
      
      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingGreaterThanBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE + (BLOCK_SIZE / 2) + 1];
      
      byte[] paddedSourceData = ArbitraryTailPadding.addPadding(unpaddedSourceData, BLOCK_SIZE);

      assertTrue("Padded data not longer than unpadded data", paddedSourceData.length > unpaddedSourceData.length);
      assertTrue("Padding length is not multiple of block size: " + paddedSourceData.length, (paddedSourceData.length % BLOCK_SIZE) == 0);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);
      
      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);
      
      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }
}
