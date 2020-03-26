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
 *     2020-02-25: V1.0.0: Created. fhs
 */
package de.db.bcm.tupw.numbers;

import org.junit.*;

import java.util.Date;

import static org.junit.Assert.assertNotEquals;


/**
 * Test cases for Pseudo-random numebr generators
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestPRNG {

   /*
    * Class variables
    */
   private static Xoroshiro128plusplus m_Xs128;
   private static SplitMix64 m_Sm64;

   /*
    * Private constants
    */

   private static final int TEST_SIZE = 97;
   private static final int TEST_START = 17;
   private static final int TEST_END = TEST_START + TEST_SIZE - 1;
   private static final int TEST_ITERATIONS = 1000;

   public TestPRNG() {
   }

   @BeforeClass
   public static void setUpClass() {
      final Date now = new Date();
      long timeMilli = now.getTime();

      m_Xs128 = new Xoroshiro128plusplus(timeMilli);

      timeMilli = now.getTime();
      m_Sm64 = new SplitMix64(timeMilli);
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
   public void TestXs128Long() {
      final long[] checkLong = new long[TEST_SIZE];
      long r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextLong(TEST_START, TEST_END);
         checkLong[(int) (r - TEST_START)]++;
      }

      for (int i = 0; i < checkLong.length; i++)
         assertNotEquals("Xs128 Long[" + i + "] is zero", 0, checkLong[i]);
   }

   @Test
   public void TestXs128Int() {
      final int[] checkInt = new int[TEST_SIZE];
      int r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextInt(TEST_START, TEST_END);
         checkInt[r - TEST_START]++;
      }

      for (int i = 0; i < checkInt.length; i++)
         assertNotEquals("Xs128 Int[" + i + "] is zero", 0, checkInt[i]);
   }

   @Test
   public void TestXs128Short() {
      final short[] checkShort = new short[TEST_SIZE];
      short r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextShort((short) TEST_START, (short) TEST_END);
         checkShort[r - TEST_START]++;
      }

      for (int i = 0; i < checkShort.length; i++)
         assertNotEquals("Xs128 Short[" + i + "] is zero", 0, checkShort[i]);
   }

   @Test
   public void TestXs128Byte() {
      final byte[] checkByte = new byte[TEST_SIZE];
      byte r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextByte((byte) TEST_START, (byte) TEST_END);
         checkByte[r - TEST_START]++;
      }

      for (int i = 0; i < checkByte.length; i++)
         assertNotEquals("Xs128 Byte[" + i + "] is zero", 0, checkByte[i]);
   }

   @Test
   public void TestSm64Long() {
      final long[] checkLong = new long[TEST_SIZE];
      long r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextLong(TEST_START, TEST_END);
         checkLong[(int) (r - TEST_START)]++;
      }

      for (int i = 0; i < checkLong.length; i++)
         assertNotEquals("Sm64 Long[" + i + "] is zero", 0, checkLong[i]);
   }

   @Test
   public void TestSm64Int() {
      final int[] checkInt = new int[TEST_SIZE];
      int r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextInt(TEST_START, TEST_END);
         checkInt[r - TEST_START]++;
      }

      for (int i = 0; i < checkInt.length; i++)
         assertNotEquals("Sm64 Int[" + i + "] is zero", 0, checkInt[i]);
   }

   @Test
   public void TestSm64Short() {
      final short[] checkShort = new short[TEST_SIZE];
      short r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextShort((short) TEST_START, (short) TEST_END);
         checkShort[r - TEST_START]++;
      }

      for (int i = 0; i < checkShort.length; i++)
         assertNotEquals("Sm64 Short[" + i + "] is zero", 0, checkShort[i]);
   }

   @Test
   public void TestSm64Byte() {
      final byte[] checkByte = new byte[TEST_SIZE];
      byte r;

      for(int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextByte((byte) TEST_START, (byte) TEST_END);
         checkByte[r - TEST_START]++;
      }

      for (int i = 0; i < checkByte.length; i++)
         assertNotEquals("Sm64 Byte[" + i + "] is zero", 0, checkByte[i]);
   }
}
