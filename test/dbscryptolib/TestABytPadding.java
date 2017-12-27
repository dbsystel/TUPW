/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package dbscryptolib;

import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author frankschwab
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
      assertTrue("Padding length is not multiple of block size: " + Integer.toString(paddedSourceData.length), (paddedSourceData.length % BLOCK_SIZE) == 0);
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
      assertTrue("Padding length is not multiple of block size: " + Integer.toString(paddedSourceData.length), (paddedSourceData.length % BLOCK_SIZE) == 0);
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
      assertTrue("Padding length is not multiple of block size: " + Integer.toString(paddedSourceData.length), (paddedSourceData.length % BLOCK_SIZE) == 0);
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
      assertTrue("Padding length is not multiple of block size: " + Integer.toString(paddedSourceData.length), (paddedSourceData.length % BLOCK_SIZE) == 0);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);
      
      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);
      
      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }
}
