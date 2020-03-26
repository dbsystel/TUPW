package de.db.bcm.tupw.strings;

import org.junit.*;

import static org.junit.Assert.*;

/**
 * Test cases for arbitrary tail byte padding
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestCharacterArrayHelper {

   public TestCharacterArrayHelper() {
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
   public void TestFromByteToChar() {
      byte[] orriginalByteArray = {116, 115, -61, -92, 84, 32, 97, 32, 115, -61, -84, 32, 115, -61, -83, 104, 84};
      byte[] testByteArray = {116, 115, -61, -92, 84, 32, 97, 32, 115, -61, -84, 32, 115, -61, -83, 104, 84};
      char[] correctCharArray = {'t', 's', 'ä', 'T', ' ', 'a', ' ', 's', 'ì', ' ', 's', 'í', 'h', 'T'};

      try {
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         assertArrayEquals("Original byte array is changed", orriginalByteArray, testByteArray);
         assertArrayEquals("Byte array is not correctly converted", correctCharArray, charArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestFromCharToByte() {
      final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};
      final char[] originalCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};
      final byte[] correctByteArray = {84, 104, -61, -83, 115, 32, -61, -84, 115, 32, 97, 32, 84, -61, -92, 115, 116};

      try {
         final byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(testCharArray);

         assertArrayEquals("Original character array is changed", originalCharArray, originalCharArray);
         assertArrayEquals("Character array is not correctly converted", correctByteArray, byteArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestNullByteArray() {
      try {
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(null);

         assertNull("Null byte array is not correctly converted", charArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestNullCharArray() {
      try {
         byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(null);

         assertNull("Null character array is not correctly converted", byteArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestEmptyByteArray() {
      try {
         byte[] testByteArray = {};
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         assertEquals("Empty byte array is not correctly converted", 0, charArrayResult.length);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestEmptyCharArray() {
      try {
         char[] testCharArray = {};
         byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(testCharArray);

         assertEquals("Empty character array is not correctly converted", 0, byteArrayResult.length);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestInvalidByteArray() {
      byte[] testByteArray = {116, 115, -92, -61, 84, 32, 97, 32, 115, -84, -61, 32, 115, -83, -61, 104, 84};

      try {
         CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String message = e.toString();

         assertTrue("Unexpected exception " + message, message.contains("MalformedInputException"));
      }
   }
}
