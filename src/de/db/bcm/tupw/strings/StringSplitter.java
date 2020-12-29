/*
 * Copyright (c) 2020, DB Systel GmbH
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Original work copyright (c) Apache Software Foundation, licensed under the Apache License, Version 2.0.
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
 *     2017-04-10: V1.0.0: Created. fhs
 *     2017-06-01: V1.0.1: Create empty String array just once. fhs
 *     2018-12-05: V2.0.0: Fixed bugs handling case where separator
 *                         is at the beginning of the search string.
 *                         Clarified handling. fhs
 *     2018-12-06: V2.1.0: Refactored class. fhs
 *     2020-03-16: V2.1.1: Added some finals. fhs
 *     2020-03-23: V2.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V2.2.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V2.3.0: Make thread safe. fhs
 */
package de.db.bcm.tupw.strings;

import java.util.ArrayList;

/**
 * Class to split a string at specified separator
 *
 * <p>This class is a modified version of the Apache Commons {@code StringUtil.splitByWholeSeparatorWorker}
 * to be found in the package {@code org.apache.commons.lang3} in the file {@code StringUtils.java}.</p>
 *
 * <p>I wrote it because I absolutely do not like inefficiency in programming and I
 * do not want to load a full RegEx machinery, like Java's String.split method does,
 * just to split a string at a simple character.</p>
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 2.3.0
 */
public class StringSplitter {
   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private StringSplitter() {
      throw new IllegalStateException("Utility class");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Splits the provided string into an array of strings with {@code separator}
    * separating the parts.
    *
    * <p>
    * This implementation treats consecutive occurrences of the separator as one separator.
    * <ul>
    * <li>If {@code separator} is not found in the {@code searchString} an array
    * with one element that contains the whole {@code searchString} is returned.</li>
    * <li>A {@code null} {@code searchString} returns {@code null}</li>
    * <li>A {@code null} or empty {@code separator} returns an array with one element
    * that contains the whole {@code searchString}</li>
    * </ul>
    * </p>
    *
    * @param searchString The String to parse, may be {@code null}
    * @param separator    The String to be used as a separator
    * @return An array of parsed Strings, {@code null} if {@code searchString} is {@code null}
    */
   public static synchronized String[] split(final String searchString, final String separator) {
      if (searchString == null)
         return null;

      final ArrayList<String> substrings = new ArrayList<>();

      final int searchStringLength = searchString.length();

      if (searchStringLength == 0)
         substrings.add(searchString);  // Just return the search string if it is empty
      else if (separator == null)
         substrings.add(searchString);  // Just return the search string if the separator is null
      else {
         final int separatorLength = separator.length();

         if (separatorLength == 0)
            substrings.add(searchString);  // Just return the search string if the separator is empty
         else
            splitIntoSubstrings(searchString, separator, substrings, searchStringLength, separatorLength);  // Now do the real work
      }

      // toArray needs a type model which should be empty as it is never used for anything else but casting
      return substrings.toArray(new String[0]);
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Do the real work of splitting a string at the specified separator
    * <p>
    * This implementation treats consecutive occurrences of the separator as one separator
    * </p>
    *
    * @param searchString       String to search for the {@code separator}
    * @param separator          String that specifies the separator where the {@code searchString} should be split
    * @param substrings         Elements of the split {@code searchString}
    * @param searchStringLength Length of the {@code searchString}
    * @param separatorLength    length of the {@code separator}
    */
   private static void splitIntoSubstrings(final String searchString,
                                           final String separator,
                                           final ArrayList<String> substrings,
                                           final int searchStringLength,
                                           final int separatorLength) {
      int startSearchIndex = 0;
      int separatorIndex = 0;

      while (separatorIndex < searchStringLength) {
         separatorIndex = searchString.indexOf(separator, startSearchIndex);

         if (separatorIndex > -1) {
            if (separatorIndex > startSearchIndex) {
               // The following is OK, because String.substring( startSearchIndex, separatorIndex ) strangely
               // and counterintuitively does *not* include the character at position 'separatorIndex'.
               substrings.add(searchString.substring(startSearchIndex, separatorIndex));

               // Set the starting point for the next search.
               // The separatorIndex is the beginning of the separator, so shifting the position
               // by it's size yields the index of the start of the part after the separator.
               startSearchIndex = separatorIndex + separatorLength;
            } else {
               // If the searchString starts with the separator add an empty string.
               if (separatorIndex == 0)
                  substrings.add("");

               // We found a consecutive occurrence of the separator, so skip it.
               startSearchIndex = separatorIndex + separatorLength;
            }
         } else {
            // String.substring( startSearchIndex ) goes from 'startSearchIndex' to the end of the String.
            substrings.add(searchString.substring(startSearchIndex));
            separatorIndex = searchStringLength;
         }
      }
   }
}
