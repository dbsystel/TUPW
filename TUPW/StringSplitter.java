/*
 * Copyright (c) 2017, DB Systel GmbH
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes: 
 *     2017-04-10: V1.0.0: Created. fhs
 *     2017-06-01: V1.0.1: Create empty String array just once. fhs
 */
package TUPW;

import java.util.ArrayList;

/**
 * Class to split a string at specified separator
 * 
 * This class is a modified version of Apache Commons
 * StringUtil.splitByWholeSeparatorWorker.
 *
 * I wrote it because I absolutely do not like inefficiency in programming and I
 * do not want to load a full RegEx machinery just to split a string at a simple
 * character like Java's String.split method does.
 * 
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.1
 */
public class StringSplitter {

    /**
     * Splits the provided string into an array of strings with {@code separator} 
     * separating the parts.
     * 
     * If {@code separator} is not found in the {@code searchString} an array
     * with one element that contains the whole {@code searchString} is returned.
     *
     * @param searchString The String to parse, may be {@code null}
     * @param separator String containing the String to be used as a separator
     * @return An array of parsed Strings, {@code null} if null String input
     */
    public static String[] split(
            final String searchString, final String separator) {
        if (searchString == null) {
            return null;
        }

        final int searchStringLength = searchString.length();

        final String[] emptyStringArray = new String[0];
        
        if (searchStringLength == 0) {
            return emptyStringArray;
        }

        final int separatorLength = separator.length();

        final ArrayList<String> substrings = new ArrayList<>();

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
                    // We found a consecutive occurrence of the separator, so skip it.
                    startSearchIndex = separatorIndex + separatorLength;
                }
            } else {
                // String.substring( startSearchIndex ) goes from 'startSearchIndex' to the end of the String.
                substrings.add(searchString.substring(startSearchIndex));
                separatorIndex = searchStringLength;
            }
        }

        // toArray needs a type model which should be empty as it is never used for anything else than casting
        return substrings.toArray(emptyStringArray);
    }
}
