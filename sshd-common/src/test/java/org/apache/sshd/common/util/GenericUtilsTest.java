/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
@SuppressWarnings("checksyle:MethodCount")
public class GenericUtilsTest extends JUnitTestSupport {

    @Test
    void isBlank() {
        assertTrue(GenericUtils.isBlank(null));
        assertTrue(GenericUtils.isBlank(""));
        assertTrue(GenericUtils.isBlank(" "));
        assertFalse(GenericUtils.isBlank("a"));
        assertFalse(GenericUtils.isBlank(" a "));
    }

    @Test
    void filterToNotBlank() {
        assertEquals(Collections.emptyList(), GenericUtils.filterToNotBlank(Arrays.asList((String) null)));
        assertEquals(Collections.emptyList(), GenericUtils.filterToNotBlank(Arrays.asList("")));
        assertEquals(Collections.emptyList(), GenericUtils.filterToNotBlank(Arrays.asList(" ")));
        assertEquals(Arrays.asList("a"), GenericUtils.filterToNotBlank(Arrays.asList("a")));
        assertEquals(Arrays.asList("a", "b"), GenericUtils.filterToNotBlank(Arrays.asList("a", "b")));
        assertEquals(Arrays.asList("a"), GenericUtils.filterToNotBlank(Arrays.asList("a", "")));
        assertEquals(Arrays.asList("a"), GenericUtils.filterToNotBlank(Arrays.asList("a", " ")));
        assertEquals(Arrays.asList("a"), GenericUtils.filterToNotBlank(Arrays.asList("a", "  ")));
        assertEquals(Arrays.asList("a"), GenericUtils.filterToNotBlank(Arrays.asList("a", null)));
        assertEquals(Arrays.asList("a", "b"), GenericUtils.filterToNotBlank(Arrays.asList("a", null, "b")));
        assertEquals(Arrays.asList("a", "b"), GenericUtils.filterToNotBlank(Arrays.asList("a", "", "b")));
        assertEquals(Arrays.asList("a", "b"), GenericUtils.filterToNotBlank(Arrays.asList("a", " ", "b")));
        assertEquals(Arrays.asList("a", "b"), GenericUtils.filterToNotBlank(Arrays.asList("a", "  ", "b")));
    }

    @Test
    void splitAndJoin() {
        List<String> expected = Collections.unmodifiableList(
                Arrays.asList(
                        getClass().getPackage().getName().replace('.', '/'),
                        getClass().getSimpleName(),
                        getCurrentTestName()));

        // NOTE: we also test characters that have meaning in String.split(...) as regex ones
        for (char ch : new char[] { ',', '.', '*', '?' }) {
            String sep = String.valueOf(ch);
            String s = GenericUtils.join(expected, sep);
            String[] actual = GenericUtils.split(s, ch);
            assertEquals(expected.size(),
                    GenericUtils.length((Object[]) actual),
                    "Mismatched split length for separator=" + sep);

            for (int index = 0; index < actual.length; index++) {
                String e = expected.get(index);
                String a = actual[index];
                if (!e.endsWith(a)) {
                    fail("Mismatched value at index=" + index + " for separator=" + sep + ": expected=" + e + ", actual=" + a);
                }
            }
        }
    }

    @Test
    void stripQuotes() {
        String expected = getCurrentTestName();
        assertSame(expected, GenericUtils.stripQuotes(expected), "Unexpected un-quoted stripping");

        StringBuilder sb = new StringBuilder(2 + expected.length()).append('|').append(expected).append('|');
        for (int index = 0; index < GenericUtils.QUOTES.length(); index++) {
            char delim = GenericUtils.QUOTES.charAt(index);
            sb.setCharAt(0, delim);
            sb.setCharAt(sb.length() - 1, delim);

            CharSequence actual = GenericUtils.stripQuotes(sb);
            assertEquals(expected, actual.toString(), "Mismatched result for delim (" + delim + ")");
        }
    }

    @Test
    void stripOnlyFirstLayerQuotes() {
        StringBuilder sb = new StringBuilder().append("||").append(getCurrentTestName()).append("||");
        char[] delims = { '\'', '"', '"', '\'' };
        for (int index = 0; index < delims.length; index += 2) {
            char topDelim = delims[index];
            char innerDelim = delims[index + 1];
            sb.setCharAt(0, topDelim);
            sb.setCharAt(1, innerDelim);
            sb.setCharAt(sb.length() - 2, innerDelim);
            sb.setCharAt(sb.length() - 1, topDelim);

            CharSequence expected = sb.subSequence(1, sb.length() - 1);
            CharSequence actual = GenericUtils.stripQuotes(sb);
            assertEquals(expected.toString(),
                    actual.toString(),
                    "Mismatched result for delim (" + topDelim + "/" + innerDelim + ")");
        }
    }

    @Test
    void stripDelimiters() {
        String expected = getCurrentTestName();
        final char delim = '|';
        assertSame(expected, GenericUtils.stripDelimiters(expected, delim), "Unexpected un-delimited stripping");

        CharSequence actual = GenericUtils.stripDelimiters(
                new StringBuilder(2 + expected.length()).append(delim).append(expected).append(delim), delim);
        assertEquals(expected, actual.toString(), "Mismatched stripped values");
    }

    @Test
    void stripDelimitersOnlyIfOnBothEnds() {
        final char delim = '$';
        StringBuilder expected = new StringBuilder().append(delim).append(getCurrentTestName()).append(delim);
        for (int index : new int[] { 0, expected.length() - 1 }) {
            // restore original delimiters
            expected.setCharAt(0, delim);
            expected.setCharAt(expected.length() - 1, delim);
            // trash one end
            expected.setCharAt(index, (char) (delim + 1));

            assertSame(expected,
                    GenericUtils.stripDelimiters(expected, delim),
                    "Mismatched result for delim at index=" + index);
        }
    }

    @Test
    void accumulateExceptionOnNullValues() {
        assertNull(ExceptionUtils.accumulateException(null, null), "Unexpected null/null result");

        Throwable expected = new NoSuchMethodException(getClass().getName() + "#" + getCurrentTestName());
        assertSame(expected, ExceptionUtils.accumulateException(null, expected), "Mismatched null/extra result");
        assertSame(expected, ExceptionUtils.accumulateException(expected, null), "Mismatched current/null result");
    }

    @Test
    void accumulateExceptionOnExistingCurrent() {
        RuntimeException[] expected = new RuntimeException[] {
                new IllegalArgumentException(getCurrentTestName()),
                new ClassCastException(getClass().getName()),
                new NoSuchElementException(getClass().getPackage().getName())
        };
        RuntimeException current = new UnsupportedOperationException("top");
        for (RuntimeException extra : expected) {
            RuntimeException actual = ExceptionUtils.accumulateException(current, extra);
            assertSame(current, actual, "Mismatched returned actual exception");
        }

        Throwable[] actual = current.getSuppressed();
        assertArrayEquals(expected, actual, "Suppressed");
    }

    @Test
    void nullOrEmptyCharArrayComparison() {
        char[][] values = new char[][] { null, GenericUtils.EMPTY_CHAR_ARRAY };
        for (char[] c1 : values) {
            for (char[] c2 : values) {
                assertEquals(0,
                        GenericUtils.compare(c1, c2),
                        ((c1 == null) ? "null" : "empty") + " vs. " + ((c2 == null) ? "null" : "empty"));
            }
        }
    }

    @Test
    void charArrayComparison() {
        String s1 = getClass().getSimpleName();
        char[] c1 = s1.toCharArray();
        assertEquals(0, GenericUtils.compare(c1, s1.toCharArray()), "Same value equality");

        String s2 = getCurrentTestName();
        char[] c2 = s2.toCharArray();
        assertEquals(Integer.signum(s1.compareTo(s2)), Integer.signum(GenericUtils.compare(c1, c2)), "s1 vs. s2");
        assertEquals(Integer.signum(s2.compareTo(s1)), Integer.signum(GenericUtils.compare(c2, c1)), "s2 vs. s1");
    }
}
