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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category(NoIoTestCase.class)
public class GenericUtilsTest extends JUnitTestSupport {
    public GenericUtilsTest() {
        super();
    }

    @Test
    public void testSplitAndJoin() {
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
            assertEquals("Mismatched split length for separator=" + sep, expected.size(),
                    GenericUtils.length((Object[]) actual));

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
    public void testStripQuotes() {
        String expected = getCurrentTestName();
        assertSame("Unexpected un-quoted stripping", expected, GenericUtils.stripQuotes(expected));

        StringBuilder sb = new StringBuilder(2 + expected.length()).append('|').append(expected).append('|');
        for (int index = 0; index < GenericUtils.QUOTES.length(); index++) {
            char delim = GenericUtils.QUOTES.charAt(index);
            sb.setCharAt(0, delim);
            sb.setCharAt(sb.length() - 1, delim);

            CharSequence actual = GenericUtils.stripQuotes(sb);
            assertEquals("Mismatched result for delim (" + delim + ")", expected, actual.toString());
        }
    }

    @Test
    public void testStripOnlyFirstLayerQuotes() {
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
            assertEquals("Mismatched result for delim (" + topDelim + "/" + innerDelim + ")", expected.toString(),
                    actual.toString());
        }
    }

    @Test
    public void testStripDelimiters() {
        String expected = getCurrentTestName();
        final char delim = '|';
        assertSame("Unexpected un-delimited stripping", expected, GenericUtils.stripDelimiters(expected, delim));

        CharSequence actual = GenericUtils.stripDelimiters(
                new StringBuilder(2 + expected.length()).append(delim).append(expected).append(delim), delim);
        assertEquals("Mismatched stripped values", expected, actual.toString());
    }

    @Test
    public void testStripDelimitersOnlyIfOnBothEnds() {
        final char delim = '$';
        StringBuilder expected = new StringBuilder().append(delim).append(getCurrentTestName()).append(delim);
        for (int index : new int[] { 0, expected.length() - 1 }) {
            // restore original delimiters
            expected.setCharAt(0, delim);
            expected.setCharAt(expected.length() - 1, delim);
            // trash one end
            expected.setCharAt(index, (char) (delim + 1));

            assertSame("Mismatched result for delim at index=" + index, expected,
                    GenericUtils.stripDelimiters(expected, delim));
        }
    }

    @Test
    public void testAccumulateExceptionOnNullValues() {
        assertNull("Unexpected null/null result", GenericUtils.accumulateException(null, null));

        Throwable expected = new NoSuchMethodException(getClass().getName() + "#" + getCurrentTestName());
        assertSame("Mismatched null/extra result", expected, GenericUtils.accumulateException(null, expected));
        assertSame("Mismatched current/null result", expected, GenericUtils.accumulateException(expected, null));
    }

    @Test
    public void testAccumulateExceptionOnExistingCurrent() {
        RuntimeException[] expected = new RuntimeException[] {
                new IllegalArgumentException(getCurrentTestName()),
                new ClassCastException(getClass().getName()),
                new NoSuchElementException(getClass().getPackage().getName())
        };
        RuntimeException current = new UnsupportedOperationException("top");
        for (RuntimeException extra : expected) {
            RuntimeException actual = GenericUtils.accumulateException(current, extra);
            assertSame("Mismatched returned actual exception", current, actual);
        }

        Throwable[] actual = current.getSuppressed();
        assertArrayEquals("Suppressed", expected, actual);
    }

    @Test
    public void testNullOrEmptyCharArrayComparison() {
        char[][] values = new char[][] { null, GenericUtils.EMPTY_CHAR_ARRAY };
        for (char[] c1 : values) {
            for (char[] c2 : values) {
                assertEquals(((c1 == null) ? "null" : "empty") + " vs. " + ((c2 == null) ? "null" : "empty"), 0,
                        GenericUtils.compare(c1, c2));
            }
        }
    }

    @Test
    public void testCharArrayComparison() {
        String s1 = getClass().getSimpleName();
        char[] c1 = s1.toCharArray();
        assertEquals("Same value equality", 0, GenericUtils.compare(c1, s1.toCharArray()));

        String s2 = getCurrentTestName();
        char[] c2 = s2.toCharArray();
        assertEquals("s1 vs. s2", Integer.signum(s1.compareTo(s2)), Integer.signum(GenericUtils.compare(c1, c2)));
        assertEquals("s2 vs. s1", Integer.signum(s2.compareTo(s1)), Integer.signum(GenericUtils.compare(c2, c1)));
    }
}
