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
@Category({ NoIoTestCase.class })
public class NumberUtilsTest extends JUnitTestSupport {
    public NumberUtilsTest() {
        super();
    }

    @Test
    public void testIntNextPowerOf2() {
        int expected = 1;
        for (int index = 0; index < Integer.SIZE; expected <<= 1, index++) {
            if (expected > 2) {
                assertEquals("Mismatched lower bound value", expected, NumberUtils.getNextPowerOf2(expected - 1));
            }

            if (expected > 0) { // avoid the negative value
                assertEquals("Mismatched exact value", expected, NumberUtils.getNextPowerOf2(expected));
            }
        }
    }

    @Test
    public void testIntNextPowerOf2Overflow() {
        int expected = Integer.MAX_VALUE - Byte.SIZE;
        int actual = NumberUtils.getNextPowerOf2(expected);
        assertEquals(expected, actual);
    }

    @Test
    public void testToInteger() {
        assertNull("Unexpected null value", NumberUtils.toInteger(null));
        for (Number n : new Number[] {
                Byte.valueOf(Byte.MAX_VALUE), Short.valueOf(Short.MIN_VALUE),
                Integer.valueOf(Short.MAX_VALUE), Long.valueOf(82007160L) }) {
            Integer i = NumberUtils.toInteger(n);
            if (n instanceof Integer) {
                assertSame("Unexpected conversion", n, i);
            } else {
                assertEquals("Mismatched values", n.intValue(), i.intValue());
            }
        }
    }

    @Test
    public void testIsValidIntegerNumber() {
        for (String s : new String[] { "7", "73", "736", "7365", "19650307" }) {
            assertTrue(s, NumberUtils.isIntegerNumber(s));

            String pos = "+" + s;
            assertTrue(pos, NumberUtils.isIntegerNumber(pos));

            String neg = "-" + s;
            assertTrue(neg, NumberUtils.isIntegerNumber(neg));
        }
    }

    @Test
    public void testIsInvalidIntegerNumber() {
        for (String s : new String[] { null, "", "    ", getCurrentTestName(), "3rd", "3.14", "-.3" }) {
            assertFalse(s, NumberUtils.isIntegerNumber(s));
        }
    }
}
