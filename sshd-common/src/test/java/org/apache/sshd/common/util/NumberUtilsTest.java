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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class NumberUtilsTest extends JUnitTestSupport {
    public NumberUtilsTest() {
        super();
    }

    @Test
    void intNextPowerOf2() {
        int expected = 1;
        for (int index = 0; index < Integer.SIZE; expected <<= 1, index++) {
            if (expected > 2) {
                assertEquals(expected, NumberUtils.getNextPowerOf2(expected - 1), "Mismatched lower bound value");
            }

            if (expected > 0) { // avoid the negative value
                assertEquals(expected, NumberUtils.getNextPowerOf2(expected), "Mismatched exact value");
            }
        }
    }

    @Test
    void intNextPowerOf2Overflow() {
        int expected = Integer.MAX_VALUE - Byte.SIZE;
        int actual = NumberUtils.getNextPowerOf2(expected);
        assertEquals(expected, actual);
    }

    @Test
    void toInteger() {
        assertNull(NumberUtils.toInteger(null), "Unexpected null value");
        for (Number n : new Number[] {
                Byte.valueOf(Byte.MAX_VALUE), Short.valueOf(Short.MIN_VALUE),
                Integer.valueOf(Short.MAX_VALUE), Long.valueOf(82007160L) }) {
            Integer i = NumberUtils.toInteger(n);
            if (n instanceof Integer) {
                assertSame(n, i, "Unexpected conversion");
            } else {
                assertEquals(n.intValue(), i.intValue(), "Mismatched values");
            }
        }
    }

    @Test
    void isValidIntegerNumber() {
        for (String s : new String[] { "7", "73", "736", "7365", "19650307" }) {
            assertTrue(NumberUtils.isIntegerNumber(s), s);

            String pos = "+" + s;
            assertTrue(NumberUtils.isIntegerNumber(pos), pos);

            String neg = "-" + s;
            assertTrue(NumberUtils.isIntegerNumber(neg), neg);
        }
    }

    @Test
    void isInvalidIntegerNumber() {
        for (String s : new String[] { null, "", "    ", getCurrentTestName(), "3rd", "3.14", "-.3" }) {
            assertFalse(NumberUtils.isIntegerNumber(s), s);
        }
    }
}
