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

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class NumberUtilsTest extends BaseTestSupport {
    public NumberUtilsTest() {
        super();
    }

    @Test
    public void testPowersOf2List() {
        assertEquals("Mismatched values size for " + NumberUtils.POWERS_OF_TWO, Long.SIZE, GenericUtils.size(NumberUtils.POWERS_OF_TWO));
        long expected = 1L;
        for (int index = 0; index < Long.SIZE; index++, expected <<= 1) {
            Long actual = NumberUtils.POWERS_OF_TWO.get(index);
            assertEquals("Mismatched value at index=" + index, Long.toHexString(expected), Long.toHexString(actual.longValue()));
        }
    }

    @Test
    public void testNextPowerOf2() {
        for (Long v : NumberUtils.POWERS_OF_TWO) {
            long expected = v.longValue();
            if (expected > 2L) {
                assertEquals("Mismatched lower bound value", expected, NumberUtils.getNextPowerOf2(expected - 1L));
            }

            if (expected > 0L) {    // avoid the negative value
                assertEquals("Mismatched exact value", expected, NumberUtils.getNextPowerOf2(expected));
            }
        }
    }

    @Test
    public void testToInteger() {
        assertNull("Unexpected null value", NumberUtils.toInteger(null));
        for (Number n : new Number[]{
                Byte.valueOf(Byte.MAX_VALUE), Short.valueOf(Short.MIN_VALUE),
                Integer.valueOf(Short.MAX_VALUE), Long.valueOf(82007160L)}) {
            Integer i = NumberUtils.toInteger(n);
            if (n instanceof Integer) {
                assertSame("Unexpected conversion", n, i);
            } else {
                assertEquals("Mismatched values", n.intValue(), i.intValue());
            }
        }
    }
}
