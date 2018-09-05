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

import java.util.Random;
import java.util.function.IntUnaryOperator;

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
public class Int2IntFunctionTest extends JUnitTestSupport {
    public Int2IntFunctionTest() {
        super();
    }

    @Test
    public void testAdd() {
        int factor = Byte.SIZE;
        IntUnaryOperator func = Int2IntFunction.add(factor);
        for (int index = 1, sum = 0; index <= Byte.SIZE; index++) {
            sum = func.applyAsInt(sum);
            assertEquals(factor * index, sum);
        }
    }

    @Test
    public void testAddIdentity() {
        IntUnaryOperator func = Int2IntFunction.add(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    public void testSub() {
        int factor = Byte.SIZE;
        IntUnaryOperator func = Int2IntFunction.sub(factor);
        for (int index = 1, sum = 0; index <= Byte.SIZE; index++) {
            sum = func.applyAsInt(sum);
            assertEquals(factor * index * -1, sum);
        }
    }

    @Test
    public void testSubIdentity() {
        IntUnaryOperator func = Int2IntFunction.sub(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    public void testMul() {
        int factor = 2;
        IntUnaryOperator func = Int2IntFunction.mul(factor);
        for (int index = 1, mul = 1, expected = factor; index <= Byte.SIZE; index++, expected *= factor) {
            mul = func.applyAsInt(mul);
            assertEquals(expected, mul);
        }
    }

    @Test
    public void testMulIdentity() {
        IntUnaryOperator func = Int2IntFunction.mul(1);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    public void testMulZero() {
        IntUnaryOperator func = Int2IntFunction.mul(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int value = rnd.nextInt();
            int actual = func.applyAsInt(value);
            assertEquals(Integer.toString(value), 0, actual);
        }
    }

    @Test
    public void testConstant() {
        int expected = 377347;
        IntUnaryOperator func = Int2IntFunction.constant(expected);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int value = rnd.nextInt();
            int actual = func.applyAsInt(value);
            assertEquals(Integer.toString(value), expected, actual);
        }
    }

    @Test
    public void testDiv() {
        int factor = 2;
        IntUnaryOperator func = Int2IntFunction.div(factor);
        for (int index = 1, quot = 65536, expected = quot / factor; index <= Byte.SIZE; index++, expected /= factor) {
            quot = func.applyAsInt(quot);
            assertEquals(expected, quot);
        }
    }

    @Test
    public void testDivIdentity() {
        IntUnaryOperator func = Int2IntFunction.div(1);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDivZeroFactor() {
        IntUnaryOperator func = Int2IntFunction.div(0);
        fail("Unexpected success: " + func);
    }
}
