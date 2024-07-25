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

import org.apache.sshd.common.util.functors.Int2IntFunction;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class Int2IntFunctionTest extends JUnitTestSupport {
    public Int2IntFunctionTest() {
        super();
    }

    @Test
    void add() {
        int factor = Byte.SIZE;
        IntUnaryOperator func = Int2IntFunction.add(factor);
        for (int index = 1, sum = 0; index <= Byte.SIZE; index++) {
            sum = func.applyAsInt(sum);
            assertEquals(factor * index, sum);
        }
    }

    @Test
    void addIdentity() {
        IntUnaryOperator func = Int2IntFunction.add(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    void sub() {
        int factor = Byte.SIZE;
        IntUnaryOperator func = Int2IntFunction.sub(factor);
        for (int index = 1, sum = 0; index <= Byte.SIZE; index++) {
            sum = func.applyAsInt(sum);
            assertEquals(factor * index * -1, sum);
        }
    }

    @Test
    void subIdentity() {
        IntUnaryOperator func = Int2IntFunction.sub(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    void mul() {
        int factor = 2;
        IntUnaryOperator func = Int2IntFunction.mul(factor);
        for (int index = 1, mul = 1, expected = factor; index <= Byte.SIZE; index++, expected *= factor) {
            mul = func.applyAsInt(mul);
            assertEquals(expected, mul);
        }
    }

    @Test
    void mulIdentity() {
        IntUnaryOperator func = Int2IntFunction.mul(1);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    void mulZero() {
        IntUnaryOperator func = Int2IntFunction.mul(0);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int value = rnd.nextInt();
            int actual = func.applyAsInt(value);
            assertEquals(0, actual, Integer.toString(value));
        }
    }

    @Test
    void constant() {
        int expected = 377347;
        IntUnaryOperator func = Int2IntFunction.constant(expected);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int value = rnd.nextInt();
            int actual = func.applyAsInt(value);
            assertEquals(expected, actual, Integer.toString(value));
        }
    }

    @Test
    void div() {
        int factor = 2;
        IntUnaryOperator func = Int2IntFunction.div(factor);
        for (int index = 1, quot = 65536, expected = quot / factor; index <= Byte.SIZE; index++, expected /= factor) {
            quot = func.applyAsInt(quot);
            assertEquals(expected, quot);
        }
    }

    @Test
    void divIdentity() {
        IntUnaryOperator func = Int2IntFunction.div(1);
        Random rnd = new Random(System.nanoTime());
        for (int index = 1; index <= Byte.SIZE; index++) {
            int expected = rnd.nextInt();
            int actual = func.applyAsInt(expected);
            assertEquals(expected, actual);
        }
    }

    @Test
    void divZeroFactor() {
        assertThrows(IllegalArgumentException.class, () -> {
            IntUnaryOperator func = Int2IntFunction.div(0);
            fail("Unexpected success: " + func);
        });
    }
}
