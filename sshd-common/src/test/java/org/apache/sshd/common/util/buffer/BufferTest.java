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
package org.apache.sshd.common.util.buffer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class BufferTest extends JUnitTestSupport {
    public BufferTest() {
        super();
    }

    @Test
    void getLong() throws Exception {
        long expected = 1234567890123456789L;

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            try (DataOutputStream ds = new DataOutputStream(stream)) {
                ds.writeLong(expected);
            }

            Buffer buffer = new ByteArrayBuffer(stream.toByteArray());
            assertEquals(expected, buffer.getLong(), "Mismatched recovered value");
        }
    }

    @Test
    void putCharsWithNullOrEmptyValue() {
        Buffer buffer = new ByteArrayBuffer(Integer.SIZE);
        for (char[] chars : new char[][] { null, GenericUtils.EMPTY_CHAR_ARRAY }) {
            buffer.putChars(chars);

            String value = buffer.getString();
            assertEquals("", value, "Mismatched value for " + ((chars == null) ? "null" : "empty") + " characters");
        }
    }

    @Test
    void putCharsOnNonEmptyValue() {
        String expected = getCurrentTestName();
        Buffer buffer = new ByteArrayBuffer(expected.length() + Byte.SIZE);
        buffer.putChars(expected.toCharArray());

        String actual = buffer.getString();
        assertEquals(expected, actual, "Mismatched recovered values");
    }

    @Test
    void putAndWipeChars() {
        String expected = getCurrentTestName();
        char[] chars = expected.toCharArray();
        Buffer buffer = new ByteArrayBuffer(chars.length + Byte.SIZE);
        buffer.putAndWipeChars(chars);

        String actual = buffer.getString();
        assertEquals(expected, actual, "Mismatched recovered values");

        for (int index = 0; index < chars.length; index++) {
            assertEquals(0, chars[index], "Character not wiped at index=" + index);
        }
    }

    @Test
    void putAndWipeBytes() {
        String expected = getCurrentTestName();
        byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
        Buffer buffer = new ByteArrayBuffer(bytes.length + Byte.SIZE);
        buffer.putAndWipeBytes(bytes);
        String actual = buffer.getString();
        assertEquals(expected, actual, "Mismatched recovered values");

        for (int index = 0; index < bytes.length; index++) {
            assertEquals(0, bytes[index], "Value not wiped at index=" + index);
        }
    }

    @Test
    void getPublicKeyCorrupted() {
        ByteArrayBuffer buffer = new ByteArrayBuffer(8);
        buffer.putInt(Integer.MAX_VALUE - 10000);
        buffer.putInt(0);
        Throwable e = assertThrows(Throwable.class, () -> buffer.getPublicKey());
        assertFalse(e instanceof OutOfMemoryError);
        assertEquals(8, buffer.array().length);
    }

    @Test
    void shortPositive() {
        ByteArrayBuffer buffer = new ByteArrayBuffer(2);
        buffer.putShort(261);
        assertEquals(261, buffer.getShort());
    }

    @Test
    void shortNegative() {
        ByteArrayBuffer buffer = new ByteArrayBuffer(2);
        buffer.putShort(-2);
        assertEquals(-2, buffer.getShort());
    }
}
