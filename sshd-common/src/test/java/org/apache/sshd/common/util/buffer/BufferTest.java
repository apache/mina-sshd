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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class BufferTest extends JUnitTestSupport {
    public BufferTest() {
        super();
    }

    @Test
    public void testGetLong() throws Exception {
        long expected = 1234567890123456789L;

        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            try (DataOutputStream ds = new DataOutputStream(stream)) {
                ds.writeLong(expected);
            }

            Buffer buffer = new ByteArrayBuffer(stream.toByteArray());
            assertEquals("Mismatched recovered value", expected, buffer.getLong());
        }
    }

    @Test
    public void testPutCharsWithNullOrEmptyValue() {
        Buffer buffer = new ByteArrayBuffer(Integer.SIZE);
        for (char[] chars : new char[][] { null, GenericUtils.EMPTY_CHAR_ARRAY }) {
            buffer.putChars(chars);

            String value = buffer.getString();
            assertEquals("Mismatched value for " + ((chars == null) ? "null" : "empty") + " characters", "", value);
        }
    }

    @Test
    public void testPutCharsOnNonEmptyValue() {
        String expected = getCurrentTestName();
        Buffer buffer = new ByteArrayBuffer(expected.length() + Byte.SIZE);
        buffer.putChars(expected.toCharArray());

        String actual = buffer.getString();
        assertEquals("Mismatched recovered values", expected, actual);
    }

    @Test
    public void testPutAndWipeChars() {
        String expected = getCurrentTestName();
        char[] chars = expected.toCharArray();
        Buffer buffer = new ByteArrayBuffer(chars.length + Byte.SIZE);
        buffer.putAndWipeChars(chars);

        String actual = buffer.getString();
        assertEquals("Mismatched recovered values", expected, actual);

        for (int index = 0; index < chars.length; index++) {
            assertEquals("Character not wiped at index=" + index, 0, chars[index]);
        }
    }

    @Test
    public void testPutAndWipeBytes() {
        String expected = getCurrentTestName();
        byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
        Buffer buffer = new ByteArrayBuffer(bytes.length + Byte.SIZE);
        buffer.putAndWipeBytes(bytes);
        String actual = buffer.getString();
        assertEquals("Mismatched recovered values", expected, actual);

        for (int index = 0; index < bytes.length; index++) {
            assertEquals("Value not wiped at index=" + index, 0, bytes[index]);
        }
    }
}
