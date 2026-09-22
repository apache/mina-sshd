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
package org.apache.sshd.client.session.proxy;

import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Basic tests for {@link Accumulator}.
 */
@Tag("NoIoTestCase")
class AccumulatorTest extends JUnitTestSupport {

    private static final byte[] END = { '\r', '\n', '\r', '\n' };

    @Test
    void normalInput() throws Exception {
        byte[] data = "Complete line\r\nHeader:foo\r\nOther:bar\r\n\r\nSomething else\r\n\r\nanother line"
                .getBytes(StandardCharsets.US_ASCII);
        Accumulator acc = new Accumulator(100, END, "Headers too long");
        assertTrue(acc.accumulate(new ByteArrayBuffer(data)));
        String headers = new String(acc.getData(), StandardCharsets.US_ASCII);
        String body = new String(acc.getRest(), StandardCharsets.US_ASCII);
        assertEquals("Something else\r\n\r\nanother line", body);
        assertArrayEquals(data, (headers + body).getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void noBody() throws Exception {
        byte[] data = "Complete line\r\nHeader:foo\r\nOther:bar\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        Accumulator acc = new Accumulator(100, END, "Headers too long");
        assertTrue(acc.accumulate(new ByteArrayBuffer(data)));
        String headers = new String(acc.getData(), StandardCharsets.US_ASCII);
        String body = new String(acc.getRest(), StandardCharsets.US_ASCII);
        assertEquals("", body);
        assertArrayEquals(data, headers.getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void fragmentedInput() throws Exception {
        byte[] data = "Complete line\r\nHeader:foo\r\nOther:bar\r\n\r\nSomething else\r\n\r\nanother line"
                .getBytes(StandardCharsets.US_ASCII);
        Accumulator acc = new Accumulator(100, END, "Headers too long");
        for (int i = 0; i < data.length; i++) {
            if (i < 39) {
                assertFalse(acc.accumulate(new ByteArrayBuffer(data, i, 1)), "Failed false at " + i);
            } else {
                assertTrue(acc.accumulate(new ByteArrayBuffer(data, i, 1)), "Failed  true at " + i);
            }
        }
        String headers = new String(acc.getData(), StandardCharsets.US_ASCII);
        String body = new String(acc.getRest(), StandardCharsets.US_ASCII);
        assertEquals("Something else\r\n\r\nanother line", body);
        assertArrayEquals(data, (headers + body).getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void limitExceeded() throws Exception {
        byte[] data = new byte[11];
        Accumulator acc = new Accumulator(10, END, "Headers too long");
        assertThrows(Exception.class, () -> acc.accumulate(new ByteArrayBuffer(data)));
    }

    @Test
    void limitExceededFragmented() throws Exception {
        byte[] data = new byte[8];
        Accumulator acc = new Accumulator(10, END, "Headers too long");
        assertFalse(acc.accumulate(new ByteArrayBuffer(data)));
        assertThrows(Exception.class, () -> acc.accumulate(new ByteArrayBuffer(data)));
    }

}
