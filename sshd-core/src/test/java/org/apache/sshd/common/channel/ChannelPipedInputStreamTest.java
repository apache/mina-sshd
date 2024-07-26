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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusChannel;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ChannelPipedInputStreamTest extends BaseTestSupport {
    public ChannelPipedInputStreamTest() {
        super();
    }

    @Test
    void available() throws IOException {
        try (ChannelPipedInputStream stream = createTestStream()) {
            byte[] b = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
            stream.receive(b, 0, b.length);
            assertEquals(b.length, stream.available(), "Mismatched reported available size after receive");

            stream.eof();
            assertEquals(b.length, stream.available(), "Mismatched reported available size after EOF");

            byte[] readBytes = new byte[b.length + Long.SIZE];
            assertEquals(b.length, stream.read(readBytes), "Mismatched reported read size");
            assertStreamEquals(b, readBytes);
            assertEquals(-1, stream.available(), "Unexpected data still available");
            assertEquals(-1, stream.read(), "Unexpectedly not at EOF");
        }
    }

    @Test
    void idempotentClose() throws IOException {
        try (ChannelPipedInputStream stream = createTestStream()) {
            byte[] b = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
            stream.receive(b, 0, b.length);
            stream.eof();

            for (int index = 0; index < Byte.SIZE; index++) {
                stream.close();
            }
        }
    }

    private static ChannelPipedInputStream createTestStream() {
        AbstractChannel channel = new BogusChannel();
        LocalWindow window = new LocalWindow(channel, true);
        window.init(PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
        return new ChannelPipedInputStream(channel, window);
    }

    private static void assertStreamEquals(byte[] expected, byte[] read) {
        if (expected.length > read.length) {
            fail("Less bytes than expected: " + Arrays.toString(expected) + " but got: " + Arrays.toString(read));
        } else {
            assertArrayEquals(expected, Arrays.copyOf(read, expected.length), "Mismatched stream content");
            for (int i = expected.length; i < read.length; i++) {
                assertEquals(0, read[i], "Non-zero value at position " + i);
            }
        }
    }
}
