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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ChannelPipedInputStreamTest extends BaseTestSupport {
    public ChannelPipedInputStreamTest() {
        super();
    }

    @Test
    public void testAvailable() throws IOException {
        try (ChannelPipedInputStream stream = createTestStream()) {
            byte[] b = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
            stream.receive(b, 0, b.length);
            assertEquals("Mismatched reported available size after receive", b.length, stream.available());

            stream.eof();
            assertEquals("Mismatched reported available size after EOF", b.length, stream.available());

            byte[] readBytes = new byte[b.length + Long.SIZE];
            assertEquals("Mismatched reported read size", b.length, stream.read(readBytes));
            assertStreamEquals(b, readBytes);
            assertEquals("Unexpected data still available", -1, stream.available());
        }
    }

    @Test
    public void testIdempotentClose() throws IOException {
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
        Window window = new Window(channel, null, true, true);
        window.init(PropertyResolverUtils.toPropertyResolver(Collections.emptyMap()));
        return new ChannelPipedInputStream(channel, window);
    }

    private static void assertStreamEquals(byte[] expected, byte[] read) {
        if (expected.length > read.length) {
            fail("Less bytes than expected: " + Arrays.toString(expected) + " but got: " + Arrays.toString(read));
        } else {
            assertArrayEquals("Mismatched stream content", expected, Arrays.copyOf(read, expected.length));
            for (int i = expected.length; i < read.length; i++) {
                assertTrue("Non-zero value at position " + i, read[i] == 0);
            }
        }
    }
}
