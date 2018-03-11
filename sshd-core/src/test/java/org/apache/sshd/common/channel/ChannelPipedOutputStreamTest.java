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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ChannelPipedOutputStreamTest extends BaseTestSupport {
    public ChannelPipedOutputStreamTest() {
        super();
    }

    @Test
    public void testNioChannelImplementation() throws IOException {
        ChannelPipedSink sink = Mockito.mock(ChannelPipedSink.class);
        AtomicBoolean eofCalled = new AtomicBoolean(false);
        Mockito.doAnswer(invocation -> {
            assertFalse("Multiple EOF calls", eofCalled.getAndSet(true));
            return null;
        }).when(sink).eof();

        AtomicInteger receiveCount = new AtomicInteger(0);
        Mockito.doAnswer(invocation -> {
            Number len = invocation.getArgument(2);
            receiveCount.addAndGet(len.intValue());
            return null;
        }).when(sink).receive(ArgumentMatchers.any(byte[].class), ArgumentMatchers.anyInt(), ArgumentMatchers.anyInt());

        try (ChannelPipedOutputStream stream = new ChannelPipedOutputStream(sink)) {
            assertTrue("Stream not marked as initially open", stream.isOpen());
            assertEquals("Unexpected initial receive count", 0, receiveCount.intValue());

            byte[] b = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
            stream.write(b);
            assertTrue("Stream not marked as still open after write data", stream.isOpen());
            assertEquals("Mismatched write data count", b.length, receiveCount.intValue());

            stream.close();
            assertFalse("Stream still marked as open after close", stream.isOpen());
            assertTrue("Sink EOF not called on close", eofCalled.get());

            try {
                stream.write(b);
                fail("Unexpected write success after close");
            } catch (IOException e) {
                // expected
            }

            try {
                stream.flush();
                fail("Unexpected flush success after close");
            } catch (IOException e) {
                // expected
            }
        }
    }
}
