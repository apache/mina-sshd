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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ChannelPipedOutputStreamTest extends BaseTestSupport {
    public ChannelPipedOutputStreamTest() {
        super();
    }

    @Test
    void nioChannelImplementation() throws IOException {
        ChannelPipedSink sink = Mockito.mock(ChannelPipedSink.class);
        AtomicBoolean eofCalled = new AtomicBoolean(false);
        Mockito.doAnswer(invocation -> {
            assertFalse(eofCalled.getAndSet(true), "Multiple EOF calls");
            return null;
        }).when(sink).eof();

        AtomicInteger receiveCount = new AtomicInteger(0);
        Mockito.doAnswer(invocation -> {
            Number len = invocation.getArgument(2);
            receiveCount.addAndGet(len.intValue());
            return null;
        }).when(sink).receive(ArgumentMatchers.any(byte[].class), ArgumentMatchers.anyInt(), ArgumentMatchers.anyInt());

        try (ChannelPipedOutputStream stream = new ChannelPipedOutputStream(sink)) {
            assertTrue(stream.isOpen(), "Stream not marked as initially open");
            assertEquals(0, receiveCount.intValue(), "Unexpected initial receive count");

            byte[] b = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
            stream.write(b);
            assertTrue(stream.isOpen(), "Stream not marked as still open after write data");
            assertEquals(b.length, receiveCount.intValue(), "Mismatched write data count");

            stream.close();
            assertFalse(stream.isOpen(), "Stream still marked as open after close");
            assertTrue(eofCalled.get(), "Sink EOF not called on close");

            assertThrows(IOException.class, () -> stream.write(b), "Unexpected write success after close");
            // flush() should not fail
            stream.flush();
        }
    }
}
