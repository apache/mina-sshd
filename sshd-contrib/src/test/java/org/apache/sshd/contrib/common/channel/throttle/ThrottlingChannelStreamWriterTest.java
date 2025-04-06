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
package org.apache.sshd.contrib.common.channel.throttle;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.InterruptedByTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.channel.IoWriteFutureImpl;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
class ThrottlingChannelStreamWriterTest extends BaseTestSupport {

    ThrottlingChannelStreamWriterTest() {
        super();
    }

    @Test
    @Timeout(value = 10_000, unit = TimeUnit.MILLISECONDS)
    void throttlerWaitsUntilPacketSendSignalled() throws IOException {
        try (ThrottlingChannelStreamWriter throttler
                = new ThrottlingChannelStreamWriter(new MockChannelStreamWriter(), Byte.SIZE, TimeUnit.SECONDS.toMillis(3L))) {
            int maxSize = throttler.getMaxPendingPackets();
            List<IoWriteFuture> pendingWrites = new ArrayList<>(maxSize);
            Buffer buf = new ByteArrayBuffer(Byte.SIZE);
            for (int index = maxSize; index > 0; index--) {
                IoWriteFuture future = throttler.writeData(buf);
                pendingWrites.add(future);
                assertEquals(index - 1, throttler.getAvailablePacketsCount(), "Mismatched available packets count");
            }

            assertEquals(0, throttler.getAvailablePacketsCount(), "Not all available packet window size exhausted");
            try {
                IoWriteFuture future = throttler.writeData(buf);
                fail("Unexpected extra packet success: " + future);
            } catch (InterruptedByTimeoutException e) {
                // expected
            }

            int sendSize = pendingWrites.size() / 2;
            for (int index = 0; index < sendSize; index++) {
                IoWriteFutureImpl future = (IoWriteFutureImpl) pendingWrites.get(index);
                future.setValue(Boolean.TRUE);
                assertEquals(index + 1, throttler.getAvailablePacketsCount(), "Mismatched available packets count");
            }

            for (int index = throttler.getAvailablePacketsCount(); index < maxSize; index++) {
                throttler.writeData(buf);
            }
        }
    }

    @Test
    @Timeout(value = 10_000, unit = TimeUnit.MILLISECONDS)
    void throttlerDoesNotSendIfClosed() throws IOException {
        assertThrows(ClosedSelectorException.class, () -> {
            try (ChannelStreamWriter throttler
                    = new ThrottlingChannelStreamWriter(new MockChannelStreamWriter(), Byte.SIZE,
                            TimeUnit.SECONDS.toMillis(3L))) {
                assertTrue(throttler.isOpen(), "Throttler not marked as open");
                throttler.close();
                assertFalse(throttler.isOpen(), "Throttler not marked as closed");

                IoWriteFuture future = throttler.writeData(new ByteArrayBuffer(Byte.SIZE));
                fail("Unexpected success: " + future);
            }
        });
    }

    @Test
    @Timeout(value = 10_000, unit = TimeUnit.MILLISECONDS)
    void throttlerStopsSendingIfExceptionSignaledOnFutureOperationCompletion() throws IOException {
        assertThrows(ClosedSelectorException.class, () -> {
            try (ChannelStreamWriter throttler
                    = new ThrottlingChannelStreamWriter(new MockChannelStreamWriter(), Byte.SIZE,
                            TimeUnit.SECONDS.toMillis(3L))) {
                assertTrue(throttler.isOpen(), "Throttler not marked as open");

                IoWriteFutureImpl futureImpl = (IoWriteFutureImpl) throttler.writeData(new ByteArrayBuffer(Byte.SIZE));
                futureImpl.setValue(new StreamCorruptedException(getCurrentTestName()));
                assertFalse(throttler.isOpen(), "Throttler not marked as closed");

                IoWriteFuture future = throttler.writeData(new ByteArrayBuffer(Byte.SIZE));
                fail("Unexpected success: " + future);
            }
        });
    }

    private static class MockChannelStreamWriter implements ChannelStreamWriter {
        MockChannelStreamWriter() {
            super();
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() throws IOException {
            throw new UnsupportedOperationException("Unexpected close call");
        }

        @Override
        public IoWriteFuture writeData(Buffer buffer) throws IOException {
            return new IoWriteFutureImpl(MockChannelStreamWriter.class.getSimpleName(), buffer);
        }
    }
}
