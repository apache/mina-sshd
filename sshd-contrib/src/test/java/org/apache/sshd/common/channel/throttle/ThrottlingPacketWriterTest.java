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
package org.apache.sshd.common.channel.throttle;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.InterruptedByTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.channel.IoWriteFutureImpl;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.PacketWriter;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ThrottlingPacketWriterTest extends BaseTestSupport {
    public ThrottlingPacketWriterTest() {
        super();
    }

    @Test
    public void testThrottlerWaitsUntilPacketSendSignalled() throws IOException {
        try (ThrottlingPacketWriter throttler = new ThrottlingPacketWriter(new MockPacketWriter(), Byte.SIZE, TimeUnit.SECONDS.toMillis(3L))) {
            int maxSize = throttler.getMaxPendingPackets();
            List<IoWriteFuture> pendingWrites = new ArrayList<>(maxSize);
            Buffer buf = new ByteArrayBuffer(Byte.SIZE);
            for (int index = maxSize; index > 0; index--) {
                IoWriteFuture future = throttler.writePacket(buf);
                pendingWrites.add(future);
                assertEquals("Mismatched available packets count", index - 1, throttler.getAvailablePacketsCount());
            }

            assertEquals("Not all available packet window size exhausted", 0, throttler.getAvailablePacketsCount());
            try {
                IoWriteFuture future = throttler.writePacket(buf);
                fail("Unexpected extra packet success: " + future);
            } catch (InterruptedByTimeoutException e) {
                // expected
            }

            int sendSize = pendingWrites.size() / 2;
            for (int index = 0; index < sendSize; index++) {
                IoWriteFutureImpl future = (IoWriteFutureImpl) pendingWrites.get(index);
                future.setValue(Boolean.TRUE);
                assertEquals("Mismatched available packets count", index + 1, throttler.getAvailablePacketsCount());
            }

            for (int index = throttler.getAvailablePacketsCount(); index < maxSize; index++) {
                throttler.writePacket(buf);
            }
        }
    }

    @Test(expected = ClosedSelectorException.class)
    public void testThrottlerDoesNotSendIfClosed() throws IOException {
        try (PacketWriter throttler = new ThrottlingPacketWriter(new MockPacketWriter(), Byte.SIZE, TimeUnit.SECONDS.toMillis(3L))) {
            assertTrue("Throttler not marked as open", throttler.isOpen());
            throttler.close();
            assertFalse("Throttler not marked as closed", throttler.isOpen());

            IoWriteFuture future = throttler.writePacket(new ByteArrayBuffer(Byte.SIZE));
            fail("Unexpected success: " + future);
        }
    }

    @Test(expected = ClosedSelectorException.class)
    public void testThrottlerStopsSendingIfExceptionSignaledOnFutureOperationCompletion() throws IOException {
        try (PacketWriter throttler = new ThrottlingPacketWriter(new MockPacketWriter(), Byte.SIZE, TimeUnit.SECONDS.toMillis(3L))) {
            assertTrue("Throttler not marked as open", throttler.isOpen());

            IoWriteFutureImpl futureImpl = (IoWriteFutureImpl) throttler.writePacket(new ByteArrayBuffer(Byte.SIZE));
            futureImpl.setValue(new StreamCorruptedException(getCurrentTestName()));
            assertFalse("Throttler not marked as closed", throttler.isOpen());

            IoWriteFuture future = throttler.writePacket(new ByteArrayBuffer(Byte.SIZE));
            fail("Unexpected success: " + future);
        }
    }

    private static class MockPacketWriter implements PacketWriter {
        MockPacketWriter() {
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
        public IoWriteFuture writePacket(Buffer buffer) throws IOException {
            return new IoWriteFutureImpl(MockPacketWriter.class.getSimpleName(), buffer);
        }
    }
}
