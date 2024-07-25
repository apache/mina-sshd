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
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://issues.apache.org/jira/browse/SSHD-565">SSHD-565</A>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class WindowTimeoutTest extends BaseTestSupport {
    public static final Duration MAX_WAIT_TIME = Duration.ofSeconds(2L);

    private AbstractChannel channel;

    public WindowTimeoutTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        channel = new AbstractChannel(getCurrentTestName(), true) {
            @Override
            public OpenFuture open(long recipient, long rwSize, long packetSize, Buffer buffer) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void handleOpenSuccess(long recipient, long rwSize, long packetSize, Buffer buffer) throws IOException {
                throw new UnsupportedOperationException();
            }

            @Override
            public void handleOpenFailure(Buffer buffer) throws IOException {
                throw new UnsupportedOperationException();
            }

            @Override
            protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
                throw new UnsupportedOperationException();
            }

            @Override
            protected void doWriteData(byte[] data, int off, long len) throws IOException {
                throw new UnsupportedOperationException();
            }
        };
    }

    @AfterEach
    void tearDown() throws Exception {
        if (channel != null) {
            channel.close();
        }
    }

    @Test
    void windowWaitForSpaceTimeout() throws Exception {
        try (RemoteWindow window = channel.getRemoteWindow()) {
            window.init(CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(),
                    CoreModuleProperties.MAX_PACKET_SIZE.getRequiredDefault(),
                    PropertyResolver.EMPTY);
            window.consume(window.getSize());
            assertEquals(0, window.getSize(), "Window not empty");

            long waitStart = System.nanoTime();
            try {
                long len = window.waitForSpace(MAX_WAIT_TIME);
                fail("Unexpected timed wait success - len=" + len);
            } catch (SocketTimeoutException e) {
                long waitEnd = System.nanoTime();
                long waitDuration = TimeUnit.NANOSECONDS.toMillis(waitEnd - waitStart);
                // we allow ~100 millis variance to compensate for O/S wait time granularity
                assertTrue(waitDuration >= (MAX_WAIT_TIME.toMillis() - 100L), "Timeout too soon: " + waitDuration);
            }

            window.close();
            assertFalse(window.isOpen(), "Window not closed");
            try {
                long len = window.waitForSpace(MAX_WAIT_TIME);
                fail("Unexpected closed wait success - len=" + len);
            } catch (WindowClosedException e) {
                // expected
            }
        }
    }

    @Test
    void windowWaitAndConsumeTimeout() throws Exception {
        try (RemoteWindow window = channel.getRemoteWindow()) {
            window.init(CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(),
                    CoreModuleProperties.MAX_PACKET_SIZE.getRequiredDefault(),
                    PropertyResolver.EMPTY);

            long waitStart = System.nanoTime();
            try {
                window.waitAndConsume(2 * window.getSize(), MAX_WAIT_TIME);
                fail("Unexpected timed wait success");
            } catch (SocketTimeoutException e) {
                long waitEnd = System.nanoTime();
                long waitDuration = TimeUnit.NANOSECONDS.toMillis(waitEnd - waitStart);
                // we allow ~100 millis variance to compensate for O/S wait time granularity
                assertTrue(waitDuration >= (MAX_WAIT_TIME.toMillis() - 100L), "Timeout too soon: " + waitDuration);
            }

            window.close();
            assertFalse(window.isOpen(), "Window not closed");
            assertThrows(WindowClosedException.class,
                    () -> window.waitAndConsume(2 * window.getSize(), MAX_WAIT_TIME),
                    "Unexpected closed wait success");
        }
    }
}
