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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://issues.apache.org/jira/browse/SSHD-565">SSHD-565</A>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class WindowTimeoutTest extends BaseTestSupport {
    public static final Duration MAX_WAIT_TIME = Duration.ofSeconds(2L);

    private AbstractChannel channel;

    public WindowTimeoutTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        channel = new AbstractChannel(getCurrentTestName(), true) {
            @Override
            public OpenFuture open(int recipient, long rwSize, long packetSize, Buffer buffer) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void handleOpenSuccess(int recipient, long rwSize, long packetSize, Buffer buffer) throws IOException {
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

    @After
    public void tearDown() throws Exception {
        if (channel != null) {
            channel.close();
        }
    }

    @Test
    public void testWindowWaitForSpaceTimeout() throws Exception {
        try (Window window = channel.getLocalWindow()) {
            window.init(CoreModuleProperties.WINDOW_SIZE.getRequiredDefault(),
                    CoreModuleProperties.MAX_PACKET_SIZE.getRequiredDefault(),
                    PropertyResolver.EMPTY);
            window.consume(window.getSize());
            assertEquals("Window not empty", 0, window.getSize());

            long waitStart = System.nanoTime();
            try {
                long len = window.waitForSpace(MAX_WAIT_TIME);
                fail("Unexpected timed wait success - len=" + len);
            } catch (SocketTimeoutException e) {
                long waitEnd = System.nanoTime();
                long waitDuration = TimeUnit.NANOSECONDS.toMillis(waitEnd - waitStart);
                // we allow ~100 millis variance to compensate for O/S wait time granularity
                assertTrue("Timeout too soon: " + waitDuration, waitDuration >= (MAX_WAIT_TIME.toMillis() - 100L));
            }

            window.close();
            assertFalse("Window not closed", window.isOpen());
            try {
                long len = window.waitForSpace(MAX_WAIT_TIME);
                fail("Unexpected closed wait success - len=" + len);
            } catch (WindowClosedException e) {
                // expected
            }
        }
    }

    @Test
    public void testWindowWaitAndConsumeTimeout() throws Exception {
        try (Window window = channel.getLocalWindow()) {
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
                assertTrue("Timeout too soon: " + waitDuration, waitDuration >= (MAX_WAIT_TIME.toMillis() - 100L));
            }

            window.close();
            assertFalse("Window not closed", window.isOpen());
            try {
                window.waitAndConsume(2 * window.getSize(), MAX_WAIT_TIME);
                fail("Unexpected closed wait success");
            } catch (WindowClosedException e) {
                // expected
            }
        }
    }
}
