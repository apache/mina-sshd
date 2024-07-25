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

package org.apache.sshd.common.util;

import java.util.Collection;

import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ThreadUtilsTest extends JUnitTestSupport {
    public ThreadUtilsTest() {
        super();
    }

    @Test
    void protectExecutorServiceShutdown() {
        for (boolean shutdownOnExit : new boolean[] { true, false }) {
            assertNull(ThreadUtils.protectExecutorServiceShutdown(null, shutdownOnExit),
                    "Unexpected instance for shutdown=" + shutdownOnExit);
        }

        CloseableExecutorService service = ThreadUtils.newSingleThreadExecutor("pool");
        try {
            assertSame(service, ThreadUtils.protectExecutorServiceShutdown(service, true), "Unexpected wrapped instance");

            CloseableExecutorService wrapped = ThreadUtils.protectExecutorServiceShutdown(service, false);
            try {
                assertNotSame(service, wrapped, "No wrapping occurred");

                wrapped.shutdown();
                assertTrue(wrapped.isShutdown(), "Wrapped service not shutdown");
                assertFalse(service.isShutdown(), "Protected service is shutdown");

                Collection<?> running = wrapped.shutdownNow();
                assertTrue(running.isEmpty(), "Non-empty runners list");
                assertTrue(wrapped.isShutdown(), "Wrapped service not shutdownNow");
                assertFalse(service.isShutdown(), "Protected service is shutdownNow");
            } finally {
                wrapped.shutdownNow(); // just in case
            }
        } finally {
            service.shutdownNow(); // just in case...
        }
    }
}
