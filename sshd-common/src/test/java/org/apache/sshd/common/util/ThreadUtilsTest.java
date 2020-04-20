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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ThreadUtilsTest extends JUnitTestSupport {
    public ThreadUtilsTest() {
        super();
    }

    @Test
    public void testProtectExecutorServiceShutdown() {
        for (boolean shutdownOnExit : new boolean[] { true, false }) {
            assertNull("Unexpected instance for shutdown=" + shutdownOnExit,
                    ThreadUtils.protectExecutorServiceShutdown(null, shutdownOnExit));
        }

        CloseableExecutorService service = ThreadUtils.newSingleThreadExecutor("pool");
        try {
            assertSame("Unexpected wrapped instance", service, ThreadUtils.protectExecutorServiceShutdown(service, true));

            CloseableExecutorService wrapped = ThreadUtils.protectExecutorServiceShutdown(service, false);
            try {
                assertNotSame("No wrapping occurred", service, wrapped);

                wrapped.shutdown();
                assertTrue("Wrapped service not shutdown", wrapped.isShutdown());
                assertFalse("Protected service is shutdown", service.isShutdown());

                Collection<?> running = wrapped.shutdownNow();
                assertTrue("Non-empty runners list", running.isEmpty());
                assertTrue("Wrapped service not shutdownNow", wrapped.isShutdown());
                assertFalse("Protected service is shutdownNow", service.isShutdown());
            } finally {
                wrapped.shutdownNow(); // just in case
            }
        } finally {
            service.shutdownNow(); // just in case...
        }
    }
}
