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
package org.apache.sshd.server;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author Kohsuke Kawaguchi
 * @author Michael Heemskerk
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SshServerTest extends BaseTestSupport {
    public SshServerTest() {
        super();
    }

    @Test
    public void stopMethodShouldBeIdempotent() throws Exception {
        try (SshServer sshd = new SshServer()) {
            sshd.stop();
            sshd.stop();
            sshd.stop();
        }
    }

    @Test
    public void testExecutorShutdownFalse() throws Exception {
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

        try (SshServer sshd = setupTestServer()) {
            sshd.setScheduledExecutorService(executorService);

            sshd.start();
            sshd.stop();

            assertFalse(executorService.isShutdown());
            executorService.shutdownNow();
        }
    }

    @Test
    public void testExecutorShutdownTrue() throws Exception {
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

        try (SshServer sshd = setupTestServer()) {
            sshd.setScheduledExecutorService(executorService, true);

            sshd.start();
            sshd.stop();

            assertTrue(executorService.isShutdown());
        }
    }

    @Test
    public void testDynamicPort() throws Exception {
        try (SshServer sshd = setupTestServer()) {
            sshd.setHost(TEST_LOCALHOST);
            sshd.start();

            assertNotEquals(0, sshd.getPort());

            sshd.stop();
        }
    }
}
