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

package org.apache.sshd.common.io.nio2;

import java.net.Socket;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Nio2ServiceTest extends BaseTestSupport {
    public Nio2ServiceTest() {
        super();
    }

    @Test   // see SSHD-554
    public void testSetSocketOptions() throws Exception {
        try (SshServer sshd = setupTestServer()) {
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.SOCKET_KEEPALIVE, true);
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.SOCKET_LINGER, 5);
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.SOCKET_RCVBUF, 1024);
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.SOCKET_REUSEADDR, true);
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.SOCKET_SNDBUF, 1024);
            PropertyResolverUtils.updateProperty(sshd, FactoryManager.TCP_NODELAY, true);

            sshd.start();

            int port = sshd.getPort();
            long startTime = System.nanoTime();
            try (Socket s = new Socket(TEST_LOCALHOST, port)) {
                long endTime = System.nanoTime();
                long duration = endTime - startTime;
                assertTrue("Connect duration is too high: " + duration, duration <= TimeUnit.SECONDS.toNanos(15L));
            } finally {
                sshd.stop();
            }
        }
    }
}
