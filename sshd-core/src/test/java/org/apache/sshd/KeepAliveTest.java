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
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.util.Collection;
import java.util.EnumSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeepAliveTest extends BaseTestSupport {

    private static final long HEARTBEAT = TimeUnit.SECONDS.toMillis(2L);
    private static final long TIMEOUT = 2L * HEARTBEAT;
    private static final long WAIT = 2L * TIMEOUT;

    private SshServer sshd;
    private int port;

    public KeepAliveTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TIMEOUT);
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testIdleClient() throws Exception {
        SshClient client = setupTestClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                Collection<ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result, result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)));
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        SshClient client = setupTestClient();
        PropertyResolverUtils.updateProperty(client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                Collection<ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result, result.contains(ClientChannelEvent.TIMEOUT));
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testShellClosedOnClientTimeout() throws Exception {
        TestEchoShell.latch = new CountDownLatch(1);

        SshClient client = setupTestClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(9L, TimeUnit.SECONDS);

                assertTrue("Latch time out", TestEchoShell.latch.await(10L, TimeUnit.SECONDS));
                Collection<ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result,
                           result.containsAll(
                               EnumSet.of(ClientChannelEvent.CLOSED, ClientChannelEvent.OPENED)));
            }
        } finally {
            TestEchoShell.latch = null;
            client.stop();
        }
    }

    public static class TestEchoShellFactory extends EchoShellFactory {
        @Override
        public Command create() {
            return new TestEchoShell();
        }
    }

    public static class TestEchoShell extends EchoShell {
        // CHECKSTYLE:OFF
        public static CountDownLatch latch;
        // CHECKSTYLE:ON

        @Override
        public void destroy() {
            if (latch != null) {
                latch.countDown();
            }
            super.destroy();
        }
    }
}
