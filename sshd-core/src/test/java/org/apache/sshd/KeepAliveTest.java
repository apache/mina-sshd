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
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
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

    private SshServer sshd;
    private int port;

    private static final long HEARTBEAT = TimeUnit.SECONDS.toMillis(2L);
    private static final long TIMEOUT = 2L * HEARTBEAT;
    private static final long WAIT = 2L * TIMEOUT;

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TIMEOUT);
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

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                Collection<ClientChannel.ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result,
                           result.containsAll(
                                   EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED, ClientChannel.ClientChannelEvent.EOF)));
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        SshClient client = setupTestClient();
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                Collection<ClientChannel.ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result, result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));
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

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(9L, TimeUnit.SECONDS);

                assertTrue("Latch time out", TestEchoShell.latch.await(10L, TimeUnit.SECONDS));
                Collection<ClientChannel.ClientChannelEvent> result =
                        channel.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), WAIT);
                assertTrue("Wrong channel state: " + result,
                           result.containsAll(
                               EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED,
                                          ClientChannel.ClientChannelEvent.EOF,
                                          ClientChannel.ClientChannelEvent.OPENED)));
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

        public static CountDownLatch latch;

        @Override
        public void destroy() {
            if (latch != null) {
                latch.countDown();
            }
            super.destroy();
        }
    }
}
