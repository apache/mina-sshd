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
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
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
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeepAliveTest extends BaseTestSupport {

    private static final long HEARTBEAT = TimeUnit.SECONDS.toMillis(2L);
    private static final long TIMEOUT = HEARTBEAT * 2L;
    private static final long WAIT = 3L * TIMEOUT;

    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    public KeepAliveTest() {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(KeepAliveTest.class);
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(KeepAliveTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @Before
    public void setUp() {
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TIMEOUT);
    }

    @After
    public void tearDown() {
        // Restore default value
        PropertyResolverUtils.updateProperty(
            sshd, FactoryManager.IDLE_TIMEOUT, FactoryManager.DEFAULT_IDLE_TIMEOUT);
        PropertyResolverUtils.updateProperty(
            client, ClientFactoryManager.HEARTBEAT_INTERVAL, ClientFactoryManager.DEFAULT_HEARTBEAT_INTERVAL);
        PropertyResolverUtils.updateProperty(
            client, ClientFactoryManager.HEARTBEAT_REPLY_WAIT, ClientFactoryManager.DEFAULT_HEARTBEAT_REPLY_WAIT);
    }

    @Test
    public void testIdleClient() throws Exception {
        try (ClientSession session =
                client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result =
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue("Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result,
                    result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)));
            }
        }
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        PropertyResolverUtils.updateProperty(
            client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        try (ClientSession session =
                client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result =
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue("Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result,
                    result.contains(ClientChannelEvent.TIMEOUT));
            }
        }
    }

    @Test
    public void testShellClosedOnClientTimeout() throws Exception {
        TestEchoShell.latch = new CountDownLatch(1);

        try (ClientSession session =
                client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(OPEN_TIMEOUT);

                assertTrue("Latch time out", TestEchoShell.latch.await(DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));

                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result =
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue("Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result,
                   result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED, ClientChannelEvent.OPENED)));
            }
        } finally {
            TestEchoShell.latch = null;
        }
    }

    @Test // see SSHD-968
    public void testAllowUnimplementedMessageHeartbeatResponse() throws Exception {
        List<RequestHandler<ConnectionService>> globalHandlers = sshd.getGlobalRequestHandlers();
        sshd.setGlobalRequestHandlers(
            Collections.singletonList(
                new AbstractConnectionServiceRequestHandler() {
                    @Override
                    public Result process(
                            ConnectionService connectionService, String request,
                            boolean wantReply, Buffer buffer)
                                throws Exception {
                        connectionService.process(
                            255 /* trigger unimplemented command handler */, buffer);
                        return Result.Replied;
                    }
                }));
        PropertyResolverUtils.updateProperty(
            client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        PropertyResolverUtils.updateProperty(
            client, ClientFactoryManager.HEARTBEAT_REPLY_WAIT, TimeUnit.SECONDS.toMillis(5L));
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(7L, TimeUnit.SECONDS)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result =
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue("Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result,
                    result.contains(ClientChannelEvent.TIMEOUT));
            }
        } finally {
            sshd.setGlobalRequestHandlers(globalHandlers); // restore original
        }
    }

    public static class TestEchoShellFactory extends EchoShellFactory {
        public TestEchoShellFactory() {
            super();
        }

        @Override
        public Command createShell(ChannelSession channel) {
            return new TestEchoShell();
        }
    }

    public static class TestEchoShell extends EchoShell {
        // CHECKSTYLE:OFF
        public static CountDownLatch latch;
        // CHECKSTYLE:ON

        public TestEchoShell() {
            super();
        }

        @Override
        public void destroy(ChannelSession channel) throws Exception {
            if (latch != null) {
                latch.countDown();
            }
            super.destroy(channel);
        }
    }
}
