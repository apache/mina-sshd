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
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class KeepAliveTest extends BaseTestSupport {

    private static final Duration HEARTBEAT = Duration.ofSeconds(2L);
    private static final Duration TIMEOUT = HEARTBEAT.multipliedBy(2L);
    private static final Duration WAIT = TIMEOUT.multipliedBy(3L);

    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(KeepAliveTest.class);
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(KeepAliveTest.class);
        client.start();
    }

    @AfterAll
    static void tearDownClientAndServer() throws Exception {
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

    @BeforeEach
    void setUp() {
        CoreModuleProperties.IDLE_TIMEOUT.set(sshd, TIMEOUT);
    }

    @AfterEach
    void tearDown() {
        // Restore default value
        CoreModuleProperties.IDLE_TIMEOUT.remove(sshd);
        CoreModuleProperties.HEARTBEAT_INTERVAL.remove(client);
        CoreModuleProperties.HEARTBEAT_NO_REPLY_MAX.remove(client);
    }

    @Test
    void idleClient() throws Exception {
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED)),
                        "Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result);
            }
        }
    }

    @Test
    void clientWithHeartBeat() throws Exception {
        CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, HEARTBEAT);
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.contains(ClientChannelEvent.TIMEOUT),
                        "Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result);
            }
        }
    }

    @Test
    void shellClosedOnClientTimeout() throws Exception {
        TestEchoShell.latch = new CountDownLatch(1);

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
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

                assertTrue(TestEchoShell.latch.await(DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS), "Latch time out");

                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.containsAll(EnumSet.of(ClientChannelEvent.CLOSED, ClientChannelEvent.OPENED)),
                        "Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result);
            }
        } finally {
            TestEchoShell.latch = null;
        }
    }

    // see SSHD-968
    @Test
    void allowUnimplementedMessageHeartbeatResponse() throws Exception {
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
        CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, HEARTBEAT);
        CoreModuleProperties.HEARTBEAT_NO_REPLY_MAX.set(client, 1);
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(7L, TimeUnit.SECONDS)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), WAIT);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.contains(ClientChannelEvent.TIMEOUT),
                        "Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result);
            }
        } finally {
            sshd.setGlobalRequestHandlers(globalHandlers); // restore original
        }
    }

    // see GH-268
    @Test
    void timeoutOnMissingHeartbeatResponse() throws Exception {
        CoreModuleProperties.IDLE_TIMEOUT.set(sshd, Duration.ofSeconds(30));
        List<RequestHandler<ConnectionService>> globalHandlers = sshd.getGlobalRequestHandlers();
        sshd.setGlobalRequestHandlers(Collections.singletonList(new AbstractConnectionServiceRequestHandler() {
            @Override
            public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
                    throws Exception {
                // Never reply;
                return Result.Replied;
            }
        }));
        CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, Duration.ofSeconds(1));
        // CoreModuleProperties.HEARTBEAT_REPLY_WAIT.set(client, Duration.ofSeconds(1));
        CoreModuleProperties.HEARTBEAT_NO_REPLY_MAX.set(client, 1);
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                long waitStart = System.currentTimeMillis();
                Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TIMEOUT);
                long waitEnd = System.currentTimeMillis();
                assertTrue(result.contains(ClientChannelEvent.CLOSED),
                        "Wrong channel state after wait of " + (waitEnd - waitStart) + " ms: " + result);
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
