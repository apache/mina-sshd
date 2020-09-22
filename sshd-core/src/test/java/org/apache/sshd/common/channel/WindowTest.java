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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.server.session.ServerUserAuthServiceFactory;
import org.apache.sshd.util.test.AsyncEchoShellFactory;
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
public class WindowTest extends BaseTestSupport {

    private SshServer sshd;
    private SshClient client;
    private int port;
    private CountDownLatch authLatch;
    private CountDownLatch channelLatch;

    public WindowTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        authLatch = new CountDownLatch(0);
        channelLatch = new CountDownLatch(0);

        sshd = setupTestServer();
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setServiceFactories(Arrays.asList(
                new ServerUserAuthServiceFactory() {
                    @Override
                    public Service create(Session session) throws IOException {
                        return new ServerUserAuthService(session) {
                            @SuppressWarnings("synthetic-access")
                            @Override
                            public void process(int cmd, Buffer buffer) throws Exception {
                                authLatch.await();
                                super.process(cmd, buffer);
                            }
                        };
                    }
                },
                ServerConnectionServiceFactory.INSTANCE));
        sshd.setChannelFactories(Arrays.asList(
                new ChannelSessionFactory() {
                    @Override
                    public Channel createChannel(Session session) throws IOException {
                        return new ChannelSession() {
                            @SuppressWarnings("synthetic-access")
                            @Override
                            public OpenFuture open(int recipient, long rwsize, long rmpsize, Buffer buffer) {
                                try {
                                    channelLatch.await();
                                } catch (InterruptedException e) {
                                    throw new RuntimeSshException(e);
                                }
                                return super.open(recipient, rwsize, rmpsize, buffer);
                            }

                            @Override
                            public String toString() {
                                return "ChannelSession" + "[id=" + getId() + ", recipient=" + getRecipient() + "]";
                            }
                        };
                    }
                },
                DirectTcpipFactory.INSTANCE));
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testWindowConsumptionWithInvertedStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        CoreModuleProperties.WINDOW_SIZE.set(sshd, 1024L);
        CoreModuleProperties.WINDOW_SIZE.set(client, 1024L);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ChannelShell channel = session.createShellChannel()) {
                channel.open().verify(OPEN_TIMEOUT);

                try (Channel serverChannel = GenericUtils.head(GenericUtils.head(sshd.getActiveSessions())
                        .getService(ServerConnectionService.class).getChannels())) {
                    Window clientLocal = channel.getLocalWindow();
                    Window clientRemote = channel.getRemoteWindow();
                    Window serverLocal = serverChannel.getLocalWindow();
                    Window serverRemote = serverChannel.getRemoteWindow();

                    final String message = "0123456789";
                    final int nbMessages = 500;

                    try (BufferedWriter writer = new BufferedWriter(
                            new OutputStreamWriter(channel.getInvertedIn(), StandardCharsets.UTF_8));
                         BufferedReader reader = new BufferedReader(
                                 new InputStreamReader(channel.getInvertedOut(), StandardCharsets.UTF_8))) {

                        for (int i = 0; i < nbMessages; i++) {
                            writer.write(message);
                            writer.write("\n");
                            writer.flush();

                            waitForWindowNotEquals(clientLocal, serverRemote, "client local", "server remote",
                                    TimeUnit.SECONDS.toMillis(3L));

                            String line = reader.readLine();
                            assertEquals("Mismatched message at line #" + i, message, line);

                            waitForWindowEquals(clientLocal, serverRemote, "client local", "server remote",
                                    TimeUnit.SECONDS.toMillis(3L));
                            waitForWindowEquals(clientRemote, serverLocal, "client remote", "server local",
                                    TimeUnit.SECONDS.toMillis(3L));
                        }
                    }
                }
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testWindowConsumptionWithDirectStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        CoreModuleProperties.WINDOW_SIZE.set(sshd, 1024L);
        CoreModuleProperties.WINDOW_SIZE.set(client, 1024L);

        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ChannelShell channel = session.createShellChannel();
                 PipedInputStream inPis = new PipedInputStream();
                 PipedOutputStream inPos = new PipedOutputStream(inPis);
                 PipedInputStream outPis = new PipedInputStream();
                 PipedOutputStream outPos = new PipedOutputStream(outPis)) {

                channel.setIn(inPis);
                channel.setOut(outPos);
                channel.open().verify(OPEN_TIMEOUT);

                try (Channel serverChannel = GenericUtils.head(GenericUtils.head(sshd.getActiveSessions())
                        .getService(ServerConnectionService.class).getChannels())) {
                    Window clientLocal = channel.getLocalWindow();
                    Window clientRemote = channel.getRemoteWindow();
                    Window serverLocal = serverChannel.getLocalWindow();
                    Window serverRemote = serverChannel.getRemoteWindow();

                    final String message = "0123456789";
                    final int nbMessages = 500;

                    try (BufferedWriter writer = new BufferedWriter(
                            new OutputStreamWriter(inPos, StandardCharsets.UTF_8));
                         BufferedReader reader = new BufferedReader(
                                 new InputStreamReader(outPis, StandardCharsets.UTF_8))) {
                        for (int i = 0; i < nbMessages; i++) {
                            writer.write(message);
                            writer.write('\n');
                            writer.flush();

                            waitForWindowEquals(clientLocal, serverRemote, "client local", "server remote",
                                    TimeUnit.SECONDS.toMillis(3L));

                            String line = reader.readLine();
                            assertEquals("Mismatched message at line #" + i, message, line);

                            waitForWindowEquals(clientLocal, serverRemote, "client local", "server remote",
                                    TimeUnit.SECONDS.toMillis(3L));
                            waitForWindowEquals(clientRemote, serverLocal, "client remote", "server local",
                                    TimeUnit.SECONDS.toMillis(3L));
                        }
                    }
                }
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testWindowConsumptionWithAsyncStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        CoreModuleProperties.WINDOW_SIZE.set(sshd, 1024L);
        CoreModuleProperties.WINDOW_SIZE.set(client, 1024L);

        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ChannelShell channel = session.createShellChannel()) {
                channel.setStreaming(StreamingChannel.Streaming.Async);
                channel.open().verify(OPEN_TIMEOUT);

                try (Channel serverChannel = GenericUtils.head(GenericUtils.head(sshd.getActiveSessions())
                        .getService(ServerConnectionService.class).getChannels())) {
                    Window clientLocal = channel.getLocalWindow();
                    Window clientRemote = channel.getRemoteWindow();
                    Window serverLocal = serverChannel.getLocalWindow();
                    Window serverRemote = serverChannel.getRemoteWindow();

                    final String message = "0123456789\n";
                    final byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
                    final int nbMessages = 500;
                    IoOutputStream output = channel.getAsyncIn();
                    IoInputStream input = channel.getAsyncOut();
                    for (int i = 0; i < nbMessages; i++) {
                        Buffer buffer = new ByteArrayBuffer(bytes);
                        output.writeBuffer(buffer).verify(DEFAULT_TIMEOUT);

                        waitForWindowNotEquals(clientLocal, serverRemote, "client local", "server remote",
                                TimeUnit.SECONDS.toMillis(3L));

                        Buffer buf = new ByteArrayBuffer(16);
                        IoReadFuture future = input.read(buf);
                        future.verify(DEFAULT_TIMEOUT);
                        assertEquals("Mismatched available data at line #" + i, message.length(), buf.available());
                        assertEquals("Mismatched data at line #" + i, message,
                                new String(buf.array(), buf.rpos(), buf.available(), StandardCharsets.UTF_8));

                        waitForWindowEquals(clientLocal, serverRemote, "client local", "server remote",
                                TimeUnit.SECONDS.toMillis(3L));
                        waitForWindowEquals(clientRemote, serverLocal, "client remote", "server local",
                                TimeUnit.SECONDS.toMillis(3L));
                    }
                }
            }
        } finally {
            client.stop();
        }
    }

    private static void waitForWindowNotEquals(Window w1, Window w2, String n1, String n2, long maxWait)
            throws InterruptedException {
        for (long waited = 0L, maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(maxWait); waited < maxWaitNanos;) {
            if (w1.getSize() != w2.getSize()) {
                return;
            }

            long nanoStart = System.nanoTime();
            Thread.sleep(1L);
            long nanoEnd = System.nanoTime();
            long nanoDuration = nanoEnd - nanoStart;
            waited += nanoDuration;
        }

        // one last chance ...
        assertNotEquals(n1 + " and " + n2, w1.getSize(), w2.getSize());
    }

    private static void waitForWindowEquals(Window w1, Window w2, String n1, String n2, long maxWait)
            throws InterruptedException {
        for (long waited = 0L, maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(maxWait); waited < maxWaitNanos;) {
            if (w1.getSize() == w2.getSize()) {
                return;
            }

            long nanoStart = System.nanoTime();
            Thread.sleep(1L);
            long nanoEnd = System.nanoTime();
            long nanoDuration = nanoEnd - nanoStart;
            waited += nanoDuration;
        }

        // one last chance ...
        assertEquals(n1 + " and " + n2, w1.getSize(), w2.getSize());
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
        public static final CountDownLatch LATCH = new CountDownLatch(1);

        public TestEchoShell() {
            super();
        }

        @Override
        public void destroy(ChannelSession channel) throws Exception {
            LATCH.countDown();
            super.destroy(channel);
        }
    }
}
