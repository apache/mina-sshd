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
package org.apache.sshd.sftp.client;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.SubsystemClient;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.ChannelListenerManager;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.server.session.ServerUserAuthServiceFactory;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.apache.sshd.util.test.TestChannelListener;
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
@SuppressWarnings("checkstyle:MethodCount")
public class ClientTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;
    private CountDownLatch authLatch;
    private CountDownLatch channelLatch;

    private final AtomicReference<ClientSession> clientSessionHolder = new AtomicReference<>(null);
    @SuppressWarnings("synthetic-access")
    private final SessionListener clientSessionListener = new SessionListener() {
        @Override
        public void sessionCreated(Session session) {
            assertObjectInstanceOf("Non client session creation notification", ClientSession.class, session);
            assertNull("Multiple creation notifications", clientSessionHolder.getAndSet((ClientSession) session));
        }

        @Override
        public void sessionEvent(Session session, Event event) {
            assertObjectInstanceOf("Non client session event notification: " + event, ClientSession.class, session);
            assertSame("Mismatched client session event instance: " + event, clientSessionHolder.get(), session);
        }

        @Override
        public void sessionException(Session session, Throwable t) {
            assertObjectInstanceOf("Non client session exception notification", ClientSession.class, session);
            assertNotNull("No session exception data", t);
        }

        @Override
        public void sessionClosed(Session session) {
            assertObjectInstanceOf("Non client session closure notification", ClientSession.class, session);
            assertSame("Mismatched client session closure instance", clientSessionHolder.getAndSet(null), session);
        }
    };

    public ClientTest() {
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
        clientSessionHolder.set(null); // just making sure
        client.addSessionListener(clientSessionListener);
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
        clientSessionHolder.set(null); // just making sure
    }

    @Test
    public void testSimpleClientListener() throws Exception {
        AtomicReference<Channel> channelHolder = new AtomicReference<>(null);
        client.addChannelListener(new ChannelListener() {
            @Override
            public void channelOpenSuccess(Channel channel) {
                assertSame("Mismatched opened channel instances", channel, channelHolder.get());
            }

            @Override
            public void channelOpenFailure(Channel channel, Throwable reason) {
                assertSame("Mismatched failed open channel instances", channel, channelHolder.get());
            }

            @Override
            public void channelInitialized(Channel channel) {
                assertNull("Multiple channel initialization notifications", channelHolder.getAndSet(channel));
            }

            @Override
            public void channelStateChanged(Channel channel, String hint) {
                outputDebugMessage("channelStateChanged(%s): %s", channel, hint);
            }

            @Override
            public void channelClosed(Channel channel, Throwable reason) {
                assertSame("Mismatched closed channel instances", channel, channelHolder.getAndSet(null));
            }
        });
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));

        client.start();

        try (ClientSession session = createTestClientSession()) {
            testClientListener(channelHolder, ChannelShell.class, () -> {
                try {
                    return session.createShellChannel();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            testClientListener(channelHolder, ChannelExec.class, () -> {
                try {
                    return session.createExecChannel(getCurrentTestName());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            testClientListener(channelHolder, SftpClient.class, () -> {
                try {
                    SftpClientFactory clientFactory = SftpClientFactory.instance();
                    return clientFactory.createSftpClient(session);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } finally {
            client.stop();
        }
    }

    private <C extends Closeable> void testClientListener(
            AtomicReference<Channel> channelHolder, Class<C> channelType, Factory<? extends C> factory)
            throws Exception {
        assertNull(channelType.getSimpleName() + ": Unexpected currently active channel", channelHolder.get());

        try (C instance = factory.create()) {
            Channel expectedChannel;
            if (instance instanceof Channel) {
                expectedChannel = (Channel) instance;
            } else if (instance instanceof SubsystemClient) {
                expectedChannel = ((SubsystemClient) instance).getClientChannel();
            } else {
                throw new UnsupportedOperationException("Unknown test instance type" + instance.getClass().getSimpleName());
            }

            Channel actualChannel = channelHolder.get();
            assertSame("Mismatched listener " + channelType.getSimpleName() + " instances", expectedChannel, actualChannel);
        }

        assertNull(channelType.getSimpleName() + ": Active channel closure not signalled", channelHolder.get());
    }

    @Test
    public void testCreateChannelByType() throws Exception {
        client.start();

        Collection<ClientChannel> channels = new LinkedList<>();
        try (ClientSession session = createTestClientSession()) {
            // required since we do not use an SFTP subsystem
            CoreModuleProperties.REQUEST_SUBSYSTEM_REPLY.set(session, false);
            channels.add(session.createChannel(Channel.CHANNEL_SUBSYSTEM, SftpConstants.SFTP_SUBSYSTEM_NAME));
            channels.add(session.createChannel(Channel.CHANNEL_EXEC, getCurrentTestName()));
            channels.add(session.createChannel(Channel.CHANNEL_SHELL, getClass().getSimpleName()));

            Set<Integer> ids = new HashSet<>(channels.size());
            for (ClientChannel c : channels) {
                int id = c.getId();
                assertTrue("Channel ID repeated: " + id, ids.add(id));
            }
        } finally {
            for (Closeable c : channels) {
                try {
                    c.close();
                } catch (IOException e) {
                    // ignored
                }
            }
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    /**
     * Makes sure that the {@link ChannelListener}s added to the client, session and channel are <U>cumulative</U> -
     * i.e., all of them invoked
     * 
     * @throws Exception If failed
     */
    @Test
    public void testChannelListenersPropagation() throws Exception {
        Map<String, TestChannelListener> clientListeners = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        addChannelListener(clientListeners, client, new TestChannelListener(client.getClass().getSimpleName()));

        // required since we do not use an SFTP subsystem
        CoreModuleProperties.REQUEST_SUBSYSTEM_REPLY.set(client, false);
        client.start();
        try (ClientSession session = createTestClientSession()) {
            addChannelListener(clientListeners, session, new TestChannelListener(session.getClass().getSimpleName()));
            assertListenerSizes("ClientSessionOpen", clientListeners, 0, 0);

            try (ClientChannel channel = session.createSubsystemChannel(SftpConstants.SFTP_SUBSYSTEM_NAME)) {
                channel.open().verify(OPEN_TIMEOUT);

                TestChannelListener channelListener = new TestChannelListener(channel.getClass().getSimpleName());
                // need to emulate them since we are adding the listener AFTER the channel is open
                channelListener.channelInitialized(channel);
                channelListener.channelOpenSuccess(channel);
                channel.addChannelListener(channelListener);
                assertListenerSizes("ClientChannelOpen", clientListeners, 1, 1);
            }

            assertListenerSizes("ClientChannelClose", clientListeners, 0, 1);
        } finally {
            client.stop();
        }

        assertListenerSizes("ClientStop", clientListeners, 0, 1);
    }

    private static void assertListenerSizes(
            String phase, Map<String, ? extends TestChannelListener> listeners, int activeSize, int openSize) {
        assertListenerSizes(phase, listeners.values(), activeSize, openSize);
    }

    private static void assertListenerSizes(
            String phase, Collection<? extends TestChannelListener> listeners, int activeSize, int openSize) {
        if (GenericUtils.isEmpty(listeners)) {
            return;
        }

        for (TestChannelListener l : listeners) {
            if (activeSize >= 0) {
                assertEquals(phase + ": mismatched active channels size for " + l.getName() + " listener",
                        activeSize, GenericUtils.size(l.getActiveChannels()));
            }

            if (openSize >= 0) {
                assertEquals(phase + ": mismatched open channels size for " + l.getName() + " listener",
                        openSize, GenericUtils.size(l.getOpenChannels()));
            }

            assertEquals(phase + ": unexpected failed channels size for " + l.getName() + " listener",
                    0, GenericUtils.size(l.getFailedChannels()));
        }
    }

    private static <L extends ChannelListener & NamedResource> void addChannelListener(
            Map<String, L> listeners, ChannelListenerManager manager, L listener) {
        String name = listener.getName();
        assertNull("Duplicate listener named " + name, listeners.put(name, listener));
        manager.addChannelListener(listener);
    }

    private ClientSession createTestClientSession() throws IOException {
        ClientSession session = createTestClientSession(TEST_LOCALHOST);
        try {
            InetSocketAddress addr = SshdSocketAddress.toInetSocketAddress(session.getConnectAddress());
            assertEquals("Mismatched connect host", TEST_LOCALHOST, addr.getHostString());

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    private ClientSession createTestClientSession(String host) throws IOException {
        ClientSession session = client.connect(getCurrentTestName(), host, port)
                .verify(CONNECT_TIMEOUT).getSession();
        try {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            InetSocketAddress addr = SshdSocketAddress.toInetSocketAddress(session.getConnectAddress());
            assertNotNull("No reported connect address", addr);
            assertEquals("Mismatched connect port", port, addr.getPort());

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
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
