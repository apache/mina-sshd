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
package org.apache.sshd.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.auth.UserAuth;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.UserAuthPublicKeyFactory;
import org.apache.sshd.client.auth.UserInteraction;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.SubsystemClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.ChannelListenerManager;
import org.apache.sshd.common.channel.TestChannelListener;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.mina.MinaSession;
import org.apache.sshd.common.io.nio2.Nio2Session;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerConnectionServiceFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.server.session.ServerUserAuthServiceFactory;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.AsyncEchoShellFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.apache.sshd.util.test.TeeOutputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientTest extends BaseTestSupport {

    private SshServer sshd;
    private SshClient client;
    private int port;
    private CountDownLatch authLatch;
    private CountDownLatch channelLatch;

    private final AtomicReference<ClientSession> clientSessionHolder = new AtomicReference<ClientSession>(null);
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
                ServerConnectionServiceFactory.INSTANCE
        ));
        sshd.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSessionFactory() {
                    @Override
                    public Channel create() {
                        return new ChannelSession() {
                            @SuppressWarnings("synthetic-access")
                            @Override
                            public OpenFuture open(int recipient, int rwsize, int rmpsize, Buffer buffer) {
                                try {
                                    channelLatch.await();
                                } catch (InterruptedException e) {
                                    throw new RuntimeSshException(e);
                                }
                                return super.open(recipient, rwsize, rmpsize, buffer);
                            }

                            @Override
                            public String toString() {
                                return "ChannelSession" + "[id=" + id + ", recipient=" + recipient + "]";
                            }
                        };
                    }
                },
                DirectTcpipFactory.INSTANCE));
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
        clientSessionHolder.set(null);  // just making sure
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
        clientSessionHolder.set(null);  // just making sure
    }

    @Test
    public void testClientStillActiveIfListenerExceptions() throws Exception {
        final Map<String, Integer> eventsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        final Collection<String> failuresSet = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        final Logger log = LoggerFactory.getLogger(getClass());
        client.addChannelListener(new ChannelListener() {
            @Override
            public void channelOpenSuccess(Channel channel) {
                handleChannelEvent("OpenSuccess", channel);
            }

            @Override
            public void channelOpenFailure(Channel channel, Throwable reason) {
                assertObjectInstanceOf("Mismatched failure reason type", ChannelFailureException.class, reason);

                String name = ((NamedResource) reason).getName();
                synchronized (failuresSet) {
                    assertTrue("Re-signalled failure location: " + name, failuresSet.add(name));
                }
            }

            @Override
            public void channelInitialized(Channel channel) {
                handleChannelEvent("Initialized", channel);
            }

            @Override
            public void channelClosed(Channel channel) {
                handleChannelEvent("Closed", channel);
            }

            private void handleChannelEvent(String name, Channel channel) {
                int id = channel.getId();
                synchronized (eventsMap) {
                    if (eventsMap.put(name, id) != null) {
                        return; // already generated an exception for this event
                    }
                }

                log.info("handleChannelEvent({})[{}]", name, id);
                throw new ChannelFailureException(name);
            }
        });

        client.start();

        try (ClientSession session = createTestClientSession();
             PipedOutputStream pipedIn = new PipedOutputStream();
             InputStream inPipe = new PipedInputStream(pipedIn);
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            // we expect failures either on channel init or open - the one on close is ignored...
            for (int retryCount = 0; retryCount <= 3; retryCount++) {
                try {
                    try(ChannelShell channel = session.createShellChannel()) {
                        channel.setIn(inPipe);
                        channel.setOut(out);
                        channel.setErr(err);
                        channel.open().verify(3L, TimeUnit.SECONDS);
                        break;  // 1st success means all methods have been invoked
                    }
                } catch (IOException e) {
                    synchronized (eventsMap) {
                        eventsMap.remove("Closed"); // since it is called anyway but does not cause an IOException
                        assertTrue("Unexpected failure at retry #" + retryCount, eventsMap.size() < 3);
                    }
                }
            }
        } finally {
            client.stop();
        }

        assertEquals("Mismatched total failures count on test end", 3, eventsMap.size());
        assertEquals("Mismatched open failures count on test end", 1, failuresSet.size());
    }

    @Test
    public void testSimpleClientListener() throws Exception {
        final AtomicReference<Channel> channelHolder = new AtomicReference<>(null);
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
            public void channelClosed(Channel channel) {
                assertSame("Mismatched closed channel instances", channel, channelHolder.getAndSet(null));
            }
        });
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));

        client.start();

        try (final ClientSession session = createTestClientSession()) {
            testClientListener(channelHolder, ChannelShell.class, new Factory<ChannelShell>() {
                @Override
                public ChannelShell create() {
                    try {
                        return session.createShellChannel();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
            testClientListener(channelHolder, ChannelExec.class, new Factory<ChannelExec>() {
                @Override
                public ChannelExec create() {
                    try {
                        return session.createExecChannel(getCurrentTestName());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
            testClientListener(channelHolder, SftpClient.class, new Factory<SftpClient>() {
                @Override
                public SftpClient create() {
                    try {
                        return session.createSftpClient();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        } finally {
            client.stop();
        }
    }

    private <C extends Closeable> void testClientListener(AtomicReference<Channel> channelHolder, Class<C> channelType, Factory<? extends C> factory) throws Exception {
        assertNull(channelType.getSimpleName() + ": Unexpected currently active channel", channelHolder.get());

        try(C instance = factory.create()) {
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
    public void testAsyncClient() throws Exception {
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.WINDOW_SIZE, 1024);
        sshd.setShellFactory(new AsyncEchoShellFactory());

        FactoryManagerUtils.updateProperty(client, FactoryManager.WINDOW_SIZE, 1024);
        client.start();

        try (ClientSession session = createTestClientSession();
             final ChannelShell channel = session.createShellChannel()) {

            channel.setStreaming(ClientChannel.Streaming.Async);
            channel.open().verify(5L, TimeUnit.SECONDS);

            final byte[] message = "0123456789\n".getBytes(StandardCharsets.UTF_8);
            final int nbMessages = 1000;

            try (final ByteArrayOutputStream baosOut = new ByteArrayOutputStream();
                 final ByteArrayOutputStream baosErr = new ByteArrayOutputStream()) {
                 final AtomicInteger writes = new AtomicInteger(nbMessages);

                channel.getAsyncIn().write(new ByteArrayBuffer(message))
                       .addListener(new SshFutureListener<IoWriteFuture>() {
                                @Override
                                public void operationComplete(IoWriteFuture future) {
                                    try {
                                        if (future.isWritten()) {
                                            if (writes.decrementAndGet() > 0) {
                                                channel.getAsyncIn().write(new ByteArrayBuffer(message)).addListener(this);
                                            } else {
                                                channel.getAsyncIn().close(false);
                                            }
                                        } else {
                                            throw new SshException("Error writing", future.getException());
                                        }
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });
                channel.getAsyncOut().read(new ByteArrayBuffer())
                       .addListener(new SshFutureListener<IoReadFuture>() {
                                @Override
                                public void operationComplete(IoReadFuture future) {
                                    try {
                                        future.verify(5L, TimeUnit.SECONDS);
                                        Buffer buffer = future.getBuffer();
                                        baosOut.write(buffer.array(), buffer.rpos(), buffer.available());
                                        buffer.rpos(buffer.rpos() + buffer.available());
                                        buffer.compact();
                                        channel.getAsyncOut().read(buffer).addListener(this);
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });
                channel.getAsyncErr().read(new ByteArrayBuffer())
                       .addListener(new SshFutureListener<IoReadFuture>() {
                                @Override
                                public void operationComplete(IoReadFuture future) {
                                    try {
                                        future.verify(5L, TimeUnit.SECONDS);
                                        Buffer buffer = future.getBuffer();
                                        baosErr.write(buffer.array(), buffer.rpos(), buffer.available());
                                        buffer.rpos(buffer.rpos() + buffer.available());
                                        buffer.compact();
                                        channel.getAsyncErr().read(buffer).addListener(this);
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });

                channel.waitFor(ClientChannel.CLOSED, 0);

                assertEquals("Mismatched sent and received data size", nbMessages * message.length, baosOut.size());
            }

            client.close(true);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testCommandDeadlock() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ChannelExec channel = session.createExecChannel(getCurrentTestName());
             OutputStream stdout = new NoCloseOutputStream(System.out);
             OutputStream stderr = new NoCloseOutputStream(System.err)) {

            channel.setOut(stdout);
            channel.setErr(stderr);
            channel.open().verify(9L, TimeUnit.SECONDS);
            Thread.sleep(125L);
            try {
                byte[] data = "a".getBytes(StandardCharsets.UTF_8);
                OutputStream invertedStream = channel.getInvertedIn();
                for (int i = 0; i < 100; i++) {
                    invertedStream.write(data);
                    invertedStream.flush();
                }
            } catch (SshException e) {
                // That's ok, the channel is being closed by the other side
            }
            assertEquals(ClientChannel.CLOSED, channel.waitFor(ClientChannel.CLOSED, 0) & ClientChannel.CLOSED);
            session.close(false).await();
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClient() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             ByteArrayOutputStream sent = new ByteArrayOutputStream();
             PipedOutputStream pipedIn = new PipedOutputStream();
             PipedInputStream pipedOut = new PipedInputStream(pipedIn)) {

            channel.setIn(pipedOut);

            try (OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open();

                teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                teeOut.flush();

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 1000; i++) {
                    sb.append("0123456789");
                }
                sb.append("\n");
                teeOut.write(sb.toString().getBytes(StandardCharsets.UTF_8));

                teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                teeOut.flush();

                channel.waitFor(ClientChannel.CLOSED, 0);

                channel.close(false);
                client.stop();

                assertArrayEquals("Mismatched sent and received data", sent.toByteArray(), out.toByteArray());
            }
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClientInverted() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             ByteArrayOutputStream sent = new ByteArrayOutputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

            channel.setOut(out);
            channel.setErr(err);
            channel.open().verify(9L, TimeUnit.SECONDS);

            try (OutputStream pipedIn = new TeeOutputStream(sent, channel.getInvertedIn())) {
                pipedIn.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                pipedIn.flush();

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 1000; i++) {
                    sb.append("0123456789");
                }
                sb.append("\n");
                pipedIn.write(sb.toString().getBytes(StandardCharsets.UTF_8));

                pipedIn.write("exit\n".getBytes(StandardCharsets.UTF_8));
                pipedIn.flush();
            }

            channel.waitFor(ClientChannel.CLOSED, 0);

            channel.close(false);
            client.stop();

            assertArrayEquals("Mismatched sent and received data", sent.toByteArray(), out.toByteArray());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClientWithCustomChannel() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ChannelShell channel = new ChannelShell();
             ByteArrayOutputStream sent = new ByteArrayOutputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

            session.getService(ConnectionService.class).registerChannel(channel);
            channel.setOut(out);
            channel.setErr(err);
            channel.open().verify(5L, TimeUnit.SECONDS);
            channel.close(false).await();
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClientClosingStream() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             ByteArrayOutputStream sent = new ByteArrayOutputStream();
             PipedOutputStream pipedIn = new PipedOutputStream();
             InputStream inPipe = new PipedInputStream(pipedIn);
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

            channel.setIn(inPipe);
            channel.setOut(out);
            channel.setErr(err);
            channel.open();

            try (OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {
                teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                teeOut.flush();

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 1000; i++) {
                    sb.append("0123456789");
                }
                sb.append("\n");
                teeOut.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            }

            channel.waitFor(ClientChannel.CLOSED, 0);

            channel.close(false);
            client.stop();

            assertArrayEquals("Mismatched sent and received data", sent.toByteArray(), out.toByteArray());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClientWithLengthyDialog() throws Exception {
        // Reduce window size and packet size
//        FactoryManagerUtils.updateProperty(client, SshClient.WINDOW_SIZE, 0x20000);
//        FactoryManagerUtils.updateProperty(client, SshClient.MAX_PACKET_SIZE, 0x1000);
//        FactoryManagerUtils.updateProperty(sshd, SshServer.WINDOW_SIZE, 0x20000);
//        FactoryManagerUtils.updateProperty(sshd, SshServer.MAX_PACKET_SIZE, 0x1000);
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             ByteArrayOutputStream sent = new ByteArrayOutputStream();
             PipedOutputStream pipedIn = new PipedOutputStream();
             InputStream inPipe = new PipedInputStream(pipedIn);
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

            channel.setIn(inPipe);
            channel.setOut(out);
            channel.setErr(err);
            channel.open().verify(9L, TimeUnit.SECONDS);

            int bytes = 0;
            byte[] data = "01234567890123456789012345678901234567890123456789\n".getBytes(StandardCharsets.UTF_8);
            long t0 = System.currentTimeMillis();
            try (OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {
                for (int i = 0; i < 10000; i++) {
                    teeOut.write(data);
                    teeOut.flush();
                    bytes += data.length;
                    if ((bytes & 0xFFF00000) != ((bytes - data.length) & 0xFFF00000)) {
                        System.out.println("Bytes written: " + bytes);
                    }
                }
                teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                teeOut.flush();
            }

            long t1 = System.currentTimeMillis();
            System.out.println("Sent " + (bytes / 1024) + " Kb in " + (t1 - t0) + " ms");

            System.out.println("Waiting for channel to be closed");
            channel.waitFor(ClientChannel.CLOSED, 0);
            channel.close(false);
            client.stop();

            assertArrayEquals("Mismatched sent and received data", sent.toByteArray(), out.toByteArray());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test(expected = SshException.class)
    public void testOpenChannelOnClosedSession() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel()) {

            session.close(false);
            assertNull("Session closure not signalled", clientSessionHolder.get());

            try (PipedOutputStream pipedIn = new PipedOutputStream();
                 InputStream inPipe = new PipedInputStream(pipedIn);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setIn(inPipe);
                channel.setOut(out);
                channel.setErr(err);
                channel.open();
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testCloseBeforeAuthSucceed() throws Exception {
        authLatch = new CountDownLatch(1);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPasswordIdentity(getCurrentTestName());

            AuthFuture authFuture = session.auth();
            CloseFuture closeFuture = session.close(false);

            authLatch.countDown();
            assertTrue("Authentication writing not completed in time", authFuture.await(11L, TimeUnit.SECONDS));
            assertTrue("Session closing not complete in time", closeFuture.await(8L, TimeUnit.SECONDS));
            assertNotNull("No authentication exception", authFuture.getException());
            assertTrue("Future not closed", closeFuture.isClosed());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testCloseCleanBeforeChannelOpened() throws Exception {
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             InputStream inp = new ByteArrayInputStream(GenericUtils.EMPTY_BYTE_ARRAY);
             OutputStream out = new ByteArrayOutputStream();
             OutputStream err = new ByteArrayOutputStream()) {

            channel.setIn(inp);
            channel.setOut(out);
            channel.setErr(err);

            OpenFuture openFuture = channel.open();
            CloseFuture closeFuture = session.close(false);
            assertTrue("Channel not open in time", openFuture.await(11L, TimeUnit.SECONDS));
            assertTrue("Session closing not complete in time", closeFuture.await(8L, TimeUnit.SECONDS));
            assertTrue("Not open", openFuture.isOpened());
            assertTrue("Not closed", closeFuture.isClosed());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testCloseImmediateBeforeChannelOpened() throws Exception {
        channelLatch = new CountDownLatch(1);
        client.start();

        try (ClientSession session = createTestClientSession();
             ClientChannel channel = session.createShellChannel();
             InputStream inp = new ByteArrayInputStream(GenericUtils.EMPTY_BYTE_ARRAY);
             OutputStream out = new ByteArrayOutputStream();
             OutputStream err = new ByteArrayOutputStream()) {

            channel.setIn(inp);
            channel.setOut(out);
            channel.setErr(err);

            OpenFuture openFuture = channel.open();
            CloseFuture closeFuture = session.close(true);
            assertNull("Session closure not signalled", clientSessionHolder.get());

            channelLatch.countDown();
            assertTrue("Channel not open in time", openFuture.await(11L, TimeUnit.SECONDS));
            assertTrue("Session closing not complete in time", closeFuture.await(8L, TimeUnit.SECONDS));
            assertNotNull("No open exception", openFuture.getException());
            assertTrue("Not closed", closeFuture.isClosed());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPublicKeyAuth() throws Exception {
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
            session.addPublicKeyIdentity(pair);
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testPublicKeyAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthPublicKeyFactory.INSTANCE));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPublicKeyIdentity(createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA));
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testPublicKeyAuthNewWithFailureOnFirstIdentity() throws Exception {
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm("RSA");

        final KeyPair pair = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return key.equals(pair.getPublic());
            }
        });
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthPublicKeyFactory.INSTANCE));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPublicKeyIdentity(provider.loadKey(KeyPairProvider.SSH_RSA));
            session.addPublicKeyIdentity(pair);
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testPasswordAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPasswordFactory()));
        client.start();

        try (ClientSession session = createTestClientSession()) {
            // nothing extra
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testPasswordAuthNewWithFailureOnFirstIdentity() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPasswordFactory()));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPasswordIdentity(getClass().getSimpleName());
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testKeyboardInteractiveAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();

        try (ClientSession session = createTestClientSession()) {
            // nothing extra
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testKeyboardInteractiveAuthNewWithFailureOnFirstIdentity() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPasswordIdentity(getClass().getSimpleName());
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test   // see SSHD-504
    public void testKeyboardInteractivePasswordPromptLocationIndependence() throws Exception {
        final Collection<String> mismatchedPrompts = new LinkedList<String>();
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthKeyboardInteractiveFactory() {
            @Override
            public UserAuth create() {
                return new UserAuthKeyboardInteractive() {
                    @Override
                    protected boolean useCurrentPassword(String password, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                        boolean expected = GenericUtils.length(password) > 0;
                        boolean actual = super.useCurrentPassword(password, name, instruction, lang, prompt, echo);
                        if (expected != actual) {
                            System.err.println("Mismatched usage result for prompt=" + prompt[0] + ": expected=" + expected + ", actual=actual");
                            mismatchedPrompts.add(prompt[0]);
                        }
                        return actual;
                    }
                };
            }
        }));
        client.start();

        final Transformer<String, String> stripper = new Transformer<String, String>() {
            @Override
            public String transform(String input) {
                int pos = GenericUtils.isEmpty(input) ? (-1) : input.lastIndexOf(':');
                if (pos < 0) {
                    return input;
                } else {
                    return input.substring(0, pos);
                }
            }
        };
        final List<Transformer<String, String>> xformers =
                Collections.unmodifiableList(Arrays.<Transformer<String, String>>asList(
                        new Transformer<String, String>() {  // prefixed
                            @Override
                            public String transform(String input) {
                                return getCurrentTestName() + " " + input;
                            }
                        },
                        new Transformer<String, String>() {  // suffixed
                            @Override
                            public String transform(String input) {
                                return stripper.transform(input) + " " + getCurrentTestName() + ":";
                            }
                        },
                        new Transformer<String, String>() {  // infix
                            @Override
                            public String transform(String input) {
                                return getCurrentTestName() + " " + stripper.transform(input) + " " + getCurrentTestName() + ":";
                            }
                        }
                ));
        sshd.setUserAuthFactories(Arrays.<NamedFactory<org.apache.sshd.server.auth.UserAuth>>asList(
                new org.apache.sshd.server.auth.UserAuthKeyboardInteractiveFactory() {
                    private int xformerIndex;

                    @Override
                    public org.apache.sshd.server.auth.UserAuth create() {
                        return new org.apache.sshd.server.auth.UserAuthKeyboardInteractive() {

                            @SuppressWarnings("synthetic-access")
                            @Override
                            protected String getInteractionPrompt() {
                                String original = super.getInteractionPrompt();
                                if (xformerIndex < xformers.size()) {
                                    Transformer<String, String> x = xformers.get(xformerIndex);
                                    xformerIndex++;
                                    return x.transform(original);
                                } else {
                                    return original;
                                }
                            }
                        };
                    }
                }));

        try {
            for (int index = 0; index < xformers.size(); index++) {
                try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7, TimeUnit.SECONDS).getSession()) {
                    assertNotNull("Client session creation not signalled at iteration #" + index, clientSessionHolder.get());
                    String password = "bad-" + getCurrentTestName() + "-" + index;
                    session.addPasswordIdentity(password);

                    AuthFuture future = session.auth();
                    assertTrue("Failed to verify password=" + password + " in time", future.await(5L, TimeUnit.SECONDS));
                    assertFalse("Unexpected success for password=" + password, future.isSuccess());
                    session.removePasswordIdentity(password);
                }

                assertNull("Session closure not signalled at iteration #" + index, clientSessionHolder.get());
            }

            try (ClientSession session = createTestClientSession()) {
                assertTrue("Mismatched prompts evaluation results", mismatchedPrompts.isEmpty());
            }

            assertNull("Final session closure not signalled", clientSessionHolder.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveWithFailures() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);

        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthKeyboardInteractiveFactory()));
        client.setUserInteraction(new UserInteraction() {
            @Override
            public void welcome(String banner) {
                // ignored
            }

            @Override
            public String[] interactive(String destination, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                count.incrementAndGet();
                return new String[]{"bad"};
            }
        });
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());

            AuthFuture future = session.auth();
            future.await();
            assertTrue("Unexpected authentication success", future.isFailure());
            assertEquals("Mismatched authentication retry count", MAX_PROMPTS, count.get());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testKeyboardInteractiveInSessionUserInteractive() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);

        client.setUserAuthFactories(Arrays
                .<NamedFactory<UserAuth>>asList(UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(String banner) {
                    // ignored
                }

                @Override
                public String[] interactive(String destination, String name, String instruction, String lang,
                                            String[] prompt, boolean[] echo) {
                    count.incrementAndGet();
                    return new String[]{getCurrentTestName()};
                }
            });

            AuthFuture future = session.auth();
            future.await();
            assertTrue("Authentication not marked as success", future.isSuccess());
            assertFalse("Authentication marked as failure", future.isFailure());
            assertEquals("Mismatched authentication attempts count", 1, count.get());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testKeyboardInteractiveInSessionUserInteractiveFailure() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);
        client.setUserAuthFactories(Arrays
                .<NamedFactory<UserAuth>>asList(new UserAuthKeyboardInteractiveFactory()));
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(String banner) {
                    // ignored
                }

                @Override
                public String[] interactive(String destination, String name, String instruction, String lang,
                                            String[] prompt, boolean[] echo) {
                    int attemptId = count.incrementAndGet();
                    return new String[]{"bad#" + attemptId};
                }
            });

            AuthFuture future = session.auth();
            assertTrue("Authentication not completed in time", future.await(11L, TimeUnit.SECONDS));
            assertTrue("Authentication not, marked as failure", future.isFailure());
            assertEquals("Mismatched authentication retry count", MAX_PROMPTS, count.get());
        } finally {
            client.stop();
        }

        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testClientDisconnect() throws Exception {
        TestEchoShell.latch = new CountDownLatch(1);
        try {
            client.start();

            try (ClientSession session = createTestClientSession();
                 ClientChannel channel = session.createShellChannel();
                 PipedOutputStream pipedIn = new PipedOutputStream();
                 InputStream inPipe = new PipedInputStream(pipedIn);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setIn(inPipe);
                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(9L, TimeUnit.SECONDS);

                //            ((AbstractSession) session).disconnect(SshConstants.SSH2_DISCONNECT_BY_APPLICATION, "Cancel");
                AbstractSession cs = (AbstractSession) session;
                Buffer buffer = cs.createBuffer(SshConstants.SSH_MSG_DISCONNECT);
                buffer.putInt(SshConstants.SSH2_DISCONNECT_BY_APPLICATION);
                buffer.putString("Cancel");
                buffer.putString("");

                IoWriteFuture f = cs.writePacket(buffer);
                assertTrue("Packet writing not completed in time", f.await(11L, TimeUnit.SECONDS));
                suspend(cs.getIoSession());

                TestEchoShell.latch.await();
            } finally {
                client.stop();
            }

            assertNull("Session closure not signalled", clientSessionHolder.get());
        } finally {
            TestEchoShell.latch = null;
        }
    }

    @Test
    public void testWaitAuth() throws Exception {
        final AtomicBoolean ok = new AtomicBoolean();
        client.setServerKeyVerifier(
                new ServerKeyVerifier() {
                    @Override
                    public boolean verifyServerKey(
                            ClientSession sshClientSession,
                            SocketAddress remoteAddress,
                            PublicKey serverKey
                    ) {
                        System.out.println(serverKey);
                        ok.set(true);
                        return true;
                    }
                }
        );
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.waitFor(ClientSession.WAIT_AUTH, TimeUnit.SECONDS.toMillis(10L));
            assertTrue("Server key verifier invoked ?", ok.get());
        } finally {
            client.stop();
        }
        assertNull("Session closure not signalled", clientSessionHolder.get());
    }

    @Test
    public void testCreateChannelByType() throws Exception {
        client.start();

        Collection<ClientChannel> channels = new LinkedList<>();
        try (ClientSession session = createTestClientSession()) {
            channels.add(session.createChannel(ClientChannel.CHANNEL_SUBSYSTEM, SftpConstants.SFTP_SUBSYSTEM_NAME));
            channels.add(session.createChannel(ClientChannel.CHANNEL_EXEC, getCurrentTestName()));
            channels.add(session.createChannel(ClientChannel.CHANNEL_SHELL, getClass().getSimpleName()));

            Set<Integer> ids = new HashSet<Integer>(channels.size());
            for (ClientChannel c : channels) {
                int id = ((AbstractChannel) c).getId();
                assertTrue("Channel ID repeated: " + id, ids.add(Integer.valueOf(id)));
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
     * Makes sure that the {@link ChannelListener}s added to the client, session
     * and channel are <U>cumulative</U> - i.e., all of them invoked
     * @throws Exception If failed
     */
    @Test
    public void testChannelListenersPropagation() throws Exception {
        Map<String,TestChannelListener> clientListeners = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        addChannelListener(clientListeners, client, new TestChannelListener(client.getClass().getSimpleName()));

        client.start();
        try (ClientSession session = createTestClientSession()) {
            addChannelListener(clientListeners, session, new TestChannelListener(session.getClass().getSimpleName()));
            assertListenerSizes("ClientSessionOpen", clientListeners, 0, 0);

            try (ClientChannel channel = session.createSubsystemChannel(SftpConstants.SFTP_SUBSYSTEM_NAME)) {
                channel.open().verify(5L, TimeUnit.SECONDS);

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

    private static void assertListenerSizes(String phase, Map<String,? extends TestChannelListener> listeners, int activeSize, int openSize) {
        assertListenerSizes(phase, listeners.values(), activeSize, openSize);
    }

    private static void assertListenerSizes(String phase, Collection<? extends TestChannelListener> listeners, int activeSize, int openSize) {
        if (GenericUtils.isEmpty(listeners)) {
            return;
        }

        for (TestChannelListener l : listeners) {
            if (activeSize >= 0) {
                assertEquals(phase + ": mismatched active channels size for " + l.getName() + " listener", activeSize, GenericUtils.size(l.getActiveChannels()));
            }

            if (openSize >= 0) {
                assertEquals(phase + ": mismatched open channels size for " + l.getName() + " listener", openSize, GenericUtils.size(l.getOpenChannels()));
            }

            assertEquals(phase + ": unexpected failed channels size for " + l.getName() + " listener", 0, GenericUtils.size(l.getFailedChannels()));
        }
    }

    private static <L extends ChannelListener & NamedResource> void addChannelListener(Map<String,L> listeners, ChannelListenerManager manager, L listener) {
        String name = listener.getName();
        assertNull("Duplicate listener named " + name, listeners.put(name, listener));
        manager.addChannelListener(listener);
    }

    private ClientSession createTestClientSession() throws IOException {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
        try {
            assertNotNull("Client session creation not signalled", clientSessionHolder.get());
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            ClientSession returnValue = session;
            session = null; // avoid 'finally' close
            return returnValue;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    private void suspend(IoSession ioSession) {
        if (ioSession instanceof MinaSession) {
            ((MinaSession) ioSession).suspend();
        } else {
            ((Nio2Session) ioSession).suspend();
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

    public static class ChannelFailureException extends RuntimeException implements NamedResource {
        private static final long serialVersionUID = 1L;    // we're not serializing it
        private final String name;

        public ChannelFailureException(String name) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No event name provided");
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    public static void main(String[] args) throws Exception {
        SshClient.main(args);
    }
}
