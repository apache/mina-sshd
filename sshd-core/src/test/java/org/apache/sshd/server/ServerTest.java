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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StreamCorruptedException;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.TestChannelListener;
import org.apache.sshd.common.channel.WindowClosedException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.deprecated.ClientUserAuthServiceOld;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.apache.sshd.util.test.Utils;
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
public class ServerTest extends BaseTestSupport {

    private SshServer sshd;
    private SshClient client;
    private int port;

    public ServerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setShellFactory(new TestEchoShellFactory());
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

    /**
     * Send bad password.  The server should disconnect after a few attempts
     *
     * @throws Exception
     */
    @Test
    public void testFailAuthenticationWithWaitFor() throws Exception {
        final int MAX_AUTH_REQUESTS = 10;
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.MAX_AUTH_REQUESTS, MAX_AUTH_REQUESTS);

        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();

        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            int nbTrials = 0;
            Collection<ClientSession.ClientSessionEvent> res = Collections.emptySet();
            Collection<ClientSession.ClientSessionEvent> mask =
                    EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH);
            while (!res.contains(ClientSession.ClientSessionEvent.CLOSED)) {
                nbTrials++;
                s.getService(ClientUserAuthServiceOld.class)
                        .auth(new org.apache.sshd.deprecated.UserAuthPassword(s, "ssh-connection", "buggy"));
                res = s.waitFor(mask, TimeUnit.SECONDS.toMillis(5L));
                assertFalse("Timeout signalled", res.contains(ClientSession.ClientSessionEvent.TIMEOUT));
            }
            assertTrue("Number trials (" + nbTrials + ") below min.=" + MAX_AUTH_REQUESTS, nbTrials > MAX_AUTH_REQUESTS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testFailAuthenticationWithFuture() throws Exception {
        final int MAX_AUTH_REQUESTS = 10;
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.MAX_AUTH_REQUESTS, MAX_AUTH_REQUESTS);

        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            int nbTrials = 0;
            AuthFuture authFuture;
            do {
                nbTrials++;
                assertTrue("Number of trials below max.", nbTrials < 100);
                authFuture = s.getService(ClientUserAuthServiceOld.class)
                        .auth(new org.apache.sshd.deprecated.UserAuthPassword(s, "ssh-connection", "buggy"));
                assertTrue("Authentication wait failed", authFuture.await(5L, TimeUnit.SECONDS));
                assertTrue("Authentication not done", authFuture.isDone());
                assertFalse("Authentication unexpectedly successful", authFuture.isSuccess());
            } while (authFuture.getException() == null);

            assertNotNull("Missing auth future exception", authFuture.getException());
            assertTrue("Number trials (" + nbTrials + ") below min.=" + MAX_AUTH_REQUESTS, nbTrials > MAX_AUTH_REQUESTS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        final long AUTH_TIMEOUT = TimeUnit.SECONDS.toMillis(5L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.AUTH_TIMEOUT, AUTH_TIMEOUT);

        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            Collection<ClientSession.ClientSessionEvent> res = s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), 2L * AUTH_TIMEOUT);
            assertTrue("Session should be closed: " + res,
                       res.containsAll(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.WAIT_AUTH)));
        } finally {
            client.stop();
        }
    }

    @Test
    public void testIdleTimeout() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);
        TestEchoShell.latch = new CountDownLatch(1);
        final long IDLE_TIMEOUT = 2500;
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, IDLE_TIMEOUT);

        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                System.out.println("Session created");
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                System.out.println("Session event: " + event);
            }

            @Override
            public void sessionClosed(Session session) {
                System.out.println("Session closed");
                latch.countDown();
            }
        });

        TestChannelListener channelListener = new TestChannelListener();
        sshd.addChannelListener(channelListener);

        client.start();
        try (ClientSession s = createTestClientSession();
             ChannelShell shell = s.createShellChannel();
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            shell.setOut(out);
            shell.setErr(err);
            shell.open().verify(9L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            Collection<ClientSession.ClientSessionEvent> res =
                    s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), 2L * IDLE_TIMEOUT);
            assertTrue("Session should be closed and authenticated: " + res,
                       res.containsAll(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED, ClientSession.ClientSessionEvent.AUTHED)));
        } finally {
            client.stop();
        }

        assertTrue("Session latch not signalled in time", latch.await(1L, TimeUnit.SECONDS));
        assertTrue("Shell latch not signalled in time", TestEchoShell.latch.await(1L, TimeUnit.SECONDS));
    }

    /*
     * The scenario is the following:
     * - create a command that sends continuous data to the client
     * - the client does not read the data, filling the ssh window and the tcp socket
     * - the server session becomes idle, but the ssh disconnect message can't be written
     * - the server session is forcibly closed
     */
    @Test
    public void testServerIdleTimeoutWithForce() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);

        sshd.setCommandFactory(new StreamCommand.Factory());

        final long IDLE_TIMEOUT_VALUE = TimeUnit.SECONDS.toMillis(5L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, IDLE_TIMEOUT_VALUE);

        final long DISCONNECT_TIMEOUT_VALUE = TimeUnit.SECONDS.toMillis(2L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.DISCONNECT_TIMEOUT, DISCONNECT_TIMEOUT_VALUE);

        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                System.out.println("Session created");
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                System.out.println("Session event: " + event);
            }

            @Override
            public void sessionClosed(Session session) {
                System.out.println("Session closed");
                latch.countDown();
            }
        });

        TestChannelListener channelListener = new TestChannelListener();
        sshd.addChannelListener(channelListener);

        client.start();

        try (ClientSession s = createTestClientSession();
             ChannelExec shell = s.createExecChannel("normal");
             // Create a pipe that will block reading when the buffer is full
             PipedInputStream pis = new PipedInputStream();
             PipedOutputStream pos = new PipedOutputStream(pis)) {

            shell.setOut(pos);
            shell.open().verify(5L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            try (AbstractSession serverSession = sshd.getActiveSessions().iterator().next();
                 Channel channel = serverSession.getService(AbstractConnectionService.class).getChannels().iterator().next()) {

                final long MAX_TIMEOUT_VALUE = IDLE_TIMEOUT_VALUE + DISCONNECT_TIMEOUT_VALUE + TimeUnit.SECONDS.toMillis(3L);
                for (long totalNanoTime = 0L; channel.getRemoteWindow().getSize() > 0; ) {
                    long nanoStart = System.nanoTime();
                    Thread.sleep(1L);
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;

                    totalNanoTime += nanoDuration;
                    assertTrue("Waiting for too long on remote window size to reach zero", totalNanoTime < TimeUnit.MILLISECONDS.toNanos(MAX_TIMEOUT_VALUE));
                }

                LoggerFactory.getLogger(getClass()).info("Waiting for session idle timeouts");

                long t0 = System.currentTimeMillis();
                latch.await(1, TimeUnit.MINUTES);
                long t1 = System.currentTimeMillis(), diff = t1 - t0;
                assertTrue("Wait time too low: " + diff, diff > IDLE_TIMEOUT_VALUE);
                assertTrue("Wait time too high: " + diff, diff < MAX_TIMEOUT_VALUE);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testLanguageNegotiation() throws Exception {
        client.setSessionFactory(new SessionFactory(client) {
            @Override
            @SuppressWarnings("synthetic-access")
            protected ClientSessionImpl createSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(client, ioSession) {
                    @Override
                    protected Map<KexProposalOption, String> createProposal(String hostKeyTypes) {
                        Map<KexProposalOption, String> proposal = super.createProposal(hostKeyTypes);
                        proposal.put(KexProposalOption.S2CLANG, "en-US");
                        proposal.put(KexProposalOption.C2SLANG, "en-US");
                        return proposal;
                    }
                };
            }
        });

        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            // do nothing
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKexCompletedEvent() throws Exception {
        final AtomicInteger serverEventCount = new AtomicInteger(0);
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if (event == Event.KexCompleted) {
                    serverEventCount.incrementAndGet();
                }
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });

        client.start();
        final AtomicInteger clientEventCount = new AtomicInteger(0);
        client.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if (event == Event.KexCompleted) {
                    clientEventCount.incrementAndGet();
                }
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });

        try (ClientSession s = createTestClientSession()) {
            assertEquals("Mismatched client events count", 1, clientEventCount.get());
            assertEquals("Mismatched server events count", 1, serverEventCount.get());
            s.close(false);
        } finally {
            client.stop();
        }
    }

    @Test   // see https://issues.apache.org/jira/browse/SSHD-456
    public void testServerStillListensIfSessionListenerThrowsException() throws Exception {
        final Map<String, SocketAddress> eventsMap = new TreeMap<String, SocketAddress>(String.CASE_INSENSITIVE_ORDER);
        final Logger log = LoggerFactory.getLogger(getClass());
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                throwException("SessionCreated", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                throwException("SessionEvent", session);
            }

            @Override
            public void sessionClosed(Session session) {
                throwException("SessionClosed", session);
            }

            private void throwException(String phase, Session session) {
                IoSession ioSession = session.getIoSession();
                SocketAddress addr = ioSession.getRemoteAddress();
                synchronized (eventsMap) {
                    if (eventsMap.put(phase, addr) != null) {
                        return; // already generated an event for this phase
                    }
                }

                RuntimeException e = new RuntimeException("Synthetic exception at phase=" + phase + ": " + addr);
                log.info(e.getMessage());
                throw e;
            }
        });

        client.start();

        int curCount = 0;
        for (int retryCount = 0; retryCount < Byte.SIZE; retryCount++) {
            synchronized (eventsMap) {
                if ((curCount = eventsMap.size()) >= 3) {
                    return;
                }
            }

            try {
                try (ClientSession s = createTestClientSession()) {
                    log.info("Retry #" + retryCount + " successful");
                }

                synchronized (eventsMap) {
                    assertTrue("Unexpected premature success at retry # " + retryCount + ": " + eventsMap, eventsMap.size() >= 3);
                }
            } catch (IOException e) {
                // expected - ignored
                synchronized (eventsMap) {
                    int nextCount = eventsMap.size();
                    assertTrue("No session event generated at retry #" + retryCount, nextCount > curCount);
                }
            }
        }

        fail("No success to authenticate");
    }

    @Test
    public void testEnvironmentVariablesPropagationToServer() throws Exception {
        final AtomicReference<Environment> envHolder = new AtomicReference<Environment>(null);
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public Command createCommand(final String command) {
                ValidateUtils.checkTrue(String.CASE_INSENSITIVE_ORDER.compare(command, getCurrentTestName()) == 0, "Unexpected command: %s", command);

                return new Command() {
                    private ExitCallback cb;

                    @Override
                    public void setOutputStream(OutputStream out) {
                        // ignored
                    }

                    @Override
                    public void setInputStream(InputStream in) {
                        // ignored
                    }

                    @Override
                    public void setExitCallback(ExitCallback callback) {
                        cb = callback;
                    }

                    @Override
                    public void setErrorStream(OutputStream err) {
                        // ignored
                    }

                    @Override
                    public void destroy() {
                        // ignored
                    }

                    @Override
                    public void start(Environment env) throws IOException {
                        if (envHolder.getAndSet(env) != null) {
                            throw new StreamCorruptedException("Multiple starts for command=" + command);
                        }

                        cb.onExit(0, command);
                    }
                };
            }
        });

        TestChannelListener channelListener = new TestChannelListener();
        sshd.addChannelListener(channelListener);

        @SuppressWarnings("synthetic-access")
        Map<String, String> expected = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                put("test", getCurrentTestName());
                put("port", Integer.toString(port));
                put("user", System.getProperty("user.name"));
            }
        };

        client.start();
        try (ClientSession s = createTestClientSession();
             ChannelExec shell = s.createExecChannel(getCurrentTestName())) {
            for (Map.Entry<String, String> ee : expected.entrySet()) {
                shell.setEnv(ee.getKey(), ee.getValue());
            }

            shell.open().verify(5L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            Collection<ClientChannel.ClientChannelEvent> result =
                    shell.waitFor(EnumSet.of(ClientChannel.ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(17L));
            assertFalse("Channel close timeout", result.contains(ClientChannel.ClientChannelEvent.TIMEOUT));

            Integer status = shell.getExitStatus();
            assertNotNull("No exit status", status);
            assertEquals("Bad exit status", 0, status.intValue());
        } finally {
            client.stop();
        }

        assertTrue("No changes in closed channels", channelListener.waitForModification(3L, TimeUnit.SECONDS));
        assertTrue("Still activated server side channels", GenericUtils.isEmpty(channelListener.getActiveChannels()));

        Environment cmdEnv = envHolder.get();
        assertNotNull("No environment set", cmdEnv);

        Map<String, String> vars = cmdEnv.getEnv();
        assertTrue("Mismatched vars count", GenericUtils.size(vars) >= GenericUtils.size(expected));
        for (Map.Entry<String, String> ee : expected.entrySet()) {
            String key = ee.getKey(), expValue = ee.getValue(), actValue = vars.get(key);
            assertEquals("Mismatched value for " + key, expValue, actValue);
        }
    }

    private ClientSession createTestClientSession() throws Exception {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession();
        try {
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

    public static class TestEchoShellFactory extends EchoShellFactory {
        public TestEchoShellFactory() {
            super();
        }

        @Override
        public Command create() {
            return new TestEchoShell();
        }
    }

    public static class TestEchoShell extends EchoShell {

        public static CountDownLatch latch;

        public TestEchoShell() {
            super();
        }

        @Override
        public void destroy() {
            if (latch != null) {
                latch.countDown();
            }
            super.destroy();
        }
    }

    public static class StreamCommand implements Command, Runnable {

        public static class Factory implements CommandFactory {
            @Override
            public Command createCommand(String name) {
                return new StreamCommand(name);
            }
        }

        public static CountDownLatch latch;

        private final String name;
        private OutputStream out;

        public StreamCommand(String name) {
            this.name = name;
        }

        @Override
        public void setInputStream(InputStream in) {
            // ignored
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
            // ignored
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            // ignored
        }

        @Override
        public void start(Environment env) throws IOException {
            new Thread(this).start();
        }

        @Override
        public void destroy() {
            synchronized (name) {
                if ("block".equals(name)) {
                    try {
                        name.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        @Override
        public void run() {
            try {
                Thread.sleep(TimeUnit.SECONDS.toMillis(5L));
                while (true) {
                    byte[] data = "0123456789\n".getBytes(StandardCharsets.UTF_8);
                    for (int i = 0; i < 100; i++) {
                        out.write(data);
                    }
                    out.flush();
                }
            } catch (WindowClosedException e) {
                // ok, do nothing
            } catch (Throwable e) {
                e.printStackTrace();
            } finally {
                if (latch != null) {
                    latch.countDown();
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SshServer sshd = Utils.setupTestServer(ServerTest.class);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TimeUnit.SECONDS.toMillis(10L));
        sshd.setPort(8001);
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.start();
        Thread.sleep(100000);
    }
}
