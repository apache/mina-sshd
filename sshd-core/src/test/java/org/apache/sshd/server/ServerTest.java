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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.ClientAuthenticationManager;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.TestChannelListener;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.channel.WindowClosedException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.helpers.AbstractConnectionService;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.deprecated.ClientUserAuthServiceOld;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.PromptEntry;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionImpl;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
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

    public ServerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setShellFactory(new TestEchoShellFactory());
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

    /*
     * Send bad password.  The server should disconnect after a few attempts
     */
    @Test
    public void testFailAuthenticationWithWaitFor() throws Exception {
        final int maxAllowedAuths = 10;
        PropertyResolverUtils.updateProperty(sshd, ServerAuthenticationManager.MAX_AUTH_REQUESTS, maxAllowedAuths);

        sshd.start();
        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();

        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
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
            assertTrue("Number trials (" + nbTrials + ") below min.=" + maxAllowedAuths, nbTrials > maxAllowedAuths);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testFailAuthenticationWithFuture() throws Exception {
        final int maxAllowedAuths = 10;
        PropertyResolverUtils.updateProperty(sshd, ServerAuthenticationManager.MAX_AUTH_REQUESTS, maxAllowedAuths);

        sshd.start();

        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
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

            Throwable t = authFuture.getException();
            assertNotNull("Missing auth future exception", t);
            assertTrue("Number trials (" + nbTrials + ") below min.=" + maxAllowedAuths, nbTrials > maxAllowedAuths);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        final long testAuthTimeout = TimeUnit.SECONDS.toMillis(5L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.AUTH_TIMEOUT, testAuthTimeout);

        sshd.start();
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            Collection<ClientSession.ClientSessionEvent> res = s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), 2L * testAuthTimeout);
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
        final long testIdleTimeout = 2500L;
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, testIdleTimeout);

        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                outputDebugMessage("Session created: %s", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                outputDebugMessage("Session %s event: ", session, event);
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                outputDebugMessage("Session %s exception %s caught: %s", session, t.getClass().getSimpleName(), t.getMessage());
            }

            @Override
            public void sessionClosed(Session session) {
                outputDebugMessage("Session closed: %s", session);
                latch.countDown();
            }
        });

        TestChannelListener channelListener = new TestChannelListener();
        sshd.addChannelListener(channelListener);
        sshd.start();

        client.start();
        try (ClientSession s = createTestClientSession(sshd);
             ChannelShell shell = s.createShellChannel();
             ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            shell.setOut(out);
            shell.setErr(err);
            shell.open().verify(9L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            Collection<ClientSession.ClientSessionEvent> res =
                    s.waitFor(EnumSet.of(ClientSession.ClientSessionEvent.CLOSED), 2L * testIdleTimeout);
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

        final long idleTimeoutValue = TimeUnit.SECONDS.toMillis(5L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, idleTimeoutValue);

        final long disconnectTimeoutValue = TimeUnit.SECONDS.toMillis(2L);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.DISCONNECT_TIMEOUT, disconnectTimeoutValue);

        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                outputDebugMessage("Session created: %s", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                outputDebugMessage("Session %s event: %s", session, event);
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                outputDebugMessage("Session %s exception %s caught: %s", session, t.getClass().getSimpleName(), t.getMessage());
            }

            @Override
            public void sessionClosed(Session session) {
                outputDebugMessage("Session closed: %s", session);
                latch.countDown();
            }
        });

        TestChannelListener channelListener = new TestChannelListener();
        sshd.addChannelListener(channelListener);
        sshd.start();

        client.start();
        try (ClientSession s = createTestClientSession(sshd);
             ChannelExec shell = s.createExecChannel("normal");
             // Create a pipe that will block reading when the buffer is full
             PipedInputStream pis = new PipedInputStream();
             PipedOutputStream pos = new PipedOutputStream(pis)) {

            shell.setOut(pos);
            shell.open().verify(5L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            try (AbstractSession serverSession = sshd.getActiveSessions().iterator().next()) {
                AbstractConnectionService<?> service = serverSession.getService(AbstractConnectionService.class);
                Collection<? extends Channel> channels = service.getChannels();

                try (Channel channel = channels.iterator().next()) {
                    final long maxTimeoutValue = idleTimeoutValue + disconnectTimeoutValue + TimeUnit.SECONDS.toMillis(3L);
                    final long maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(maxTimeoutValue);
                    Window wRemote = channel.getRemoteWindow();
                    for (long totalNanoTime = 0L; wRemote.getSize() > 0;) {
                        long nanoStart = System.nanoTime();
                        Thread.sleep(1L);
                        long nanoEnd = System.nanoTime();
                        long nanoDuration = nanoEnd - nanoStart;

                        totalNanoTime += nanoDuration;
                        assertTrue("Waiting for too long on remote window size to reach zero", totalNanoTime < maxWaitNanos);
                    }

                    LoggerFactory.getLogger(getClass()).info("Waiting for session idle timeouts");

                    long t0 = System.currentTimeMillis();
                    latch.await(1L, TimeUnit.MINUTES);
                    long t1 = System.currentTimeMillis();
                    long diff = t1 - t0;
                    assertTrue("Wait time too low: " + diff, diff > idleTimeoutValue);
                    assertTrue("Wait time too high: " + diff, diff < maxTimeoutValue);
                }
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testLanguageNegotiation() throws Exception {
        sshd.start();

        client.setSessionFactory(new org.apache.sshd.client.session.SessionFactory(client) {
            @Override
            protected ClientSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(getClient(), ioSession) {
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

        final Semaphore sigSem = new Semaphore(0, true);
        client.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                outputDebugMessage("Session created: %s", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if (Event.KeyEstablished.equals(event)) {
                    for (KexProposalOption option : new KexProposalOption[]{
                        KexProposalOption.S2CLANG, KexProposalOption.C2SLANG
                    }) {
                        assertNull("Unexpected negotiated language for " + option, session.getNegotiatedKexParameter(option));
                    }

                    sigSem.release();
                }
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                outputDebugMessage("Session %s exception %s caught: %s", session, t.getClass().getSimpleName(), t.getMessage());
            }

            @Override
            public void sessionClosed(Session session) {
                outputDebugMessage("Session closed: %s", session);
            }
        });

        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            assertTrue("Failed to receive signal on time", sigSem.tryAcquire(11L, TimeUnit.SECONDS));
        } finally {
            client.stop();
        }
    }

    @Test   // see SSHD-609
    public void testCompressionNegotiation() throws Exception {
        sshd.setSessionFactory(new org.apache.sshd.server.session.SessionFactory(sshd) {
            @Override
            protected ServerSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                return new ServerSessionImpl(getServer(), ioSession) {
                    @Override
                    protected Map<KexProposalOption, String> createProposal(String hostKeyTypes) {
                        Map<KexProposalOption, String> proposal = super.createProposal(hostKeyTypes);
                        proposal.put(KexProposalOption.C2SCOMP, getCurrentTestName());
                        proposal.put(KexProposalOption.S2CCOMP, getCurrentTestName());
                        return proposal;
                    }
                };
            }
        });
        sshd.start();

        client.setSessionFactory(new org.apache.sshd.client.session.SessionFactory(client) {
            @Override
            protected ClientSessionImpl doCreateSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(getClient(), ioSession) {
                    @Override
                    protected Map<KexProposalOption, String> createProposal(String hostKeyTypes) {
                        Map<KexProposalOption, String> proposal = super.createProposal(hostKeyTypes);
                        proposal.put(KexProposalOption.C2SCOMP, getCurrentTestName());
                        proposal.put(KexProposalOption.S2CCOMP, getCurrentTestName());
                        return proposal;
                    }
                };
            }
        });

        final Semaphore sigSem = new Semaphore(0, true);
        client.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                outputDebugMessage("Session created: %s", session);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                assertNotEquals("Unexpected key establishment success", Event.KeyEstablished, event);
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                outputDebugMessage("Session %s exception %s caught: %s", session, t.getClass().getSimpleName(), t.getMessage());
            }

            @Override
            public void sessionClosed(Session session) {
                sigSem.release();
            }
        });

        client.start();
        try {
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
                assertTrue("Session closing not signalled on time", sigSem.tryAcquire(5L, TimeUnit.SECONDS));
                for (boolean incoming : new boolean[]{true, false}) {
                    assertNull("Unexpected compression information for incoming=" + incoming, s.getCompressionInformation(incoming));
                }
                assertFalse("Session unexpectedly still open", s.isOpen());
            }
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
            public void sessionException(Session session, Throwable t) {
                // ignored
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });
        sshd.start();

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
            public void sessionException(Session session, Throwable t) {
                // ignored
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        });
        client.start();

        try (ClientSession s = createTestClientSession(sshd)) {
            assertEquals("Mismatched client events count", 1, clientEventCount.get());
            assertEquals("Mismatched server events count", 1, serverEventCount.get());
            s.close(false);
        } finally {
            client.stop();
        }
    }

    @Test   // see SSHD-645
    public void testChannelStateChangeNotifications() throws Exception {
        final Semaphore exitSignal = new Semaphore(0);
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
                        exitSignal.release();
                        cb.onExit(0, command);
                    }
                };
            }
        });
        sshd.start();
        client.start();

        final Collection<String> stateChangeHints = new CopyOnWriteArrayList<>();
        try (ClientSession s = createTestClientSession(sshd);
             ChannelExec shell = s.createExecChannel(getCurrentTestName())) {
            shell.addChannelListener(new ChannelListener() {
                @Override
                public void channelStateChanged(Channel channel, String hint) {
                    assertNotNull("No hint for channel", hint);
                    outputDebugMessage("channelStateChanged(%s): %s", channel, hint);
                    stateChangeHints.add(hint);
                }

                @Override
                public void channelOpenSuccess(Channel channel) {
                    // ignored
                }

                @Override
                public void channelOpenFailure(Channel channel, Throwable reason) {
                    // ignored
                }

                @Override
                public void channelInitialized(Channel channel) {
                    // ignored
                }

                @Override
                public void channelClosed(Channel channel, Throwable reason) {
                    // ignored
                }
            });
            shell.open().verify(9L, TimeUnit.SECONDS);

            assertTrue("Timeout while wait for exit signal", exitSignal.tryAcquire(15L, TimeUnit.SECONDS));
            Collection<ClientChannelEvent> result =
                    shell.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(13L));
            assertFalse("Channel close timeout", result.contains(ClientChannelEvent.TIMEOUT));

            Integer status = shell.getExitStatus();
            assertNotNull("No exit status", status);
        } finally {
            client.stop();
        }

        for (String h : new String[]{"exit-status"}) {
            assertTrue("Missing hint=" + h + " in " + stateChangeHints, stateChangeHints.contains(h));
        }
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
        sshd.start();

        @SuppressWarnings("synthetic-access")
        Map<String, String> expected = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                put("test", getCurrentTestName());
                put("port", Integer.toString(sshd.getPort()));
                put("user", OsUtils.getCurrentUser());
            }
        };

        client.start();
        try (ClientSession s = createTestClientSession(sshd);
             ChannelExec shell = s.createExecChannel(getCurrentTestName())) {
            for (Map.Entry<String, String> ee : expected.entrySet()) {
                shell.setEnv(ee.getKey(), ee.getValue());
            }

            shell.open().verify(5L, TimeUnit.SECONDS);

            assertTrue("No changes in activated channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No activated server side channels", GenericUtils.size(channelListener.getActiveChannels()) > 0);
            assertTrue("No changes in open channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
            assertTrue("No open server side channels", GenericUtils.size(channelListener.getOpenChannels()) > 0);

            Collection<ClientChannelEvent> result =
                    shell.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(17L));
            assertFalse("Channel close timeout", result.contains(ClientChannelEvent.TIMEOUT));

            Integer status = shell.getExitStatus();
            assertNotNull("No exit status", status);
            assertEquals("Bad exit status", 0, status.intValue());
        } finally {
            client.stop();
        }

        assertTrue("No changes in closed channels", channelListener.waitForModification(5L, TimeUnit.SECONDS));
        assertTrue("Still activated server side channels", GenericUtils.isEmpty(channelListener.getActiveChannels()));

        Environment cmdEnv = envHolder.get();
        assertNotNull("No environment set", cmdEnv);

        Map<String, String> vars = cmdEnv.getEnv();
        assertTrue("Mismatched vars count", GenericUtils.size(vars) >= GenericUtils.size(expected));
        for (Map.Entry<String, String> ee : expected.entrySet()) {
            String key = ee.getKey();
            String expValue = ee.getValue();
            String actValue = vars.get(key);
            assertEquals("Mismatched value for " + key, expValue, actValue);
        }
    }

    @Test   // see SSHD-611
    public void testImmediateAuthFailureOpcode() throws Exception {
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        final AtomicInteger challengeCount = new AtomicInteger(0);
        sshd.setKeyboardInteractiveAuthenticator(new KeyboardInteractiveAuthenticator() {
            @Override
            public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods) {
                challengeCount.incrementAndGet();
                outputDebugMessage("generateChallenge(%s@%s) count=%s", username, session, challengeCount);
                return null;
            }

            @Override
            public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
                return false;
            }
        });
        sshd.start();

        // order is important
        String authMethods = GenericUtils.join(
                Arrays.asList(UserAuthMethodFactory.KB_INTERACTIVE, UserAuthMethodFactory.PUBLIC_KEY, UserAuthMethodFactory.PUBLIC_KEY), ',');
        PropertyResolverUtils.updateProperty(client, ClientAuthenticationManager.PREFERRED_AUTHS, authMethods);

        client.start();
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            AuthFuture auth = session.auth();
            assertTrue("Failed to complete authentication on time", auth.await(17L, TimeUnit.SECONDS));
            assertFalse("Unexpected authentication success", auth.isSuccess());
            assertEquals("Mismatched interactive challenge calls", 1, challengeCount.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testMaxKeyboardInteractiveTrialsSetting() throws Exception {
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);

        final InteractiveChallenge challenge = new InteractiveChallenge();
        challenge.setInteractionInstruction(getCurrentTestName());
        challenge.setInteractionName(getClass().getSimpleName());
        challenge.setLanguageTag("il-heb");
        challenge.addPrompt(new PromptEntry("Password", false));
        final AtomicInteger serverCount = new AtomicInteger(0);
        sshd.setKeyboardInteractiveAuthenticator(new KeyboardInteractiveAuthenticator() {
            @Override
            public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods) {
                return challenge;
            }

            @Override
            public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
                outputDebugMessage("authenticate(%s@%s) count=%s", username, session, serverCount);
                serverCount.incrementAndGet();
                return false;
            }
        });
        sshd.start();

        // order is important
        String authMethods = GenericUtils.join(
                Arrays.asList(UserAuthMethodFactory.KB_INTERACTIVE, UserAuthMethodFactory.PUBLIC_KEY, UserAuthMethodFactory.PUBLIC_KEY), ',');
        PropertyResolverUtils.updateProperty(client, ClientAuthenticationManager.PREFERRED_AUTHS, authMethods);
        final AtomicInteger clientCount = new AtomicInteger(0);
        final String[] replies = {getCurrentTestName()};
        client.setUserInteraction(new UserInteraction() {
            @Override
            public void welcome(ClientSession session, String banner, String lang) {
                // ignored
            }

            @Override
            public void serverVersionInfo(ClientSession clientSession, List<String> lines) {
                // ignored
            }

            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                clientCount.incrementAndGet();
                return replies;
            }

            @Override
            public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                throw new UnsupportedOperationException("Unexpected updated password request");
            }
        });

        client.start();
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            AuthFuture auth = session.auth();
            assertTrue("Failed to complete authentication on time", auth.await(17L, TimeUnit.SECONDS));
            assertFalse("Unexpected authentication success", auth.isSuccess());
            assertEquals("Mismatched interactive server challenge calls", ClientAuthenticationManager.DEFAULT_PASSWORD_PROMPTS, serverCount.get());
            assertEquals("Mismatched interactive client challenge calls", ClientAuthenticationManager.DEFAULT_PASSWORD_PROMPTS, clientCount.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testIdentificationStringsOverrides() throws Exception {
        String clientIdent = getCurrentTestName() + "-client";
        PropertyResolverUtils.updateProperty(client, ClientFactoryManager.CLIENT_IDENTIFICATION, clientIdent);
        final String expClientIdent = Session.DEFAULT_SSH_VERSION_PREFIX + clientIdent;

        String serverIdent = getCurrentTestName() + "-server";
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.SERVER_IDENTIFICATION, serverIdent);
        final String expServerIdent = Session.DEFAULT_SSH_VERSION_PREFIX + serverIdent;

        SessionListener listener = new SessionListener() {
            @Override
            public void sessionException(Session session, Throwable t) {
                // ignored
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if (Event.KexCompleted.equals(event)) {
                    assertEquals("Mismatched client listener identification", expClientIdent, session.getClientVersion());
                    assertEquals("Mismatched server listener identification", expServerIdent, session.getServerVersion());
                }
            }

            @Override
            public void sessionCreated(Session session) {
                // ignored
            }

            @Override
            public void sessionClosed(Session session) {
                // ignored
            }
        };

        sshd.addSessionListener(listener);
        sshd.start();

        client.addSessionListener(listener);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(9L, TimeUnit.SECONDS);
            assertEquals("Mismatched client identification", expClientIdent, session.getClientVersion());
            assertEquals("Mismatched server identification", expServerIdent, session.getServerVersion());
        } finally {
            client.stop();
        }
    }

    @Test   // see SSHD-659
    public void testMultiLineServerIdentification() throws Exception {
        List<String> expected = Arrays.asList(
                getClass().getPackage().getName(),
                getClass().getSimpleName(),
                getCurrentTestName());
        PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.SERVER_EXTRA_IDENTIFICATION_LINES,
                GenericUtils.join(expected, ServerFactoryManager.SERVER_EXTRA_IDENT_LINES_SEPARATOR));
        sshd.start();

        final AtomicReference<List<String>> actualHolder = new AtomicReference<>();
        final Semaphore signal = new Semaphore(0);
        client.setUserInteraction(new UserInteraction() {
            @Override
            public void welcome(ClientSession session, String banner, String lang) {
                // ignored
            }

            @Override
            public void serverVersionInfo(ClientSession session, List<String> lines) {
                assertNull("Unexpected extra call", actualHolder.getAndSet(lines));
                signal.release();
            }

            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public String[] interactive(ClientSession session, String name, String instruction, String lang, String[] prompt, boolean[] echo) {
                return null;
            }

            @Override
            public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                return null;
            }
        });
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(9L, TimeUnit.SECONDS);
            assertTrue("No signal received in time", signal.tryAcquire(11L, TimeUnit.SECONDS));
        } finally {
            client.stop();
        }

        List<String> actual = actualHolder.get();
        assertNotNull("Information not signalled", actual);
        assertListEquals("Server information", expected, actual);
    }

    private ClientSession createTestClientSession(SshServer server) throws Exception {
        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, server.getPort()).verify(7L, TimeUnit.SECONDS).getSession();
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
        // CHECKSTYLE:OFF
        public static CountDownLatch latch;
        // CHECKSTYLE:ON

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
        // CHECKSTYLE:OFF
        public static CountDownLatch latch;
        // CHECKSTYLE:ON

        public static class Factory implements CommandFactory {
            @Override
            public Command createCommand(String name) {
                return new StreamCommand(name);
            }
        }

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
}
