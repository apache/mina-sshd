/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
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
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
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
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setSessionFactory(new org.apache.sshd.server.session.SessionFactory());
        sshd.start();
        port = sshd.getPort();
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
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.MAX_AUTH_REQUESTS, MAX_AUTH_REQUESTS);

        client = SshClient.setUpDefaultClient();
        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();

        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            int nbTrials = 0;
            int res = 0;
            while ((res & ClientSession.CLOSED) == 0) {
                nbTrials++;
                s.getService(ClientUserAuthServiceOld.class)
                        .auth(new org.apache.sshd.deprecated.UserAuthPassword(s, "ssh-connection", "buggy"))
                ;
                res = s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, TimeUnit.SECONDS.toMillis(5L));
                if (res == ClientSession.TIMEOUT) {
                    throw new TimeoutException("Client session timeout signalled");
                }
            }
            assertTrue("Number trials (" + nbTrials + ") below min.=" + MAX_AUTH_REQUESTS, nbTrials > MAX_AUTH_REQUESTS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testFailAuthenticationWithFuture() throws Exception {
        final int MAX_AUTH_REQUESTS = 10;
        FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.MAX_AUTH_REQUESTS, MAX_AUTH_REQUESTS);

        client = SshClient.setUpDefaultClient();
        client.setServiceFactories(Arrays.asList(
                new ClientUserAuthServiceOld.Factory(),
                ClientConnectionServiceFactory.INSTANCE
        ));
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            int nbTrials = 0;
            AuthFuture authFuture;
            do {
                nbTrials++;
                assertTrue(nbTrials < 100);
                authFuture = s.getService(ClientUserAuthServiceOld.class)
                        .auth(new org.apache.sshd.deprecated.UserAuthPassword(s, "ssh-connection", "buggy"))
                ;
                assertTrue("Authentication wait failed", authFuture.await(5000));
                assertTrue("Authentication not done", authFuture.isDone());
                assertFalse("Authentication unexpectedly successful", authFuture.isSuccess());
            }
            while (authFuture.isFailure());
            assertNotNull("Missing auth future exception", authFuture.getException());
            assertTrue("Number trials (" + nbTrials + ") below min.=" + MAX_AUTH_REQUESTS, nbTrials > MAX_AUTH_REQUESTS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        final int AUTH_TIMEOUT = 5000;
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.AUTH_TIMEOUT, AUTH_TIMEOUT);

        client = SshClient.setUpDefaultClient();
        client.start();
        try (ClientSession s = client.connect("test", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            int res = s.waitFor(ClientSession.CLOSED, 2 * AUTH_TIMEOUT);
            assertEquals("Session should be closed", ClientSession.CLOSED | ClientSession.WAIT_AUTH, res);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testIdleTimeout() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);
        final int IDLE_TIMEOUT = 2500;
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, IDLE_TIMEOUT);

        sshd.getSessionFactory().addListener(new SessionListener() {
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

        client = SshClient.setUpDefaultClient();
        client.start();
        try (ClientSession s = client.connect("test", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.addPasswordIdentity("test");
            s.auth().verify(5L, TimeUnit.SECONDS);

            try (ChannelShell shell = s.createShellChannel();
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {
                shell.setOut(out);
                shell.setErr(err);
                shell.open().verify(9L, TimeUnit.SECONDS);
                int res = s.waitFor(ClientSession.CLOSED, 2 * IDLE_TIMEOUT);
                assertEquals("Session should be closed", ClientSession.CLOSED | ClientSession.AUTHED, res);
            }
        } finally {
            client.stop();
        }

        assertTrue(latch.await(1, TimeUnit.SECONDS));
        assertTrue(TestEchoShellFactory.TestEchoShell.latch.await(1, TimeUnit.SECONDS));
    }

    /**
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

        FactoryManagerUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, 5000);
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.DISCONNECT_TIMEOUT, 2000);
        sshd.getSessionFactory().addListener(new SessionListener() {
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

        client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(5L, TimeUnit.SECONDS);

            try (ChannelExec shell = s.createExecChannel("normal");
                 // Create a pipe that will block reading when the buffer is full
                 PipedInputStream pis = new PipedInputStream();
                 PipedOutputStream pos = new PipedOutputStream(pis)) {

                shell.setOut(pos);
                shell.open().verify(5L, TimeUnit.SECONDS);

                try (AbstractSession serverSession = sshd.getActiveSessions().iterator().next();
                     Channel channel = serverSession.getService(AbstractConnectionService.class).getChannels().iterator().next()) {

                    while (channel.getRemoteWindow().getSize() > 0) {
                        Thread.sleep(1);
                    }

                    LoggerFactory.getLogger(getClass()).info("Waiting for session idle timeouts");

                    long t0 = System.currentTimeMillis();
                    latch.await(1, TimeUnit.MINUTES);
                    long t1 = System.currentTimeMillis(), diff = t1 - t0;
                    assertTrue("Wait time too low: " + diff, diff > 7000);
                    assertTrue("Wait time too high: " + diff, diff < 10000);
                }
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testLanguage() throws Exception {
        client = SshClient.setUpDefaultClient();
        client.setSessionFactory(new SessionFactory() {
            @Override
            protected AbstractSession createSession(IoSession ioSession) throws Exception {
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
        try (ClientSession s = client.connect("test", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.close(false);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKexCompletedEvent() throws Exception {
        final AtomicInteger serverEventCount = new AtomicInteger(0);
        sshd.getSessionFactory().addListener(new SessionListener() {
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

        client = SshClient.setUpDefaultClient();
        client.start();
        final AtomicInteger clientEventCount = new AtomicInteger(0);
        client.getSessionFactory().addListener(new SessionListener() {
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

        try (ClientSession s = client.connect("test", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.addPasswordIdentity("test");
            s.auth().verify(5L, TimeUnit.SECONDS);
            assertEquals("Mismatched client events count", 1, clientEventCount.get());
            assertEquals("Mismatched server events count", 1, serverEventCount.get());
            s.close(false);
        } finally {
            client.stop();
        }
    }

    @Test   // see https://issues.apache.org/jira/browse/SSHD-456
    public void testServerStillListensIfSessionListenerThrowsException() throws InterruptedException {
        final Map<String, SocketAddress> eventsMap = new TreeMap<String, SocketAddress>(String.CASE_INSENSITIVE_ORDER);
        sshd.getSessionFactory().addListener(new SessionListener() {
            private final Logger log = LoggerFactory.getLogger(getClass());

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

        client = SshClient.setUpDefaultClient();
        client.start();

        int curCount = 0;
        for (int retryCount = 0; retryCount < Byte.SIZE; retryCount++) {
            synchronized (eventsMap) {
                if ((curCount = eventsMap.size()) >= 3) {
                    return;
                }
            }

            try {
                try (ClientSession s = client.connect("test", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                    s.addPasswordIdentity("test");
                    s.auth().verify(5L, TimeUnit.SECONDS);
                }

                synchronized (eventsMap) {
                    assertTrue("Unexpected premature success: " + eventsMap, eventsMap.size() >= 3);
                }
            } catch (IOException e) {
                // expected - ignored
                synchronized (eventsMap) {
                    int nextCount = eventsMap.size();
                    assertTrue("No session event generated", nextCount > curCount);
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


        @SuppressWarnings("synthetic-access")
        Map<String, String> expected = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                put("test", getCurrentTestName());
                put("port", Integer.toString(port));
                put("user", System.getProperty("user.name"));
            }
        };

        client = SshClient.setUpDefaultClient();
        client.start();
        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(5L, TimeUnit.SECONDS);

            try (ChannelExec shell = s.createExecChannel(getCurrentTestName())) {
                for (Map.Entry<String, String> ee : expected.entrySet()) {
                    shell.setEnv(ee.getKey(), ee.getValue());
                }
                shell.open().verify(5L, TimeUnit.SECONDS);
                shell.waitFor(ClientChannel.CLOSED, TimeUnit.SECONDS.toMillis(17L));

                Integer status = shell.getExitStatus();
                assertNotNull("No exit status", status);
                assertEquals("Bad exit status", 0, status.intValue());
            }

            Environment cmdEnv = envHolder.get();
            assertNotNull("No environment set", cmdEnv);

            Map<String, String> vars = cmdEnv.getEnv();
            assertTrue("Mismatched vars count", GenericUtils.size(vars) >= GenericUtils.size(expected));
            for (Map.Entry<String, String> ee : expected.entrySet()) {
                String key = ee.getKey(), expValue = ee.getValue(), actValue = vars.get(key);
                assertEquals("Mismatched value for " + key, expValue, actValue);
            }
        } finally {
            client.stop();
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

        public static class TestEchoShell extends EchoShell {

            public static CountDownLatch latch = new CountDownLatch(1);

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
                Thread.sleep(5000);
                while (true) {
                    for (int i = 0; i < 100; i++) {
                        out.write("0123456789\n".getBytes(StandardCharsets.UTF_8));
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
        SshServer sshd = SshServer.setUpDefaultServer();
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TimeUnit.SECONDS.toMillis(10L));
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.start();
        Thread.sleep(100000);
    }
}
