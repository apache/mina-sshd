/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerTest extends BaseTest {

    private SshServer sshd;
    private SshClient client;
    private int port;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setSessionFactory(new org.apache.sshd.server.session.SessionFactory());
        sshd.start();
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
     * @throws Exception
     */
    @Test
    public void testFailAuthenticationWithWaitFor() throws Exception {
        sshd.getProperties().put(SshServer.MAX_AUTH_REQUESTS, "10");

        client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        int nbTrials = 0;
        int res = 0;
        while ((res & ClientSession.CLOSED) == 0) {
            nbTrials ++;
            s.authPassword("smx", "buggy");
            res = s.waitFor(ClientSession.CLOSED | ClientSession.WAIT_AUTH, 5000);
            if (res == ClientSession.TIMEOUT) {
                throw new TimeoutException();
            }
        }
        assertTrue(nbTrials > 10);
    }

    @Test
    public void testFailAuthenticationWithFuture() throws Exception {
        sshd.getProperties().put(SshServer.MAX_AUTH_REQUESTS, "10");

        client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        int nbTrials = 0;
        AuthFuture authFuture;
        do {
            nbTrials++;
            assertTrue(nbTrials < 100);
            authFuture = s.authPassword("smx", "buggy");
            assertTrue(authFuture.await(5000));
            assertTrue(authFuture.isDone());
            assertFalse(authFuture.isSuccess());
        }
        while (authFuture.isFailure());
        assertNotNull(authFuture.getException());
        assertTrue(nbTrials > 10);
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        sshd.getProperties().put(SshServer.AUTH_TIMEOUT, "5000");

        client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        int res = s.waitFor(ClientSession.CLOSED, 10000);
        assertEquals("Session should be closed", ClientSession.CLOSED | ClientSession.WAIT_AUTH, res);
    }

    @Test
    public void testIdleTimeout() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);

        sshd.getProperties().put(SshServer.IDLE_TIMEOUT, "2500");
        sshd.getSessionFactory().addListener(new SessionListener() {
            public void sessionCreated(Session session) {
                System.out.println("Session created");
            }
            public void sessionEvent(Session sesssion, Event event) {
                System.out.println("Session event: " + event);
            }
            public void sessionClosed(Session session) {
                System.out.println("Session closed");
                latch.countDown();
            }
        });

        client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        s.authPassword("test", "test").await();
        ChannelShell shell = s.createShellChannel();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        shell.setOut(out);
        shell.setErr(err);
        shell.open().await();
        int res = s.waitFor(ClientSession.CLOSED, 5000);
        assertEquals("Session should be closed", ClientSession.CLOSED | ClientSession.AUTHED, res);
        assertTrue(latch.await(1, TimeUnit.SECONDS));
        assertTrue(TestEchoShellFactory.TestEchoShell.latch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void testLanguage() throws Exception {
        client = SshClient.setUpDefaultClient();
        client.setSessionFactory(new SessionFactory() {
            @Override
            protected AbstractSession createSession(IoSession ioSession) throws Exception {
                return new ClientSessionImpl(client, ioSession) {
                    @Override
                    protected String[] createProposal(String hostKeyTypes) {
                        String[] proposal = super.createProposal(hostKeyTypes);
                        proposal[SshConstants.PROPOSAL_LANG_CTOS] = "en-US";
                        proposal[SshConstants.PROPOSAL_LANG_STOC] = "en-US";
                        return proposal;
                    }
                };
            }
        });
        client.start();
        ClientSession s = client.connect("localhost", port).await().getSession();
        s.close(false);
    }

    public static class TestEchoShellFactory extends EchoShellFactory {
        @Override
        public Command create() {
            return new TestEchoShell();
        }
        public static class TestEchoShell extends EchoShell {

            public static CountDownLatch latch = new CountDownLatch(1);

            @Override
            public void destroy() {
                if (latch != null) {
                    latch.countDown();
                }
                super.destroy();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.getProperties().put(SshServer.IDLE_TIMEOUT, "10000");
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        Thread.sleep(100000);
    }

}
