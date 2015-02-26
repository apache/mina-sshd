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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.apache.sshd.client.SessionFactory;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.WindowClosedException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

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
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
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
        ClientSession s = client.connect("test", "localhost", port).await().getSession();
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
            public void sessionEvent(Session session, Event event) {
                System.out.println("Session event: " + event);
            }
            public void sessionClosed(Session session) {
                System.out.println("Session closed");
                latch.countDown();
            }
        });

        client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession s = client.connect("test", "localhost", port).await().getSession();
        s.addPasswordIdentity("test");
        s.auth().verify();
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

    /**
     * The scenario is the following:
     *  - create a command that sends continuous data to the client
     *  - the client does not read the data, filling the ssh window and the tcp socket
     *  - the server session becomes idle, but the ssh disconnect message can't be written
     *  - the server session is forcibly closed
     */
    @Test
    public void testServerIdleTimeoutWithForce() throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);

        sshd.setCommandFactory(new StreamCommand.Factory());
        sshd.getProperties().put(SshServer.IDLE_TIMEOUT, "5000");
        sshd.getProperties().put(SshServer.DISCONNECT_TIMEOUT, "2000");
        sshd.getSessionFactory().addListener(new SessionListener() {
            public void sessionCreated(Session session) {
                System.out.println("Session created");
            }

            public void sessionEvent(Session session, Event event) {
                System.out.println("Session event: " + event);
            }

            public void sessionClosed(Session session) {
                System.out.println("Session closed");
                latch.countDown();
            }
        });

        client = SshClient.setUpDefaultClient();
        client.start();

        ClientSession s = client.connect("test", "localhost", port).await().getSession();
        s.addPasswordIdentity("test");
        s.auth().verify();
        ChannelExec shell = s.createExecChannel("normal");
        // Create a pipe that will block reading when the buffer is full
        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);
        shell.setOut(pos);
        shell.open().await();

        AbstractSession serverSession = sshd.getActiveSessions().iterator().next();
        Channel channel = serverSession.getService(AbstractConnectionService.class).getChannels().iterator().next();
        while (channel.getRemoteWindow().getSize() > 0) {
            Thread.sleep(1);
        }

        Logger.getLogger(getClass()).info("Waiting for session idle timeouts");

        long t0 = System.currentTimeMillis();
        latch.await(1, TimeUnit.MINUTES);
        long t1 = System.currentTimeMillis();
        assertTrue(t1 - t0 > 7000);
        assertTrue(t1 - t0 < 10000);
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
        ClientSession s = client.connect("test", "localhost", port).await().getSession();
        s.close(false);
    }

    @Test
    public void testKexCompletedEvent() throws Exception {
    	final AtomicInteger	serverEventCount=new AtomicInteger(0);
        sshd.getSessionFactory().addListener(new SessionListener() {
	            public void sessionCreated(Session session) {
	            	// ignored
	            }
	
	            public void sessionEvent(Session session, Event event) {
	            	if (event == Event.KexCompleted) {
	            		serverEventCount.incrementAndGet();
	            	}
	            }
	
	            public void sessionClosed(Session session) {
	            	// ignored
	            }
	        });

        client = SshClient.setUpDefaultClient();
        client.start();
    	final AtomicInteger	clientEventCount=new AtomicInteger(0);
        client.getSessionFactory().addListener(new SessionListener() {
	            public void sessionCreated(Session session) {
	            	// ignored
	            }
	
	            public void sessionEvent(Session session, Event event) {
	            	if (event == Event.KexCompleted) {
	            		clientEventCount.incrementAndGet();
	            	}
	            }
	
	            public void sessionClosed(Session session) {
	            	// ignored
	            }
	        });

        ClientSession s = client.connect("test", "localhost", port).await().getSession();
        s.addPasswordIdentity("test");
        s.auth().verify();
        Assert.assertEquals("Mismatched client events count", 1, clientEventCount.get());
        Assert.assertEquals("Mismatched server events count", 1, serverEventCount.get());
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

    public static class StreamCommand implements Command, Runnable {

        public static class Factory implements CommandFactory {
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

        public void setInputStream(InputStream in) {
            // ignored
        }

        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        public void setErrorStream(OutputStream err) {
            // ignored
        }

        public void setExitCallback(ExitCallback callback) {
            // ignored
        }

        public void start(Environment env) throws IOException {
            Thread  t=new Thread(this);
            t.setDaemon(true);
            t.start();
        }

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

        public void run() {
            try {
                Thread.sleep(5000);
                while (true) {
                    for (int i = 0; i < 100; i++) {
                        out.write("0123456789\n".getBytes());
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
