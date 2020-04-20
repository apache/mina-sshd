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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding test multiple clients connecting at once.
 */
public class ConcurrentConnectionTest extends BaseTestSupport {
    private static final byte[] PAYLOAD_TO_SERVER = "To Server -> To Server -> To Server".getBytes();
    private static final byte[] PAYLOAD_TO_CLIENT = "<- To Client <- To Client <-".getBytes();
    private static final Logger LOG = LoggerFactory.getLogger(ConcurrentConnectionTest.class);

    // These are the critical test parameters.
    // When the number of clients is greater than or equal to the number of IO
    // Workers, the server deadlocks
    private static final int SSHD_NIO_WORKERS = 8;
    private static final int PORT_FORWARD_CLIENT_COUNT = 12;

    private static final int SO_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(10L);

    // SSHD Server State
    private static int sshServerPort;
    private static SshServer server;

    // Test Server State
    private int testServerPort;
    private ServerSocket testServerSock;
    private Thread testServerThread;

    // SSH Client State
    private ClientSession session;

    public ConcurrentConnectionTest() {
        super();
    }

    /*
     * Start a server to forward to.
     *
     * Reads PAYLOAD_TO_SERVER from client and then sends PAYLOAD_TO_CLIENT to client. This server emulates a web
     * server, closely enough for thie test
     */
    @Before
    public void startTestServer() throws Exception {
        testServerThread = new Thread(this::serverAcceptLoop);
        testServerThread.setDaemon(true);
        testServerThread.setName("Server Acceptor");
        testServerThread.start();
        Thread.sleep(100);
    }

    protected void serverAcceptLoop() {
        try {
            final AtomicInteger activeServers = new AtomicInteger(0);
            testServerSock = new ServerSocket(0);
            testServerPort = testServerSock.getLocalPort();
            LOG.debug("Listening on {}", testServerPort);
            while (true) {
                final Socket s = testServerSock.accept();
                LOG.debug("Got connection");
                final Thread server = new Thread(() -> serverSocketLoop(activeServers, s));
                server.setDaemon(true);
                server.setName("Server " + s.getPort());
                server.start();
            }
        } catch (final SocketException e) {
            LOG.debug("Shutting down test server");
        } catch (final Throwable t) {
            LOG.error("Error", t);
        }
    }

    private void serverSocketLoop(AtomicInteger activeServers, Socket s) {
        try {
            LOG.debug("Active Servers: {}", activeServers.incrementAndGet());
            final byte[] buf = new byte[PAYLOAD_TO_SERVER.length];
            final long r = s.getInputStream().read(buf);
            LOG.debug("Read {} payload from client", r);
            s.getOutputStream().write(PAYLOAD_TO_CLIENT);
            LOG.debug("Wrote payload to client");
            s.close();
            LOG.debug("Active Servers: {}", activeServers.decrementAndGet());
        } catch (final Throwable t) {
            LOG.error("Error", t);
        }
    }

    @After
    public void stopTestServer() throws Exception {
        testServerSock.close();
        testServerThread.interrupt();
    }

    @BeforeClass
    public static void startSshServer() throws IOException {
        LOG.debug("Starting SSHD...");
        server = SshServer.setUpDefaultServer();
        server.setPasswordAuthenticator((u, p, s) -> true);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        server.setNioWorkers(SSHD_NIO_WORKERS);
        server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        server.start();
        sshServerPort = server.getPort();
        LOG.debug("SSHD Running on port {}", server.getPort());
    }

    @AfterClass
    public static void stopServer() throws IOException {
        if (!server.close(true).await(CLOSE_TIMEOUT)) {
            LOG.warn("Failed to close server within {} sec.", CLOSE_TIMEOUT.toMillis() / 1000);
        }
    }

    @Before
    public void createClient() throws IOException {
        final SshClient client = SshClient.setUpDefaultClient();
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        client.start();
        LOG.debug("Connecting...");
        session = client.connect("user", TEST_LOCALHOST, sshServerPort).verify(CONNECT_TIMEOUT).getSession();
        LOG.debug("Authenticating...");
        session.addPasswordIdentity("foo");
        session.auth().verify(AUTH_TIMEOUT);
        LOG.debug("Authenticated");
    }

    @After
    public void stopClient() throws Exception {
        LOG.debug("Disconnecting Client");
        try {
            assertTrue("Failed to close session", session.close(true).await(CLOSE_TIMEOUT));
        } finally {
            session = null;
        }
    }

    @Test
    /*
     * Run PORT_FORWARD_CLIENT_COUNT simultaneous server threads.
     *
     * Emulates a web browser making a number of simultaneous requests on different connections to the same server HTTP
     * specifies no more than two, but most modern browsers do 6 or more.
     */
    public void testConcurrentConnectionsToPortForward() throws Exception {
        final SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, 0);
        final SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, testServerPort);
        final SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);
        final int forwardedPort = bound.getPort();

        final CyclicBarrier b = new CyclicBarrier(PORT_FORWARD_CLIENT_COUNT, () -> {
            LOG.debug("And away we go.");
        });

        final AtomicInteger success = new AtomicInteger(0);
        final AtomicInteger fail = new AtomicInteger(0);
        final long[] bytesRead = new long[PORT_FORWARD_CLIENT_COUNT];

        for (int i = 0; i < PORT_FORWARD_CLIENT_COUNT; i++) {
            final long wait = 100 * i;
            final int n = i;
            final Thread t = new Thread(() -> {
                try {
                    bytesRead[n] = makeClientRequest(forwardedPort, b, wait);
                    LOG.debug("Complete, received full payload from server.");
                    success.incrementAndGet();
                } catch (final Exception e) {
                    fail.incrementAndGet();
                    LOG.error("Error in client code", e);
                }
            });
            t.setName("Client " + i);
            t.setDaemon(true);
            t.start();
        }

        while (true) {
            if (success.get() + fail.get() == PORT_FORWARD_CLIENT_COUNT) {
                break;
            }
            Thread.sleep(100);
        }

        for (int i = 0; i < PORT_FORWARD_CLIENT_COUNT; i++) {
            assertEquals("Mismatched data length read from server for client " + i, PAYLOAD_TO_CLIENT.length,
                    bytesRead[i]);
        }

        assertEquals("Not all clients succeeded", PORT_FORWARD_CLIENT_COUNT, success.get());
    }

    /*
     * Send PAYLOAD_TO_SERVER to the server, then read PAYLOAD_TO_CLIENT from server. Emulates a web browser making a
     * request
     */
    private long makeClientRequest(final int serverPort, final CyclicBarrier barrier, final long wait)
            throws Exception {
        outputDebugMessage("readInLoop(port=%d)", serverPort);

        final Socket s = new Socket();
        s.setSoTimeout(SO_TIMEOUT);

        barrier.await();

        s.connect(new InetSocketAddress(TEST_LOCALHOST, serverPort));

        s.getOutputStream().write(PAYLOAD_TO_SERVER);

        final byte[] buf = new byte[PAYLOAD_TO_CLIENT.length];
        final long r = s.getInputStream().read(buf);
        LOG.debug("Read {} payload from server", r);

        assertEquals("Mismatched data length", PAYLOAD_TO_CLIENT.length, r);
        s.close();

        return r;
    }

}
