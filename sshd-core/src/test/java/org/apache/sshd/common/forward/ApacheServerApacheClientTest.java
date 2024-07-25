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
import java.time.Duration;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port forwarding tests, Apache server & client
 */
@TestMethodOrder(MethodName.class)
public class ApacheServerApacheClientTest extends AbstractServerCloseTestSupport {
    private static final Logger LOG = LoggerFactory.getLogger(ApacheServerApacheClientTest.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(10L);

    private static int sshServerPort;
    private static SshServer server;

    private SshClient client;
    private ClientSession session;

    public ApacheServerApacheClientTest() {
        super();
    }

    @BeforeAll
    static void startSshServer() throws IOException {
        LOG.info("Starting SSHD...");
        server = SshServer.setUpDefaultServer();
        server.setPasswordAuthenticator((u, p, s) -> true);
        server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        // Some tests expect to be able to read the whole data with a single or with two read() calls.
        // This can only work if read buffers at all levels are large enough. With MINA, this is not case
        // by default: it uses an adaptive algorithm that adjusts the read buffer size between 64 bytes
        // and 64 kB, and starts out with 2kB. This is too small for these tests to pass.
        //
        // So ensure that MINA uses at least 32kB read buffers
        CoreModuleProperties.NIO2_READ_BUFFER_SIZE.set(server, 32 * 1024);
        CoreModuleProperties.MIN_READ_BUFFER_SIZE.set(server, 32 * 1024);
        server.start();
        sshServerPort = server.getPort();
        LOG.info("SSHD Running on port {}", server.getPort());
    }

    @AfterAll
    static void stopServer() throws IOException {
        if (!server.close(true).await(TIMEOUT)) {
            LOG.warn("Failed to close server within {} sec.", TIMEOUT.toMillis() / 1000);
        }
    }

    @BeforeEach
    void createClient() throws IOException {
        client = SshClient.setUpDefaultClient();
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        CoreModuleProperties.NIO2_READ_BUFFER_SIZE.set(client, 32 * 1024);
        CoreModuleProperties.MIN_READ_BUFFER_SIZE.set(client, 32 * 1024);
        client.start();
        LOG.info("Connecting...");
        session = client.connect("user", TEST_LOCALHOST, sshServerPort).verify(TIMEOUT).getSession();
        LOG.info("Authenticating...");
        session.addPasswordIdentity("foo");
        session.auth().verify(TIMEOUT);
        LOG.info("Authenticated");
    }

    @AfterEach
    void stopClient() throws Exception {
        LOG.info("Disconnecting Client");
        try {
            assertTrue(session.close(true).await(TIMEOUT), "Failed to close session");
        } finally {
            session = null;
            client.stop();
        }
    }

    @Override
    protected SshdSocketAddress startRemotePF() throws Exception {
        SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, 0);
        SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, testServerPort);
        return session.startRemotePortForwarding(remote, local);
    }

    @Override
    protected SshdSocketAddress startLocalPF() throws Exception {
        SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, 0);
        SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, testServerPort);
        return session.startLocalPortForwarding(local, remote);
    }

    @Override
    protected void stopRemotePF(SshdSocketAddress bound) throws Exception {
        session.stopRemotePortForwarding(bound);
    }

    @Override
    protected void stopLocalPF(SshdSocketAddress bound) throws Exception {
        session.stopLocalPortForwarding(bound);
    }

    @Override
    protected boolean hasLocalPFStarted(int port) {
        return session.isLocalPortForwardingStartedForPort(port);
    }

    @Override
    protected boolean hasRemotePFStarted(int port) {
        return session.isRemotePortForwardingStartedForPort(port);
    }

}
