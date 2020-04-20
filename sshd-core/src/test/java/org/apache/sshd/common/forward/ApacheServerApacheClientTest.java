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
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests, Apache server & client
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ApacheServerApacheClientTest extends AbstractServerCloseTestSupport {
    private static final Logger LOG = LoggerFactory.getLogger(ApacheServerApacheClientTest.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(10L);

    private static int sshServerPort;
    private static SshServer server;

    private ClientSession session;

    public ApacheServerApacheClientTest() {
        super();
    }

    @BeforeClass
    public static void startSshServer() throws IOException {
        LOG.info("Starting SSHD...");
        server = SshServer.setUpDefaultServer();
        server.setPasswordAuthenticator((u, p, s) -> true);
        server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        server.start();
        sshServerPort = server.getPort();
        LOG.info("SSHD Running on port {}", server.getPort());
    }

    @AfterClass
    public static void stopServer() throws IOException {
        if (!server.close(true).await(TIMEOUT)) {
            LOG.warn("Failed to close server within {} sec.", TIMEOUT.toMillis() / 1000);
        }
    }

    @Before
    public void createClient() throws IOException {
        SshClient client = SshClient.setUpDefaultClient();
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        client.start();
        LOG.info("Connecting...");
        session = client.connect("user", TEST_LOCALHOST, sshServerPort).verify(TIMEOUT).getSession();
        LOG.info("Authenticating...");
        session.addPasswordIdentity("foo");
        session.auth().verify(TIMEOUT);
        LOG.info("Authenticated");
    }

    @After
    public void stopClient() throws Exception {
        LOG.info("Disconnecting Client");
        try {
            assertTrue("Failed to close session", session.close(true).await(TIMEOUT));
        } finally {
            session = null;
        }
    }

    @Override
    protected int startRemotePF() throws Exception {
        SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, 0);
        SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, testServerPort);
        SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);
        return bound.getPort();
    }

    @Override
    protected int startLocalPF() throws Exception {
        SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, 0);
        SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, testServerPort);
        SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);
        return bound.getPort();
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
