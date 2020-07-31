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
import java.net.ServerSocket;
import java.util.concurrent.TimeUnit;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests - Apache server, JSch client
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ApacheServerJSchClientTest extends AbstractServerCloseTestSupport {
    private static final long TIMEOUT = TimeUnit.SECONDS.toMillis(10L);
    private static final Logger LOG = LoggerFactory.getLogger(ApacheServerJSchClientTest.class);

    private static int sshServerPort;
    private static SshServer server;

    private Session session;

    public ApacheServerJSchClientTest() {
        super();
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /*
     * Starts an SSH Server
     */
    @BeforeClass
    public static void startSshServer() throws IOException {
        LOG.info("Starting SSHD...");
        server = CoreTestSupportUtils.setupTestFullSupportServer(SshServer.setUpDefaultServer());
        server.setPasswordAuthenticator((u, p, s) -> true);
        server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        server.start();
        sshServerPort = server.getPort();
        LOG.info("SSHD Running on port {}", server.getPort());
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @AfterClass
    public static void stopServer() throws IOException {
        if (!server.close(true).await(TIMEOUT)) {
            LOG.warn("Failed to close server within {} sec.", TimeUnit.MILLISECONDS.toSeconds(TIMEOUT));
        }
    }

    @Before
    public void createClient() throws Exception {
        JSch client = new JSch();
        session = client.getSession("user", TEST_LOCALHOST, sshServerPort);
        session.setUserInfo(new SimpleUserInfo("password"));
        LOG.trace("Connecting session...");
        session.connect();
        LOG.trace("Client is running now...");
    }

    @After
    public void stopClient() throws Exception {
        LOG.info("Disconnecting Client");
        session.disconnect();
    }

    @Override
    protected int startRemotePF() throws Exception {
        int port = findFreePort();
        session.setPortForwardingR(TEST_LOCALHOST, port, TEST_LOCALHOST, testServerPort);
        return port;
    }

    @Override
    protected int startLocalPF() throws Exception {
        int port = findFreePort();
        session.setPortForwardingL(TEST_LOCALHOST, port, TEST_LOCALHOST, testServerPort);
        return port;
    }
}
