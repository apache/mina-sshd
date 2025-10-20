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
package org.apache.sshd.client.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.AbstractContainerTestBase;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

/**
 * Test client connection through tinyproxy (HTTP CONNECT), anonymous.
 */
class ProxyHttpIntegrationTest extends AbstractContainerTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(ProxyHttpIntegrationTest.class);

    private static GenericContainer<?> proxy = new GenericContainer<>("ajoergensen/tinyproxy") //
            .withCopyFileToContainer(MountableFile.forClasspathResource("org/apache/sshd/proxy/tinyproxy.conf"),
                    "/etc/tinyproxy/tinyproxy.conf") //
            .withExposedPorts(1080) //
            .withLogConsumer(new Slf4jLogConsumer(LOG));

    private static SshServer server;

    @BeforeAll
    static void setup() throws IOException {
        server = CoreTestSupportUtils.setupTestServer(ProxySocksIntegrationTest.class);
        // setup server with an echo command
        server.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                return false;
            }
        });
        server.start();
        Testcontainers.exposeHostPorts(server.getPort());
        proxy.start();
    }

    @AfterAll
    static void tearDown() throws IOException {
        try {
            server.stop();
        } finally {
            proxy.stop();
        }
    }

    @Test
    void httpProxy() throws Exception {
        doTest(null, null);
    }

    @Test
    void httpProxyAuth() throws Exception {
        doTest("httptester", "testhttp".toCharArray());
    }

    private void doTest(String user, char[] password) throws Exception {
        Proxy proxyDescriptor = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy.getHost(), proxy.getMappedPort(1080)));
        ProxyData proxyData = new ProxyData(proxyDescriptor, user, password);
        try (SshClient client = setupTestClient()) {
            client.setProxyDataFactory(remoteAddress -> proxyData);
            client.start();
            // Connect through the proxy
            try (ClientSession session = client.connect("user1", "host.testcontainers.internal", server.getPort())
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity("user1");
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated());
                testCommand(session, "ls -al");
            }
        }
    }

    private void testCommand(ClientSession session, String command) throws IOException {
        String result;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream errors = new ByteArrayOutputStream();
        session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
        result = out.toString();
        assertEquals(command, result);
    }

}
