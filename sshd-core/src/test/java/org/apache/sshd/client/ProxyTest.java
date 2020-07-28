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
package org.apache.sshd.client;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;

import org.apache.sshd.client.config.hosts.KnownHostHashValue;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.RejectAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ProxyTest extends BaseTestSupport {

    @Rule
    public TemporaryFolder tmpClientDir = new TemporaryFolder();

    private ClientSession proxySession;

    public ProxyTest() {
        super();
    }

    @Test
    public void testProxy() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {

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
            // setup proxy with a forwarding filter to allow the local port forwarding
            proxy.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
            proxy.start();
            // setup client
            client.start();

            String command = "ls -la";
            String result;
            try (ClientSession session = createSession(
                    client,
                    "localhost", server.getPort(), "user1", "user1",
                    "localhost", proxy.getPort(), "user2", "user2")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream errors = new ByteArrayOutputStream();
                session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
                result = out.toString();
            }
            assertEquals(command, result);
            // make sure the proxy session is closed / closing
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
        }
    }

    @Test
    public void testDirectWithHostKeyVerification() throws Exception {
        // This test exists only to show that the knownhosts setup is correct
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer()) {

            File knownHosts = prepareHostKeySetup(server, proxy);
            try (SshClient client = setupTestClient()) {
                // Setup client with a standard ServerKeyVerifier
                client.setServerKeyVerifier(
                        new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts.toPath()));
                client.start();

                // Connect to the server directly to verify the knownhosts setup.
                String command = "ls -al";
                String result;
                try (ClientSession session = createSession(
                        client,
                        "localhost", server.getPort(), "user1", "user1",
                        null, -1, null, null)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream errors = new ByteArrayOutputStream();
                    session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
                    result = out.toString();
                }
                assertEquals(command, result);
                // Connect directly to the proxy.
                try (ClientSession session = createSession(
                        client,
                        "localhost", proxy.getPort(), "user2", "user2",
                        null, -1, null, null)) {
                    assertTrue(session.isOpen());
                }
            }
        }
    }

    @Test
    public void testProxyWithHostKeyVerification() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer()) {

            File knownHosts = prepareHostKeySetup(server, proxy);
            try (SshClient client = setupTestClient()) {
                // Setup client with a standard ServerKeyVerifier
                client.setServerKeyVerifier(
                        new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts.toPath()));
                client.start();

                // Connect via the proxy
                String command = "ls -la";
                String result;
                try (ClientSession session = createSession(
                        client,
                        "localhost", server.getPort(), "user1", "user1",
                        "localhost", proxy.getPort(), "user2", "user2")) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream errors = new ByteArrayOutputStream();
                    session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
                    result = out.toString();
                }
                assertEquals(command, result);
                // make sure the proxy session is closed / closing
                assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
            }
        }
    }

    protected File prepareHostKeySetup(SshServer server, SshServer proxy) throws Exception {
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
        File knownHosts = tmpClientDir.newFile("knownhosts");
        writeKnownHosts(server, knownHosts);
        // setup proxy with a forwarding filter to allow the local port forwarding
        proxy.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        proxy.start();
        writeKnownHosts(proxy, knownHosts);
        return knownHosts;
    }

    protected File writeKnownHosts(SshServer server, File knownHosts) throws Exception {
        KeyPair serverHostKey = GenericUtils.head(server.getKeyPairProvider().loadKeys(null));
        try (BufferedWriter writer = Files.newBufferedWriter(knownHosts.toPath(), StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            KnownHostHashValue.appendHostPattern(writer, "localhost", server.getPort());
            writer.append(' ');
            PublicKeyEntry.appendPublicKeyEntry(writer, serverHostKey.getPublic());
            writer.append('\n');
        }
        return knownHosts;
    }

    @SuppressWarnings("checkstyle:ParameterNumber")
    protected ClientSession createSession(
            SshClient client,
            String host, int port, String user, String password,
            String proxyHost, int proxyPort, String proxyUser, String proxyPassword)
            throws java.io.IOException {
        ClientSession session;
        if (proxyHost != null) {
            proxySession = client.connect(proxyUser, proxyHost, proxyPort)
                    .verify(CONNECT_TIMEOUT).getSession();
            proxySession.addPasswordIdentity(proxyPassword);
            proxySession.auth().verify(AUTH_TIMEOUT);
            SshdSocketAddress address = new SshdSocketAddress(host, port);
            ExplicitPortForwardingTracker tracker = proxySession.createLocalPortForwardingTracker(
                    SshdSocketAddress.LOCALHOST_ADDRESS, address);
            SshdSocketAddress bound = tracker.getBoundAddress();
            session = client.connect(user, bound.getHostName(), bound.getPort())
                    .verify(CONNECT_TIMEOUT).getSession();
            session.addCloseFutureListener(f -> IoUtils.closeQuietly(tracker, proxySession));
        } else {
            session = client.connect(user, host, port).verify(CONNECT_TIMEOUT).getSession();
        }
        session.addPasswordIdentity(password);
        session.auth().verify(AUTH_TIMEOUT);
        return session;
    }

}
