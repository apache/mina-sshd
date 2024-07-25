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
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.config.hosts.KnownHostHashValue;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.keyverifier.RejectAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.StaticDecisionForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class ProxyTest extends BaseTestSupport {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @TempDir
    private File tmpClientDir;

    private ClientSession proxySession;

    public ProxyTest() {
        super();
    }

    @Test
    void proxy() throws Exception {
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

            logger.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());

            // Connect through to the proxy.
            client.addPasswordIdentity("user2");
            try (ClientSession session = createSession(
                    client,
                    "localhost", server.getPort(), "user1", "user1",
                    "user2@localhost:" + proxy.getPort())) {
                assertTrue(session.isOpen());
                doTestCommand(session, "ls -al");
            }
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
        }
    }

    @Test
    void directWithHostKeyVerification() throws Exception {
        // This test exists only to show that the knownhosts setup is correct
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {

            File knownHosts = prepareHostKeySetup(server, proxy);
            // Setup client with a standard ServerKeyVerifier
            client.setServerKeyVerifier(
                    new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts.toPath()));
            client.start();

            logger.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());

            // Connect to the server directly to verify the knownhosts setup.
            try (ClientSession session = createSession(
                    client, "localhost", server.getPort(), "user1", "user1", null)) {
                assertTrue(session.isOpen());
                doTestCommand(session, "ls -al");
            }
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());

            // Connect through to the proxy.
            try (ClientSession session = createSession(
                    client, "localhost", proxy.getPort(), "user2", "user2", null)) {
                assertTrue(session.isOpen());
                assertThrows(RemoteException.class,
                        () -> doTestCommand(session, "ls -al"));
            }
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
        }
    }

    @Test
    void proxyWithHostKeyVerification() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {

            File knownHosts = prepareHostKeySetup(server, proxy);
            // Setup client with a standard ServerKeyVerifier
            client.setServerKeyVerifier(
                    new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts.toPath()));
            client.start();

            logger.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());

            // Connect via the proxy
            client.addPasswordIdentity("user2");
            try (ClientSession session = createSession(
                    client, "localhost", server.getPort(), "user1", "user1",
                    "user2@localhost:" + proxy.getPort())) {

                assertTrue(session.isOpen());
                doTestCommand(session, "ls -la");
            }
            // make sure the proxy session is closed / closing
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
        }
    }

    @Test
    void proxyWithHostKeyVerificationAndCustomConfig() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer();
             SshClient client = setupTestClient()) {

            File knownHosts = prepareHostKeySetup(server, proxy);
            // Setup client with a standard ServerKeyVerifier
            client.setServerKeyVerifier(
                    new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts.toPath()));
            client.start();
            client.setHostConfigEntryResolver(HostConfigEntry.toHostConfigEntryResolver(Arrays.asList(
                    new HostConfigEntry("server", "localhost", server.getPort(), "user1", "proxy"),
                    new HostConfigEntry("proxy", "localhost", proxy.getPort(), "user2"))));

            logger.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());

            // Connect via the proxy
            client.addPasswordIdentity("user1");
            client.addPasswordIdentity("user2");
            try (ClientSession session = client.connect("server")
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);

                assertTrue(session.isOpen());
                doTestCommand(session, "ls -la");
            }
            // make sure the proxy session is closed / closing
            assertTrue(proxySession == null || proxySession.isClosing() || proxySession.isClosed());
        }
    }

    @Test
    void proxyChain() throws Exception {
        try (SshServer target = setupTestServer();
             SshServer proxy1 = setupTestServer();
             SshServer proxy2 = setupTestServer();
             SshClient client = setupTestClient()) {
            target.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream stdout = getOutputStream();
                    stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                    stdout.flush();
                    return false;
                }
            });

            client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            client.setKeyIdentityProvider(s -> {
                return Collections.singletonList(kp);
            });
            target.setPublickeyAuthenticator((u, k, s) -> "userT".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy1.setPublickeyAuthenticator((u, k, s) -> "user1".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy2.setPublickeyAuthenticator((u, k, s) -> "user2".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            int[] forwarded = new int[2];
            proxy1.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[0] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            proxy2.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[1] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            target.start();
            proxy1.start();
            proxy2.start();
            client.setHostConfigEntryResolver(HostConfigEntry.toHostConfigEntryResolver(
                    Arrays.asList(new HostConfigEntry("target", "localhost", target.getPort(), "userT", "proxy2, proxy1"),
                            new HostConfigEntry("proxy1", "localhost", proxy1.getPort(), "user1"),
                            new HostConfigEntry("proxy2", "localhost", proxy2.getPort(), "user2"))));
            client.start();
            try (ClientSession session = client.connect("target").verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);

                assertTrue(session.isOpen());
                doTestCommand(session, "ls -la");
            }
            assertEquals(proxy2.getPort(), forwarded[0]);
            assertEquals(target.getPort(), forwarded[1]);
        }
    }

    @Test
    void proxyCascade() throws Exception {
        try (SshServer target = setupTestServer();
             SshServer proxy1 = setupTestServer();
             SshServer proxy2 = setupTestServer();
             SshClient client = setupTestClient()) {
            target.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream stdout = getOutputStream();
                    stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                    stdout.flush();
                    return false;
                }
            });

            client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            client.setKeyIdentityProvider(s -> {
                return Collections.singletonList(kp);
            });
            target.setPublickeyAuthenticator((u, k, s) -> "userT".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy1.setPublickeyAuthenticator((u, k, s) -> "user1".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy2.setPublickeyAuthenticator((u, k, s) -> "user2".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            int[] forwarded = new int[2];
            proxy1.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[0] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            proxy2.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[1] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            target.start();
            proxy1.start();
            proxy2.start();
            client.setHostConfigEntryResolver(HostConfigEntry.toHostConfigEntryResolver(
                    Arrays.asList(new HostConfigEntry("target", "localhost", target.getPort(), "userT", "proxy2"),
                            new HostConfigEntry("proxy1", "localhost", proxy1.getPort(), "user1"),
                            new HostConfigEntry("proxy2", "localhost", proxy2.getPort(), "user2", "proxy1"))));
            client.start();
            try (ClientSession session = client.connect("target").verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);

                assertTrue(session.isOpen());
                doTestCommand(session, "ls -la");
            }
            assertEquals(proxy2.getPort(), forwarded[0]);
            assertEquals(target.getPort(), forwarded[1]);
        }
    }

    @Test
    void proxyInfinite() throws Exception {
        try (SshServer target = setupTestServer();
             SshServer proxy1 = setupTestServer();
             SshServer proxy2 = setupTestServer();
             SshClient client = setupTestClient()) {
            target.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream stdout = getOutputStream();
                    stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                    stdout.flush();
                    return false;
                }
            });

            client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            client.setKeyIdentityProvider(s -> {
                return Collections.singletonList(kp);
            });
            target.setPublickeyAuthenticator((u, k, s) -> "userT".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy1.setPublickeyAuthenticator((u, k, s) -> "user1".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy2.setPublickeyAuthenticator((u, k, s) -> "user2".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            int[] forwarded = new int[2];
            proxy1.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[0] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            proxy2.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[1] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            target.start();
            proxy1.start();
            proxy2.start();
            client.setHostConfigEntryResolver(HostConfigEntry.toHostConfigEntryResolver(
                    Arrays.asList(new HostConfigEntry("target", "localhost", target.getPort(), "userT", "proxy2"),
                            new HostConfigEntry("proxy1", "localhost", proxy1.getPort(), "user1", "proxy2"),
                            new HostConfigEntry("proxy2", "localhost", proxy2.getPort(), "user2", "proxy1"))));
            client.start();
            Exception e = assertThrows(Exception.class, () -> {
                try (ClientSession session = client.connect("target").verify(CONNECT_TIMEOUT).getSession()) {
                    // Nothing
                }
            });
            // One exception should have a message "Too many proxy jumps"
            Throwable t = e;
            while (t != null) {
                if (t.getMessage().contains("Too many proxy jumps")) {
                    break;
                }
                t = t.getCause();
            }
            assertNotNull(t);
        }
    }

    @Test
    void proxyOverride() throws Exception {
        try (SshServer target = setupTestServer();
             SshServer proxy1 = setupTestServer();
             SshServer proxy2 = setupTestServer();
             SshClient client = setupTestClient()) {
            target.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
                @Override
                protected boolean handleCommandLine(String command) throws Exception {
                    OutputStream stdout = getOutputStream();
                    stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                    stdout.flush();
                    return false;
                }
            });

            client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
            KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            client.setKeyIdentityProvider(s -> {
                return Collections.singletonList(kp);
            });
            target.setPublickeyAuthenticator((u, k, s) -> "userT".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy1.setPublickeyAuthenticator((u, k, s) -> "user1".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            proxy2.setPublickeyAuthenticator((u, k, s) -> "user2".equals(u) && KeyUtils.compareKeys(k, kp.getPublic()));
            int[] forwarded = new int[2];
            proxy1.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[0] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            proxy2.setForwardingFilter(new StaticDecisionForwardingFilter(true) {

                @Override
                protected boolean checkAcceptance(String request, Session session, SshdSocketAddress target) {
                    forwarded[1] = target.getPort();
                    return super.checkAcceptance(request, session, target);
                }
            });
            target.start();
            proxy1.start();
            proxy2.start();
            // "Proxy3" should be ignored.
            client.setHostConfigEntryResolver(HostConfigEntry.toHostConfigEntryResolver(
                    Arrays.asList(new HostConfigEntry("target", "localhost", target.getPort(), "userT", "proxy2, proxy1"),
                            new HostConfigEntry("proxy1", "localhost", proxy1.getPort(), "user1"),
                            new HostConfigEntry("proxy2", "localhost", proxy2.getPort(), "user2", "proxy3"))));
            client.start();
            try (ClientSession session = client.connect("target").verify(CONNECT_TIMEOUT).getSession()) {
                session.auth().verify(AUTH_TIMEOUT);

                assertTrue(session.isOpen());
                doTestCommand(session, "ls -la");
            }
            assertEquals(proxy2.getPort(), forwarded[0]);
            assertEquals(target.getPort(), forwarded[1]);
        }
    }

    @Test
    @Disabled
    void external() throws Exception {
        try (SshServer server = setupTestServer();
             SshServer proxy = setupTestServer()) {

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

            logger.info("Proxy: " + proxy.getPort() + ", server: " + server.getPort());
            Thread.sleep(TimeUnit.MINUTES.toMillis(5));
        }
    }

    protected void doTestCommand(ClientSession session, String command) throws IOException {
        String result;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream errors = new ByteArrayOutputStream();
        session.executeRemoteCommand(command, out, errors, StandardCharsets.UTF_8);
        result = out.toString();
        assertEquals(command, result);
    }

    protected File prepareHostKeySetup(SshServer server, SshServer proxy) throws Exception {
        // setup server with an echo command
        server.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                return true;
            }
        });

        server.start();
        File knownHosts = File.createTempFile("knownhosts", null, tmpClientDir);
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
            String proxyJump)
            throws IOException {
        ClientSession session = client.connect(new HostConfigEntry(
                "", host, port, user,
                proxyJump))
                .verify(CONNECT_TIMEOUT).getSession();
        session.addPasswordIdentity(password);
        session.auth().verify(AUTH_TIMEOUT);
        return session;
    }

}
