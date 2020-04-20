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
package org.apache.sshd.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.agent.local.LocalAgentFactory;
import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.agent.unix.AgentServer;
import org.apache.sshd.agent.unix.AprLibrary;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AgentTest extends BaseTestSupport {
    public AgentTest() {
        super();
    }

    @BeforeClass
    public static void checkTestAssumptions() {
        // TODO: revisit this test to work without BC
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        AprLibrary library = null;
        try {
            library = AprLibrary.getInstance();
        } catch (RuntimeException e) {
            Throwable cause = e.getCause();
            if (cause instanceof UnsatisfiedLinkError) {
                library = null;
            } else {
                throw e;
            }
        }
        Assume.assumeTrue("Native library N/A", library != null);
    }

    @Test
    public void testAgentServer() throws Exception {
        try (AgentServer agent = new AgentServer()) {
            String authSocket = agent.start();

            FactoryManager manager = Mockito.mock(FactoryManager.class);
            Mockito.when(manager.getParentPropertyResolver()).thenReturn(null);
            Mockito.when(manager.getProperties()).thenReturn(Collections.emptyMap());

            try (SshAgent client = new AgentClient(manager, authSocket)) {
                Iterable<? extends Map.Entry<PublicKey, String>> keys = client.getIdentities();
                assertNotNull("No initial identities", keys);
                assertObjectInstanceOf("Non collection initial identities", Collection.class, keys);
                assertEquals("Unexpected initial identities size", 0, ((Collection<?>) keys).size());

                KeyPairProvider provider = createTestHostKeyProvider();
                KeyPair k = provider.loadKey(null, KeyPairProvider.SSH_RSA);
                client.addIdentity(k, "");
                keys = client.getIdentities();
                assertNotNull("No registered identities after add", keys);
                assertObjectInstanceOf("Non collection registered identities", Collection.class, keys);
                assertEquals("Mismatched registered keys size", 1, ((Collection<?>) keys).size());

                client.removeIdentity(k.getPublic());
                keys = client.getIdentities();
                assertNotNull("No registered identities after remove", keys);
                assertObjectInstanceOf("Non collection removed identities", Collection.class, keys);
                assertEquals("Registered keys size not empty", 0, ((Collection<?>) keys).size());

                client.removeAllIdentities();
            }
        }
    }

    @Test
    @SuppressWarnings("checkstyle:nestedtrydepth")
    public void testAgentForwarding() throws Exception {
        TestEchoShellFactory shellFactory = new TestEchoShellFactory();
        ProxyAgentFactory agentFactory = new ProxyAgentFactory();
        LocalAgentFactory localAgentFactory = new LocalAgentFactory();
        String username = getCurrentTestName();
        FileKeyPairProvider provider = CommonTestSupportUtils.createTestKeyPairProvider("dsaprivkey.pem");
        KeyPair pair = provider.loadKey(null, KeyPairProvider.SSH_DSS);
        localAgentFactory.getAgent().addIdentity(pair, username);

        try (SshServer sshd1 = setupTestServer()) {
            sshd1.setShellFactory(shellFactory);
            sshd1.setAgentFactory(agentFactory);
            sshd1.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
            sshd1.start();

            final int port1 = sshd1.getPort();
            try (SshServer sshd2 = setupTestServer()) {
                sshd2.setShellFactory(new TestEchoShellFactory());
                sshd1.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
                sshd2.setAgentFactory(new ProxyAgentFactory());
                sshd2.start();

                final int port2 = sshd2.getPort();
                try (SshClient client1 = setupTestClient()) {
                    client1.setAgentFactory(localAgentFactory);
                    client1.start();

                    try (ClientSession session1
                            = client1.connect(username, TEST_LOCALHOST, port1).verify(CONNECT_TIMEOUT).getSession()) {
                        session1.auth().verify(AUTH_TIMEOUT);

                        try (ChannelShell channel1 = session1.createShellChannel();
                             ByteArrayOutputStream out = new ByteArrayOutputStream();
                             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                            channel1.setOut(out);
                            channel1.setErr(err);
                            channel1.setAgentForwarding(true);
                            channel1.open().verify(OPEN_TIMEOUT);

                            try (OutputStream pipedIn = channel1.getInvertedIn()) {
                                synchronized (shellFactory.shell) {
                                    System.out.println("Possibly waiting for remote shell to start");
                                    if (!shellFactory.shell.started) {
                                        shellFactory.shell.wait();
                                    }
                                }

                                try (SshClient client2 = setupTestClient()) {
                                    client2.setAgentFactory(agentFactory);
                                    client2.getProperties().putAll(shellFactory.shell.getEnvironment().getEnv());
                                    client2.start();

                                    try (ClientSession session2 = client2.connect(username, TEST_LOCALHOST, port2)
                                            .verify(CONNECT_TIMEOUT).getSession()) {
                                        session2.auth().verify(AUTH_TIMEOUT);

                                        try (ChannelShell channel2 = session2.createShellChannel()) {
                                            channel2.setIn(shellFactory.shell.getInputStream());
                                            channel2.setOut(shellFactory.shell.getOutputStream());
                                            channel2.setErr(shellFactory.shell.getErrorStream());
                                            channel2.setAgentForwarding(true);
                                            channel2.open().verify(OPEN_TIMEOUT);

                                            pipedIn.write("foo\n".getBytes(StandardCharsets.UTF_8));
                                            pipedIn.flush();
                                        }

                                        Thread.sleep(1000);

                                        System.out.println(out.toString());
                                        System.err.println(err.toString());

                                        sshd1.stop(true);
                                        sshd2.stop(true);
                                        client1.stop();
                                        client2.stop();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public static class TestEchoShellFactory extends EchoShellFactory {
        // CHECKSTYLE:OFF
        public final TestEchoShell shell = new TestEchoShell();
        // CHECKSTYLE:ON

        public TestEchoShellFactory() {
            super();
        }

        @Override
        public Command createShell(ChannelSession channel) {
            return shell;
        }
    }

    public static class TestEchoShell extends EchoShell {
        // CHECKSTYLE:OFF
        public boolean started;
        // CHECKSTYLE:ON

        public TestEchoShell() {
            super();
        }

        @Override
        public synchronized void start(ChannelSession channel, Environment env) throws IOException {
            super.start(channel, env);
            started = true;
            notifyAll();
        }
    }
}
