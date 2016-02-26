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
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.local.LocalAgentFactory;
import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.agent.unix.AgentServer;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.EchoShell;
import org.apache.sshd.util.test.EchoShellFactory;
import org.apache.sshd.util.test.Utils;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AgentTest extends BaseTestSupport {
    public AgentTest() {
        super();
    }

    @Test
    public void testAgentServer() throws Exception {
        // TODO: revisit this test to work without BC
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());

        try (AgentServer agent = new AgentServer()) {
            String authSocket;
            try {
                authSocket = agent.start();
            } catch (RuntimeException e) {
                Throwable cause = e.getCause();
                if (cause instanceof UnsatisfiedLinkError) {
                    // the native library is not available, so these tests should be skipped
                    authSocket = null;
                } else {
                    throw e;
                }
            }
            Assume.assumeTrue("Native library N/A", authSocket != null);

            try (SshAgent client = new AgentClient(authSocket)) {
                List<Pair<PublicKey, String>> keys = client.getIdentities();
                assertNotNull("No initial identities", keys);
                assertEquals("Unexpected initial identities size", 0, keys.size());

                KeyPair k = createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
                client.addIdentity(k, "");
                keys = client.getIdentities();
                assertNotNull("No registered identities after add", keys);
                assertEquals("Mismatched registered keys size", 1, keys.size());

                client.removeIdentity(k.getPublic());
                keys = client.getIdentities();
                assertNotNull("No registered identities after remove", keys);
                assertEquals("Registered keys size not empty", 0, keys.size());

                client.removeAllIdentities();
            }
        }
    }

    @Test
    @SuppressWarnings("checkstyle:nestedtrydepth")
    public void testAgentForwarding() throws Exception {
        // TODO: revisit this test to work without BC
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());

        TestEchoShellFactory shellFactory = new TestEchoShellFactory();
        ProxyAgentFactory agentFactory = new ProxyAgentFactory();
        LocalAgentFactory localAgentFactory = new LocalAgentFactory();
        String username = getCurrentTestName();
        KeyPair pair = Utils.createTestKeyPairProvider("dsaprivkey.pem").loadKey(KeyPairProvider.SSH_DSS);
        localAgentFactory.getAgent().addIdentity(pair, username);

        try (SshServer sshd1 = setupTestServer()) {
            sshd1.setShellFactory(shellFactory);
            sshd1.setAgentFactory(agentFactory);
            sshd1.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
            sshd1.start();

            final int port1 = sshd1.getPort();
            try (SshServer sshd2 = setupTestServer()) {
                sshd2.setShellFactory(new TestEchoShellFactory());
                sshd1.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
                sshd2.setAgentFactory(new ProxyAgentFactory());
                sshd2.start();

                final int port2 = sshd2.getPort();
                try (SshClient client1 = setupTestClient()) {
                    client1.setAgentFactory(localAgentFactory);
                    client1.start();

                    try (ClientSession session1 = client1.connect(username, TEST_LOCALHOST, port1).verify(7L, TimeUnit.SECONDS).getSession()) {
                        session1.auth().verify(15L, TimeUnit.SECONDS);

                        try (ChannelShell channel1 = session1.createShellChannel();
                             ByteArrayOutputStream out = new ByteArrayOutputStream();
                             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                            channel1.setOut(out);
                            channel1.setErr(err);
                            channel1.setAgentForwarding(true);
                            channel1.open().verify(9L, TimeUnit.SECONDS);

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

                                    try (ClientSession session2 = client2.connect(username, TEST_LOCALHOST, port2).verify(7L, TimeUnit.SECONDS).getSession()) {
                                        session2.auth().verify(15L, TimeUnit.SECONDS);

                                        try (ChannelShell channel2 = session2.createShellChannel()) {
                                            channel2.setIn(shellFactory.shell.getIn());
                                            channel2.setOut(shellFactory.shell.getOut());
                                            channel2.setErr(shellFactory.shell.getErr());
                                            channel2.setAgentForwarding(true);
                                            channel2.open().verify(9L, TimeUnit.SECONDS);

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
        public Command create() {
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
        public synchronized void start(Environment env) throws IOException {
            super.start(env);
            started = true;
            notifyAll();
        }
    }
}
