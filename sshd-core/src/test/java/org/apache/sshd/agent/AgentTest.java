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
package org.apache.sshd.agent;

import static org.apache.sshd.util.Utils.createTestKeyPairProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.local.LocalAgentFactory;
import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.agent.unix.AgentServer;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.PublickeyAuthenticator.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
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

        try(AgentServer agent = new AgentServer()) {
            String authSocket;
            try {
                authSocket = agent.start();
            } catch (UnsatisfiedLinkError e) {
                // the native library is not available, so these tests should be skipped
                authSocket = null;
            }
            Assume.assumeTrue("Native library N/A", authSocket != null);
    
            try(SshAgent client = new AgentClient(authSocket)) {
                List<SshAgent.Pair<PublicKey, String>> keys = client.getIdentities();
                assertNotNull("No initial identities", keys);
                assertEquals("Unexpected initial identities size", 0, keys.size());
        
                KeyPair k = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
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
    public void testAgentForwarding() throws Exception {
        // TODO: revisit this test to work without BC
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());

        TestEchoShellFactory shellFactory = new TestEchoShellFactory();
        ProxyAgentFactory agentFactory = new ProxyAgentFactory();
        LocalAgentFactory localAgentFactory = new LocalAgentFactory();
        String username = getCurrentTestName();
        KeyPair pair = createTestKeyPairProvider("dsaprivkey.pem").loadKey(KeyPairProvider.SSH_DSS);
        localAgentFactory.getAgent().addIdentity(pair, username);

        try(SshServer sshd1 = SshServer.setUpDefaultServer()) {
            sshd1.setKeyPairProvider(Utils.createTestHostKeyProvider());
            sshd1.setShellFactory(shellFactory);
            sshd1.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
            sshd1.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
            sshd1.setAgentFactory(agentFactory);
            sshd1.setTcpipForwardingFilter(ForwardingFilter.AcceptAllForwardingFilter.INSTANCE);
            sshd1.start();
            
            final int port1 = sshd1.getPort();
            try(SshServer sshd2 = SshServer.setUpDefaultServer()) {
                sshd2.setKeyPairProvider(Utils.createTestHostKeyProvider());
                sshd2.setShellFactory(new TestEchoShellFactory());
                sshd2.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
                sshd2.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
                sshd1.setTcpipForwardingFilter(ForwardingFilter.AcceptAllForwardingFilter.INSTANCE);
                sshd2.setAgentFactory(new ProxyAgentFactory());
                sshd2.start();
    
                final int port2 = sshd2.getPort();
                try(SshClient client1 = SshClient.setUpDefaultClient()) {
                    client1.setAgentFactory(localAgentFactory);
                    client1.start();
                    
                    try(ClientSession session1 = client1.connect(username, "localhost", port1).await().getSession()) {
                        session1.auth().verify(15L, TimeUnit.SECONDS);

                        try(ChannelShell channel1 = session1.createShellChannel();
                            ByteArrayOutputStream out = new ByteArrayOutputStream();
                            ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                            channel1.setOut(out);
                            channel1.setErr(err);
                            channel1.setAgentForwarding(true);
                            channel1.open().await();
                            
                            try(OutputStream pipedIn = channel1.getInvertedIn()) {
                                synchronized (shellFactory.shell) {
                                    System.out.println("Possibly waiting for remote shell to start");
                                    if (!shellFactory.shell.started) {
                                        shellFactory.shell.wait();
                                    }
                                }
                        
                                try(SshClient client2 = SshClient.setUpDefaultClient()) {
                                    client2.setAgentFactory(agentFactory);
                                    client2.getProperties().putAll(shellFactory.shell.getEnvironment().getEnv());
                                    client2.start();
                                    
                                    try(ClientSession session2 = client2.connect(username, "localhost", port2).await().getSession()) {
                                        session2.auth().verify(15L, TimeUnit.SECONDS);

                                        try(ChannelShell channel2 = session2.createShellChannel()) {
                                            channel2.setIn(shellFactory.shell.getIn());
                                            channel2.setOut(shellFactory.shell.getOut());
                                            channel2.setErr(shellFactory.shell.getErr());
                                            channel2.setAgentForwarding(true);
                                            channel2.open().await();
                                    
                                            pipedIn.write("foo\n".getBytes());
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

        TestEchoShell shell = new TestEchoShell();

        @Override
        public Command create() {
            return shell;
        }

        public class TestEchoShell extends EchoShell {

            boolean started;

            @Override
            public synchronized void start(Environment env) throws IOException {
                super.start(env);
                started = true;
                notifyAll();
            }
        }
    }
}
