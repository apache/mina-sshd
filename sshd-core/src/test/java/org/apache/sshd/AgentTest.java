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
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.local.ProxyAgentFactory;
import org.apache.sshd.agent.local.LocalAgentFactory;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.agent.unix.AgentServer;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.util.*;
import org.junit.Test;

import static org.apache.sshd.util.Utils.createTestKeyPairProvider;
import static org.apache.sshd.util.Utils.getFreePort;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeThat;

public class AgentTest {

    @Test
    public void testAgent() throws Exception {
        AgentServer agent = new AgentServer();
        String authSocket;
        try {
            authSocket = agent.start();
        } catch (UnsatisfiedLinkError e) {
            // the native library is not available, so these tests should be skipped
            authSocket = null;
        }
        assumeThat(authSocket, notNullValue());

        SshAgent client = new AgentClient(authSocket);
        List<SshAgent.Pair<PublicKey, String>> keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(0, keys.size());

        KeyPair[] k = Utils.createTestHostKeyProvider().loadKeys();
        client.addIdentity(k[0], "");
        keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(1, keys.size());

        client.removeIdentity(k[0].getPublic());
        keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(0, keys.size());

        client.removeAllIdentities();

        client.close();

        agent.close();
    }

    @Test
    public void testAgentForwarding() throws Exception {

        int port1 = getFreePort();
        int port2 = getFreePort();

        TestEchoShellFactory shellFactory = new TestEchoShellFactory();
        ProxyAgentFactory agentFactory = new ProxyAgentFactory();
        LocalAgentFactory localAgentFactory = new LocalAgentFactory();

        KeyPair pair = createTestKeyPairProvider("dsaprivkey.pem").loadKey(KeyPairProvider.SSH_DSS);
        localAgentFactory.getAgent().addIdentity(pair, "smx");

        SshServer sshd1 = SshServer.setUpDefaultServer();
        sshd1.setPort(port1);
        sshd1.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd1.setShellFactory(shellFactory);
        sshd1.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd1.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd1.setAgentFactory(agentFactory);
        sshd1.start();

        SshServer sshd2 = SshServer.setUpDefaultServer();
        sshd2.setPort(port2);
        sshd2.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd2.setShellFactory(new TestEchoShellFactory());
        sshd2.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd2.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd2.setAgentFactory(new ProxyAgentFactory());
        sshd2.start();

        SshClient client1 = SshClient.setUpDefaultClient();
        client1.setAgentFactory(localAgentFactory);
        client1.start();
        ClientSession session1 = client1.connect("localhost", port1).await().getSession();
        assertTrue(session1.authAgent("smx").await().isSuccess());
        ChannelShell channel1 = session1.createShellChannel();
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new TeePipedOutputStream(sent);
        channel1.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel1.setOut(out);
        channel1.setErr(err);
        channel1.setAgentForwarding(true);
        channel1.open().await();

        synchronized (shellFactory.shell) {
            System.out.println("Possibly waiting for remote shell to start");
            if (!shellFactory.shell.started) {
                shellFactory.shell.wait();
            }
        }

        SshClient client2 = SshClient.setUpDefaultClient();
        client2.setAgentFactory(agentFactory);
        client2.getProperties().putAll(shellFactory.shell.getEnvironment().getEnv());
        client2.start();
        ClientSession session2 = client2.connect("localhost", port2).await().getSession();
        assertTrue(session2.authAgent("smx").await().isSuccess());
        ChannelShell channel2 = session2.createShellChannel();
        channel2.setIn(shellFactory.shell.getIn());
        channel2.setOut(shellFactory.shell.getOut());
        channel2.setErr(shellFactory.shell.getErr());
        channel2.setAgentForwarding(true);
        channel2.open().await();

        pipedIn.write("foo\n".getBytes());
        pipedIn.flush();

        Thread.sleep(1000);

        System.out.println(out.toString());
        System.err.println(err.toString());

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
