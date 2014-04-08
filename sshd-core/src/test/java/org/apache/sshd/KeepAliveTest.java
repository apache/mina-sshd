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
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusPublickeyAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeepAliveTest extends BaseTest {

    private SshServer sshd;
    private int port;

    private int heartbeat = 2000;
    private int timeout = 4000;
    private int wait = 8000;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.getProperties().put(ServerFactoryManager.IDLE_TIMEOUT, Integer.toString(timeout));
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
            Thread.sleep(50);
        }
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF, state);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testClientNew() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF, state);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.getProperties().put(ClientFactoryManager.HEARTBEAT_INTERVAL, Integer.toString(heartbeat));
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.TIMEOUT, state);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testClientWithHeartBeatNew() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.getProperties().put(ClientFactoryManager.HEARTBEAT_INTERVAL, Integer.toString(heartbeat));
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.TIMEOUT, state);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testShellClosedOnClientTimeout() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open().await();


        TestEchoShellFactory.TestEchoShell.latch.await();
        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF | ClientChannel.OPENED, state);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testShellClosedOnClientTimeoutNew() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open().await();


        TestEchoShellFactory.TestEchoShell.latch.await();
        int state = channel.waitFor(ClientChannel.CLOSED, wait);
        assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF | ClientChannel.OPENED, state);

        channel.close(false);
        client.stop();
    }


    public static class TestEchoShellFactory extends EchoShellFactory {
        @Override
        public Command create() {
            return new TestEchoShell();
        }
        public static class TestEchoShell extends EchoShell {

            public static CountDownLatch latch;

            @Override
            public void destroy() {
                if (latch != null) {
                    latch.countDown();
                }
                super.destroy();
            }
        }
    }

}
