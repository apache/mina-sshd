/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeepAliveTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    private static final int HEARTBEAT = 2000;
    private static final int TIMEOUT = 4000;
    private static final int WAIT = 8000;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        FactoryManagerUtils.updateProperty(sshd, FactoryManager.IDLE_TIMEOUT, TIMEOUT);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientNew() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.TIMEOUT, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithHeartBeatNew() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.HEARTBEAT_INTERVAL, HEARTBEAT);
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.TIMEOUT, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testShellClosedOnClientTimeout() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(9L, TimeUnit.SECONDS);

                assertTrue("Latch time out", TestEchoShellFactory.TestEchoShell.latch.await(10L, TimeUnit.SECONDS));
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF | ClientChannel.OPENED, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testShellClosedOnClientTimeoutNew() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            try (ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                 ByteArrayOutputStream out = new ByteArrayOutputStream();
                 ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(9L, TimeUnit.SECONDS);

                assertTrue("Latch time out", TestEchoShellFactory.TestEchoShell.latch.await(10L, TimeUnit.SECONDS));
                int state = channel.waitFor(ClientChannel.CLOSED, WAIT);
                assertEquals("Wrong channel state", ClientChannel.CLOSED | ClientChannel.EOF | ClientChannel.OPENED, state);

                channel.close(false);
            }
        } finally {
            client.stop();
        }
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
