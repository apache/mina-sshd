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

import java.net.ServerSocket;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusPublickeyAuthenticator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeepAliveTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.getProperties().put(ServerFactoryManager.IDLE_TIMEOUT, "1000");
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new ClientTest.TestEchoShellFactory());
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

        int state = channel.waitFor(ClientChannel.CLOSED, 2000);
        assertTrue((state & ClientChannel.CLOSED) != 0);

        channel.close(false);
        client.stop();
    }

    @Test
    public void testClientWithHeartBeat() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.getProperties().put(ClientFactoryManager.HEARTBEAT_INTERVAL, "500");
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        int state = channel.waitFor(ClientChannel.CLOSED, 2000);
        assertTrue((state & ClientChannel.CLOSED) == 0);

        channel.close(false);
        client.stop();
    }

}
