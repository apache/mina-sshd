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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.client.kex.DHG1;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.TeePipedOutputStream;
import org.junit.After;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class LoadTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        sshd.stop();
    }

    @Test
    public void testLoad() throws Exception {
        final int nbThreads = 4;
        final int nbSessionsPerThread = 4;
        final CountDownLatch latch = new CountDownLatch(nbThreads);

        for (int i = 0; i < nbThreads; i++) {
            Runnable r = new Runnable() {
                public void run() {
                    try {
                        testClient(nbSessionsPerThread);
                    } catch (Throwable t) {
                        t.printStackTrace();
                    } finally {
                        latch.countDown();
                    }
                }
            };
            new Thread(r).start();
        }

        latch.await();
    }

    protected void testClient(int nbSessionsPerThread) throws Exception {
        for (int i = 0; i < nbSessionsPerThread; i++) {
            runClient();
        }
    }

    protected void runClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                new DHG1.Factory()));
        client.setCipherFactories(Arrays.<NamedFactory<Cipher>>asList(
                new BlowfishCBC.Factory()));
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("sshd", "sshd").await().isSuccess();

        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new TeePipedOutputStream(sent);
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        pipedIn.write("this is my command\n".getBytes());
        pipedIn.flush();

        pipedIn.write("exit\n".getBytes());
        pipedIn.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }
}
