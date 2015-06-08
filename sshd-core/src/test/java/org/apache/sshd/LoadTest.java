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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LoadTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.start();
        port  = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        sshd.stop(true);
    }

    @Test
    public void testLoad() throws Exception {
        test("this is my command", 4, 4);
    }

    @Test
    public void testHighLoad() throws Exception {
        final StringBuilder response = new StringBuilder(1000000);
        for (int i = 0; i < 100000; i++) {
            response.append("0123456789");
        }
        test(response.toString(), 1, 100);
    }

    @Test
    public void testBigResponse() throws Exception {
        final StringBuilder response = new StringBuilder(1000000);
        for (int i = 0; i < 100000; i++) {
            response.append("0123456789");
        }
        test(response.toString(), 1, 1);
    }

    protected void test(final String msg, final int nbThreads, final int nbSessionsPerThread) throws Exception {
        final List<Throwable> errors = new ArrayList<>();
        final CountDownLatch latch = new CountDownLatch(nbThreads);
        for (int i = 0; i < nbThreads; i++) {
            Runnable r = new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < nbSessionsPerThread; i++) {
                            runClient(msg);
                        }
                    } catch (Throwable t) {
                        errors.add(t);
                    } finally {
                        latch.countDown();
                    }
                }
            };
            new Thread(r).start();
        }
        latch.await();
        if (errors.size() > 0) {
            throw new Exception("Errors", errors.get(0));
        }
    }

    protected void runClient(String msg) throws Exception {
        try(SshClient client = SshClient.setUpDefaultClient()) {
            Map<String,Object>  props=client.getProperties();
            FactoryManagerUtils.updateProperty(props, FactoryManager.MAX_PACKET_SIZE, 1024 * 16);
            FactoryManagerUtils.updateProperty(props, FactoryManager.WINDOW_SIZE, 1024 * 8);
            client.setKeyExchangeFactories(Arrays.asList(
                    ClientBuilder.DH2KEX.transform(BuiltinDHFactories.dhg1)));
            client.setCipherFactories(Arrays.<NamedFactory<Cipher>>asList(BuiltinCiphers.blowfishcbc));
            client.start();
            try(ClientSession session = client.connect("sshd", "localhost", port).await().getSession()) {
                session.addPasswordIdentity("sshd");
                session.auth().verify(5L, TimeUnit.SECONDS);
    
                try(ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream err = new ByteArrayOutputStream();
                    ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                    channel.setOut(out);
                    channel.setErr(err);

                    try {
                        channel.open().await();
                        try(OutputStream pipedIn = channel.getInvertedIn()) {
                            msg += "\nexit\n";
                            pipedIn.write(msg.getBytes());
                            pipedIn.flush();
                        }
            
                        channel.waitFor(ClientChannel.CLOSED, 0);
                    } finally {    
                        channel.close(false);
                    }
    
                    assertArrayEquals("Mismatched message data", msg.getBytes(), out.toByteArray());
                }
            } finally {
                client.stop();
            }
        }
    }
}
