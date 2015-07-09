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
package org.apache.sshd.client.kex;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.TeeOutputStream;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Test client key exchange algorithms.
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KexTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    public KexTest() {
        super();
    }

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
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    public void testClientKeyExchanges() throws Exception {
        Exception   err=null;

        for (BuiltinDHFactories f : BuiltinDHFactories.VALUES) {
            if (!f.isSupported()) {
                System.out.println("Skip KEX=" + f.getName() + " - unsupported");
                continue;
            }
            
            try {
                testClient(f);
            } catch(Exception e) {
                System.err.println(e.getClass().getSimpleName() + " while test KEX=" + f.getName() + ": " + e.getMessage());
                err = e;
            }
        }
        
        if (err != null) {
            throw err;
        }
    }

    private void testClient(DHFactory factory) throws Exception {
        testClient(ClientBuilder.DH2KEX.transform(factory));
    }

    private void testClient(NamedFactory<KeyExchange> kex) throws Exception {
        System.out.println("testClient - KEX=" + kex.getName());

        try(ByteArrayOutputStream sent = new ByteArrayOutputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            try(SshClient client = SshClient.setUpDefaultClient()) {
                client.setKeyExchangeFactories(Collections.singletonList(kex));
                client.start();
                
                try(ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);
                    
                    try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                        PipedOutputStream pipedIn = new PipedOutputStream();
                        InputStream inPipe = new PipedInputStream(pipedIn);
                        ByteArrayOutputStream err = new ByteArrayOutputStream();
                        OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {
    
                        channel.setIn(inPipe);
                        channel.setOut(out);
                        channel.setErr(err);
                        channel.open().verify(9L, TimeUnit.SECONDS);
            
                        teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                        teeOut.flush();
            
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < 10; i++) {
                            sb.append("0123456789");
                        }
                        sb.append("\n");
                        teeOut.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            
                        teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                        teeOut.flush();
            
                        channel.waitFor(ClientChannel.CLOSED, 0);
                    }
                } finally {
                    client.stop();
                }
            }
    
            assertArrayEquals(kex.getName(), sent.toByteArray(), out.toByteArray());
        }
    }
}
