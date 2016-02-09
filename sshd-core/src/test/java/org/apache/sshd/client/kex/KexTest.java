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
package org.apache.sshd.client.kex;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.TeeOutputStream;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test client key exchange algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class KexTest extends BaseTestSupport {

    private final BuiltinDHFactories factory;
    private SshServer sshd;
    private int port;

    public KexTest(BuiltinDHFactories factory) {
        this.factory = factory;
    }

    @Parameters(name = "Factory={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(BuiltinDHFactories.VALUES);
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
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
    public void testClientKeyExchange() throws Exception {
        if (factory.isGroupExchange()) {
            assertEquals(factory.getName() + " not supported even though DH group exchange supported",
                         SecurityUtils.isDHGroupExchangeSupported(), factory.isSupported());
        }

        Assume.assumeTrue(factory.getName() + " not supported", factory.isSupported());
        testClient(ClientBuilder.DH2KEX.transform(factory));
    }

    private void testClient(NamedFactory<KeyExchange> kex) throws Exception {
        try (ByteArrayOutputStream sent = new ByteArrayOutputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            try (SshClient client = setupTestClient()) {
                client.setKeyExchangeFactories(Collections.singletonList(kex));
                client.start();

                try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                    session.addPasswordIdentity(getCurrentTestName());
                    session.auth().verify(5L, TimeUnit.SECONDS);

                    try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL);
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

                        Collection<ClientChannelEvent> result =
                                channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                        assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));
                    }
                } finally {
                    client.stop();
                }
            }

            assertArrayEquals(kex.getName(), sent.toByteArray(), out.toByteArray());
        }
    }
}
