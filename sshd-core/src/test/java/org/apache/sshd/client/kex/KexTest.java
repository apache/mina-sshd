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
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.TeeOutputStream;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * Test client key exchange algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class KexTest extends BaseTestSupport {
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static SshServer sshd;
    private static int port;
    private static SshClient client;

    private final BuiltinDHFactories factory;

    public KexTest(BuiltinDHFactories factory) {
        this.factory = factory;
    }

    @Parameters(name = "Factory={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(BuiltinDHFactories.VALUES);
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(KexTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(KexTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @Test
    public void testClientKeyExchange() throws Exception {
        if (factory.isGroupExchange()) {
            assertEquals(factory.getName() + " not supported even though DH group exchange supported",
                    SecurityUtils.isDHGroupExchangeSupported(), factory.isSupported());
        }

        Assume.assumeTrue(factory.getName() + " not supported", factory.isSupported());
        testClient(ClientBuilder.DH2KEX.apply(factory));
    }

    private void testClient(KeyExchangeFactory kex) throws Exception {
        try (ByteArrayOutputStream sent = new ByteArrayOutputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            client.setKeyExchangeFactories(Collections.singletonList(kex));
            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL);
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn);
                     ByteArrayOutputStream err = new ByteArrayOutputStream();
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open().verify(OPEN_TIMEOUT);

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 10; i++) {
                        sb.append("0123456789");
                    }
                    sb.append('\n');
                    teeOut.write(sb.toString().getBytes(StandardCharsets.UTF_8));

                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    Collection<ClientChannelEvent> result = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TIMEOUT);
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));
                }
            }

            assertArrayEquals(kex.getName(), sent.toByteArray(), out.toByteArray());
        }
    }
}
