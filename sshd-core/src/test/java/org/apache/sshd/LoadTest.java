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
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestMethodOrder(MethodName.class)
public class LoadTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    public LoadTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestFullSupportServer();
        sshd.start();
        port = sshd.getPort();
    }

    @AfterEach
    void tearDown() throws Exception {
        sshd.stop(true);
    }

    @Test
    void load() throws Exception {
        test("this is my command", 4, 4);
    }

    @Test
    void highLoad() throws Exception {
        final StringBuilder response = new StringBuilder(1000000);
        for (int i = 0; i < 100000; i++) {
            response.append("0123456789");
        }
        test(response.toString(), 1, 100);
    }

    @Test
    void bigResponse() throws Exception {
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
            Runnable r = () -> {
                try {
                    for (int i1 = 0; i1 < nbSessionsPerThread; i1++) {
                        runClient(msg);
                    }
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    latch.countDown();
                }
            };
            new Thread(r).start();
        }
        latch.await();
        if (errors.size() > 0) {
            throw new Exception("Errors", errors.get(0));
        }
    }

    @SuppressWarnings("checkstyle:nestedtrydepth")
    protected void runClient(String msg) throws Exception {
        try (SshClient client = setupTestFullSupportClient()) {
            CoreModuleProperties.MAX_PACKET_SIZE.set(client, 1024L * 16);
            CoreModuleProperties.WINDOW_SIZE.set(client, 1024L * 8);
            client.start();
            try (ClientSession session
                    = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (ByteArrayOutputStream out = new ByteArrayOutputStream();
                     ByteArrayOutputStream err = new ByteArrayOutputStream();
                     ClientChannel channel = session.createChannel(Channel.CHANNEL_SHELL)) {
                    channel.setOut(out);
                    channel.setErr(err);

                    try {
                        channel.open().verify(OPEN_TIMEOUT);
                        try (OutputStream pipedIn = channel.getInvertedIn()) {
                            msg += "\nexit\n";
                            pipedIn.write(msg.getBytes(StandardCharsets.UTF_8));
                            pipedIn.flush();
                        }

                        Collection<ClientChannelEvent> result
                                = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(15L));
                        assertFalse(result.contains(ClientChannelEvent.TIMEOUT), "Timeout while waiting for channel closure");
                    } finally {
                        channel.close(false);
                    }

                    assertArrayEquals(msg.getBytes(StandardCharsets.UTF_8), out.toByteArray(), "Mismatched message data");
                }
            } finally {
                client.stop();
            }
        }
    }
}
