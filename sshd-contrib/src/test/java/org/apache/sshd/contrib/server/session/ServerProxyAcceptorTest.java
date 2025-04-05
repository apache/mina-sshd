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

package org.apache.sshd.contrib.server.session;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.contrib.server.filter.HAProxyProtocolFilter;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
class ServerProxyAcceptorTest extends BaseTestSupport {

    private static final SshdSocketAddress EXPECTED_CLIENT_ADDRESS = new SshdSocketAddress("7.3.6.5", 7365);

    private static final Random RND = new JceRandom();

    private SshServer sshd;
    private SshClient client;

    ServerProxyAcceptorTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestServer();
        client = setupTestClient();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    static Stream<Arguments> parameters() {
        // A V1 proxy header
        final byte[] v1Header = "PROXY TCP4 7.3.6.5 7.3.6.6 7365 443\r\n".getBytes(StandardCharsets.US_ASCII);
        // A V2 proxy header
        Buffer buf = new ByteArrayBuffer();
        buf.putRawBytes(new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A });
        buf.putByte((byte) 0x21);
        buf.putByte((byte) 0x11);
        final int pos = buf.wpos();
        int length = 2 * Integer.BYTES + 2 * Short.BYTES;
        buf.putShort(length);
        buf.putUInt(0x07030605);
        buf.putUInt(0x07030606);
        buf.putShort(7365);
        buf.putShort(443);
        byte[] v2Header = buf.getCompactData();
        int end = buf.wpos();
        buf.wpos(end + 33333);
        RND.fill(buf.array(), end, 33333);
        end += 33333;
        buf.wpos(pos);
        buf.putShort(end - pos - 2);
        buf.wpos(end);
        return Stream.of(
                Arguments.of("V1 separate", v1Header, false),
                Arguments.of("V1 combined", v1Header, true),
                Arguments.of("V2 separate", v2Header, false),
                Arguments.of("V2 combined", v2Header, true),
                Arguments.of("No proxy header", null, false),
                Arguments.of("V2 large", buf.getCompactData(), false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("parameters")
    void clientAddressOverride(String name, byte[] proxyMessage, boolean combine) throws Exception {
        AtomicReference<SocketAddress> actualClientAddress1 = new AtomicReference<>();
        AtomicReference<SocketAddress> actualClientAddress2 = new AtomicReference<>();
        sshd.addSessionListener(new SessionListener() {

            @Override
            public void sessionStarting(Session session) {
                if (session instanceof ServerSession) {
                    // Register the HAProxy filter
                    FilterChain filters = session.getFilterChain();
                    filters.addFirst(new HAProxyProtocolFilter((ServerSession) session));
                }
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                if (session instanceof ServerSession) {
                    actualClientAddress1.set(((ServerSession) session).getClientAddress());
                }
            }

            @Override
            public void sessionClosed(Session session) {
                if (session instanceof ServerSession) {
                    actualClientAddress2.set(((ServerSession) session).getClientAddress());
                }
            }
        });
        sshd.start();

        client.addSessionListener(new SessionListener() {

            @Override
            public void sessionStarting(Session session) {
                // Add a filter that writes the fake HAProxy header before the first message
                FilterChain filters = session.getFilterChain();
                filters.addFirst(new IoFilter() {

                    private boolean proxyHeaderSent;

                    @Override
                    public InputHandler in() {
                        return null;
                    }

                    @Override
                    public OutputHandler out() {
                        return (cmd, message) -> {
                            if (proxyMessage != null && !proxyHeaderSent) {
                                if (combine) {
                                    byte[] combined = Arrays.copyOf(proxyMessage, proxyMessage.length + message.available());
                                    message.getRawBytes(combined, proxyMessage.length, message.available());
                                    IoWriteFuture future = owner().send(cmd, new ByteArrayBuffer(combined));
                                    proxyHeaderSent = true;
                                    return future;
                                }
                                owner().send(-1, new ByteArrayBuffer(proxyMessage));
                                proxyHeaderSent = true;
                            }
                            return owner().send(cmd, message);
                        };
                    }
                });
            }
        });
        client.start();

        CountDownLatch sessionClosed = new CountDownLatch(1);
        try (ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            session.close(false).addListener(f -> sessionClosed.countDown());
        } finally {
            client.stop();
        }
        sessionClosed.await(CLOSE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        SocketAddress address1 = actualClientAddress1.get();
        assertNotNull(address1, "Client address should be set");
        SocketAddress address2 = actualClientAddress2.get();
        assertSame(address1, address2, "Client address should not change");
        assertInstanceOf(InetSocketAddress.class, address1);
        InetSocketAddress inet = (InetSocketAddress) address1;
        if (proxyMessage != null) {
            assertEquals(EXPECTED_CLIENT_ADDRESS.getHostName(), inet.getHostString(), "Host mismatch");
            assertEquals(EXPECTED_CLIENT_ADDRESS.getPort(), inet.getPort(), "Port mismatch");
        } else {
            assertEquals("127.0.0.1", inet.getHostString(), "Host mismatch");
        }
    }
}
