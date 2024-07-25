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

package org.apache.sshd.server;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.ServerTest.TestEchoShellFactory;
import org.apache.sshd.server.session.AbstractServerSession;
import org.apache.sshd.server.session.ServerProxyAcceptor;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class ServerProxyAcceptorTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;

    public ServerProxyAcceptorTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setShellFactory(new TestEchoShellFactory());
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

    @Test
    void clientAddressOverride() throws Exception {
        SshdSocketAddress expectedClientAddress = new SshdSocketAddress("7.3.6.5", 7365);
        String proxyMetadata = getCurrentTestName()
                               + " " + expectedClientAddress.getHostName()
                               + " " + expectedClientAddress.getPort();
        byte[] metaDataBytes = (proxyMetadata + IoUtils.EOL).getBytes(StandardCharsets.UTF_8);
        sshd.setServerProxyAcceptor(new ServerProxyAcceptor() {
            private final AtomicInteger invocationCount = new AtomicInteger(0);

            @Override
            public boolean acceptServerProxyMetadata(ServerSession session, Buffer buffer) throws Exception {
                if (buffer.available() < metaDataBytes.length) {
                    return false; // wait for more data
                }

                byte[] rawData = new byte[metaDataBytes.length];
                buffer.getRawBytes(rawData);
                outputDebugMessage("acceptServerProxyMetadata(%s) proxy data: %s", session,
                        new String(rawData, StandardCharsets.UTF_8));
                assertArrayEquals(metaDataBytes, rawData, "Mismatched meta data");

                int count = invocationCount.incrementAndGet();
                if (count == 1) {
                    ((AbstractServerSession) session).setClientAddress(expectedClientAddress);
                } else {
                    assertSame(expectedClientAddress,
                            session.getClientAddress(),
                            "Mismatched client address for invocation #" + count);
                }
                return true; // proxy completed
            }
        });

        Semaphore sessionSignal = new Semaphore(0);
        sshd.addSessionListener(new SessionListener() {
            @Override
            public void sessionEvent(Session session, Event event) {
                verifyClientAddress(event.name(), session);
                if (Event.KeyEstablished.equals(event)) {
                    sessionSignal.release();
                }
            }

            @Override
            public void sessionClosed(Session session) {
                verifyClientAddress("sessionClosed", session);
            }

            private void verifyClientAddress(String location, Session session) {
                assertObjectInstanceOf(location + ": not a server session", ServerSession.class, session);
                SocketAddress actualClientAddress = ((ServerSession) session).getClientAddress();
                assertSame(expectedClientAddress, actualClientAddress, location + ": mismatched client address instance");
            }
        });
        sshd.start();

        client.setClientProxyConnector(session -> {
            IoSession ioSession = session.getIoSession();
            ioSession.writeBuffer(new ByteArrayBuffer(metaDataBytes));
        });
        client.start();

        try (ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshd.getPort()).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            assertTrue(sessionSignal.tryAcquire(DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "Failed to receive session signal on time");
        } finally {
            client.stop();
        }
    }
}
