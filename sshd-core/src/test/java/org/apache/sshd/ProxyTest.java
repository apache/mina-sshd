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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.DynamicPortForwardingTracker;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ProxyTest extends BaseTestSupport {
    private SshServer sshd;
    private int sshPort;
    private int echoPort;
    private IoAcceptor acceptor;
    private SshClient client;

    @SuppressWarnings("checkstyle:anoninnerlength")
    private final PortForwardingEventListener serverSideListener = new PortForwardingEventListener() {
        private final Logger log = LoggerFactory.getLogger(ProxyTest.class);

        @Override
        public void establishingExplicitTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                SshdSocketAddress remote, boolean localForwarding)
                throws IOException {
            log.info("establishingExplicitTunnel(session={}, local={}, remote={}, localForwarding={})",
                    session, local, remote, localForwarding);
        }

        @Override
        public void establishedExplicitTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                SshdSocketAddress remote, boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
                throws IOException {
            log.info("establishedExplicitTunnel(session={}, local={}, remote={}, bound={}, localForwarding={}): {}",
                    session, local, remote, boundAddress, localForwarding, reason);
        }

        @Override
        public void tearingDownExplicitTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                SshdSocketAddress remoteAddress)
                throws IOException {
            log.info("tearingDownExplicitTunnel(session={}, address={}, localForwarding={}, remote={})",
                    session, address, localForwarding, remoteAddress);
        }

        @Override
        public void tornDownExplicitTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                SshdSocketAddress remoteAddress, Throwable reason)
                throws IOException {
            log.info("tornDownExplicitTunnel(session={}, address={}, localForwarding={}, remote={}, reason={})",
                    session, address, localForwarding, remoteAddress, reason);
        }

        @Override
        public void establishingDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local)
                throws IOException {
            log.info("establishingDynamicTunnel(session={}, local={})", session, local);
        }

        @Override
        public void establishedDynamicTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                SshdSocketAddress boundAddress, Throwable reason)
                throws IOException {
            log.info("establishedDynamicTunnel(session={}, local={}, bound={}, reason={})", session, local, boundAddress,
                    reason);
        }

        @Override
        public void tearingDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address)
                throws IOException {
            log.info("tearingDownDynamicTunnel(session={}, address={})", session, address);
        }

        @Override
        public void tornDownDynamicTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress address,
                Throwable reason)
                throws IOException {
            log.info("tornDownDynamicTunnel(session={}, address={}, reason={})", session, address, reason);
        }
    };

    public ProxyTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        CoreModuleProperties.WINDOW_SIZE.set(sshd, 2048L);
        CoreModuleProperties.MAX_PACKET_SIZE.set(sshd, 256L);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.addPortForwardingEventListener(serverSideListener);
        sshd.start();
        sshPort = sshd.getPort();

        NioSocketAcceptor acceptor = new NioSocketAcceptor();
        acceptor.setHandler(new IoHandlerAdapter() {
            @Override
            public void messageReceived(IoSession session, Object message) throws Exception {
                IoBuffer recv = (IoBuffer) message;
                IoBuffer sent = IoBuffer.allocate(recv.remaining());
                sent.put(recv);
                sent.flip();
                session.write(sent);
            }
        });
        acceptor.setReuseAddress(true);
        acceptor.bind(new InetSocketAddress(0));
        echoPort = acceptor.getLocalAddress().getPort();
        this.acceptor = acceptor;
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (acceptor != null) {
            acceptor.dispose(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testSocksProxy() throws Exception {
        final AtomicReference<SshdSocketAddress> localAddressHolder = new AtomicReference<>();
        final AtomicReference<SshdSocketAddress> boundAddressHolder = new AtomicReference<>();
        final AtomicInteger tearDownSignal = new AtomicInteger(0);
        @SuppressWarnings("checkstyle:anoninnerlength")
        PortForwardingEventListener listener = new PortForwardingEventListener() {
            @Override
            public void tornDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress, Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected explicit tunnel torn down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void tornDownDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, Throwable reason)
                    throws IOException {
                assertNotNull("Establishment (local) indication not invoked for address=" + address, localAddressHolder.get());
                assertNotNull("Establishment (bound) indication not invoked for address=" + address, boundAddressHolder.get());
                assertEquals("No tear down indication", 1, tearDownSignal.get());
            }

            @Override
            public void tearingDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected explicit tunnel tear down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void tearingDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address)
                    throws IOException {
                assertNotNull("Establishment (local) indication not invoked for address=" + address, localAddressHolder.get());
                assertNotNull("Establishment (bound) indication not invoked for address=" + address, boundAddressHolder.get());
                assertEquals("Multiple tearing down indications", 1, tearDownSignal.incrementAndGet());
            }

            @Override
            public void establishingExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress remote,
                    boolean localForwarding)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected explicit tunnel establishment indication: session=" + session + ", address=" + local);
            }

            @Override
            public void establishingDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local)
                    throws IOException {
                assertNull("Multiple calls to establishment indicator", localAddressHolder.getAndSet(local));
            }

            @Override
            public void establishedExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                    SshdSocketAddress remote, boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected explicit tunnel established indication: session=" + session + ", address=" + boundAddress);
            }

            @Override
            public void establishedDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress boundAddress,
                    Throwable reason)
                    throws IOException {
                assertSame("Establishment indication not invoked", local, localAddressHolder.get());
                assertNull("Multiple calls to establishment indicator", boundAddressHolder.getAndSet(boundAddress));
            }

            @Override
            public String toString() {
                return getCurrentTestName();
            }
        };

        try (ClientSession session = createNativeSession(listener)) {
            String expected = getCurrentTestName();
            byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
            byte[] buf = new byte[bytes.length + Long.SIZE];

            SshdSocketAddress dynamic;
            try (DynamicPortForwardingTracker tracker
                    = session.createDynamicPortForwardingTracker(new SshdSocketAddress(TEST_LOCALHOST, 0))) {
                dynamic = tracker.getBoundAddress();
                assertTrue("Tracker not marked as open", tracker.isOpen());

                for (int i = 0; i < 10; i++) {
                    try (Socket s = new Socket(
                            new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(TEST_LOCALHOST, dynamic.getPort())))) {
                        s.connect(new InetSocketAddress(TEST_LOCALHOST, echoPort));
                        s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                        try (OutputStream sockOut = s.getOutputStream();
                             InputStream sockIn = s.getInputStream()) {

                            sockOut.write(bytes);
                            sockOut.flush();

                            int l = sockIn.read(buf);
                            assertEquals("Mismatched data at iteration " + i, expected,
                                    new String(buf, 0, l, StandardCharsets.UTF_8));
                        }
                    }
                }

                tracker.close();
                assertFalse("Tracker not marked as closed", tracker.isOpen());
            } finally {
                client.removePortForwardingEventListener(listener);
            }

            assertNotNull("Local tunnel address not indicated", localAddressHolder.getAndSet(null));
            assertNotNull("Bound tunnel address not indicated", boundAddressHolder.getAndSet(null));

            try {
                try (Socket s
                        = new Socket(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(TEST_LOCALHOST, dynamic.getPort())))) {
                    s.connect(new InetSocketAddress(TEST_LOCALHOST, echoPort));
                    s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(11L));
                    s.getOutputStream().write(bytes);
                    fail("Unexpected success to write proxy data");
                }
            } catch (IOException e) {
                // expected
            }
        }
    }

    protected ClientSession createNativeSession(PortForwardingEventListener listener) throws Exception {
        client = setupTestClient();
        CoreModuleProperties.WINDOW_SIZE.set(client, 2048L);
        CoreModuleProperties.MAX_PACKET_SIZE.set(client, 256L);
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        if (listener != null) {
            client.addPortForwardingEventListener(listener);
        }
        client.start();

        ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshPort).verify(CONNECT_TIMEOUT).getSession();
        session.addPasswordIdentity(getCurrentTestName());
        session.auth().verify(AUTH_TIMEOUT);
        return session;
    }
}
