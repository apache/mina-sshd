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
package org.apache.sshd.common.forward;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.ProxyUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.global.CancelTcpipForwardHandler;
import org.apache.sshd.server.global.TcpipForwardHandler;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("checkstyle:MethodCount")
public class PortForwardingTest extends BaseTestSupport {

    public static final int SO_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(13L);

    @SuppressWarnings("checkstyle:anoninnerlength")
    private static final PortForwardingEventListener SERVER_SIDE_LISTENER = new PortForwardingEventListener() {
        private final org.slf4j.Logger log = LoggerFactory.getLogger(PortForwardingEventListener.class);

        @Override
        public void establishingExplicitTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress remote,
                boolean localForwarding)
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
                org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress boundAddress,
                Throwable reason)
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
                org.apache.sshd.common.session.Session session, SshdSocketAddress address, Throwable reason)
                throws IOException {
            log.info("tornDownDynamicTunnel(session={}, address={}, reason={})", session, address, reason);
        }
    };

    private static final BlockingQueue<String> REQUESTS_QUEUE = new LinkedBlockingDeque<>();
    private static SshServer sshd;
    private static int sshPort;
    private static int echoPort;
    private static IoAcceptor acceptor;
    private static SshClient client;

    private final Logger log = LoggerFactory.getLogger(getClass());

    public PortForwardingTest() {
        super();
    }

    @BeforeClass
    public static void setUpTestEnvironment() throws Exception {
        JSchLogger.init();
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(PortForwardingTest.class);
        CoreModuleProperties.WINDOW_SIZE.set(sshd, 2048L);
        CoreModuleProperties.MAX_PACKET_SIZE.set(sshd, 256L);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.addPortForwardingEventListener(SERVER_SIDE_LISTENER);
        sshd.start();
        sshPort = sshd.getPort();

        if (!REQUESTS_QUEUE.isEmpty()) {
            REQUESTS_QUEUE.clear();
        }

        ForwarderFactory factory = Objects.requireNonNull(sshd.getForwarderFactory(), "No ForwarderFactory");
        sshd.setForwarderFactory(new ForwarderFactory() {
            private final Map<String, String> method2req
                    = NavigableMapBuilder.<String, String> builder(String.CASE_INSENSITIVE_ORDER)
                            .put("localPortForwardingRequested", TcpipForwardHandler.REQUEST)
                            .put("localPortForwardingCancelled", CancelTcpipForwardHandler.REQUEST)
                            .build();

            @Override
            public Forwarder create(ConnectionService service) {
                Thread thread = Thread.currentThread();
                ClassLoader cl = thread.getContextClassLoader();

                Forwarder forwarder = factory.create(service);
                return ProxyUtils.newProxyInstance(cl, Forwarder.class, new InvocationHandler() {
                    private final org.slf4j.Logger log = LoggerFactory.getLogger(Forwarder.class);

                    @SuppressWarnings("synthetic-access")
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        Object result;
                        try {
                            result = method.invoke(forwarder, args);
                        } catch (Throwable t) {
                            throw ProxyUtils.unwrapInvocationThrowable(t);
                        }

                        String name = method.getName();
                        String request = method2req.get(name);
                        if (GenericUtils.length(request) > 0) {
                            if (REQUESTS_QUEUE.offer(request)) {
                                log.info("Signal " + request);
                            } else {
                                log.error("Failed to offer request=" + request);
                            }
                        }
                        return result;
                    }
                });
            }
        });

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

        client = CoreTestSupportUtils.setupTestClient(PortForwardingTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownTestEnvironment() throws Exception {
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

    @Before
    public void setUp() {
        if (!REQUESTS_QUEUE.isEmpty()) {
            REQUESTS_QUEUE.clear();
        }
    }

    private static void waitForForwardingRequest(String expected, Duration timeout) throws InterruptedException {
        for (long remaining = timeout.toMillis(); remaining > 0L;) {
            long waitStart = System.currentTimeMillis();
            String actual = REQUESTS_QUEUE.poll(remaining, TimeUnit.MILLISECONDS);
            long waitEnd = System.currentTimeMillis();
            if (GenericUtils.isEmpty(actual)) {
                throw new IllegalStateException("Failed to retrieve request=" + expected);
            }

            if (expected.equals(actual)) {
                return;
            }

            long waitDuration = waitEnd - waitStart;
            remaining -= waitDuration;
        }

        throw new IllegalStateException("Timeout while waiting to retrieve request=" + expected);
    }

    @Test
    public void testRemoteForwarding() throws Exception {
        Session session = createSession();
        try {
            int forwardedPort = CoreTestSupportUtils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, DEFAULT_TIMEOUT);

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(13L));

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                assertEquals("Mismatched data", expected, res);
            } finally {
                session.delPortForwardingR(forwardedPort);
            }
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testRemoteForwardingSecondTimeInSameSession() throws Exception {
        Session session = createSession();
        try {
            int forwardedPort = CoreTestSupportUtils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, DEFAULT_TIMEOUT);

            session.delPortForwardingR(TEST_LOCALHOST, forwardedPort);
            waitForForwardingRequest(CancelTcpipForwardHandler.REQUEST, DEFAULT_TIMEOUT);

            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, DEFAULT_TIMEOUT);

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                assertEquals("Mismatched data", expected, res);
            } finally {
                session.delPortForwardingR(TEST_LOCALHOST, forwardedPort);
            }
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testRemoteForwardingNative() throws Exception {
        try (ClientSession session = createNativeSession(null)) {
            SshdSocketAddress remote = new SshdSocketAddress("", 0);
            SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);

            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n);
                assertEquals("Mismatched data", expected, res);
            } finally {
                session.stopRemotePortForwarding(remote);
            }
        }
    }

    @Test
    public void testRemoteForwardingNativeBigPayload() throws Exception {
        AtomicReference<SshdSocketAddress> localAddressHolder = new AtomicReference<>();
        AtomicReference<SshdSocketAddress> remoteAddressHolder = new AtomicReference<>();
        AtomicReference<SshdSocketAddress> boundAddressHolder = new AtomicReference<>();
        AtomicInteger tearDownSignal = new AtomicInteger(0);
        @SuppressWarnings("checkstyle:anoninnerlength")
        PortForwardingEventListener listener = new PortForwardingEventListener() {
            @Override
            public void tornDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress, Throwable reason)
                    throws IOException {
                assertFalse("Unexpected local tunnel has been torn down: address=" + address, localForwarding);
                assertEquals("Tear down indication not invoked", 1, tearDownSignal.get());
            }

            @Override
            public void tornDownDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel torn down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void tearingDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress)
                    throws IOException {
                assertFalse("Unexpected local tunnel being torn down: address=" + address, localForwarding);
                assertEquals("Duplicate tear down signalling", 1, tearDownSignal.incrementAndGet());
            }

            @Override
            public void tearingDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel tearing down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void establishingExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress remote,
                    boolean localForwarding)
                    throws IOException {
                assertFalse("Unexpected local tunnel being established: local=" + local + ", remote=" + remote,
                        localForwarding);
                assertNull("Duplicate establishment indication call for local address=" + local,
                        localAddressHolder.getAndSet(local));
                assertNull("Duplicate establishment indication call for remote address=" + remote,
                        remoteAddressHolder.getAndSet(remote));
            }

            @Override
            public void establishingDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel establishing indication: session=" + session + ", address=" + local);
            }

            @Override
            public void establishedExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                    SshdSocketAddress remote, boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
                    throws IOException {
                assertFalse("Unexpected local tunnel has been established: local=" + local + ", remote=" + remote + ", bound="
                            + boundAddress,
                        localForwarding);
                assertSame("Mismatched established tunnel local address", local, localAddressHolder.get());
                assertSame("Mismatched established tunnel remote address", remote, remoteAddressHolder.get());
                assertNull("Duplicate establishment indication call for bound address=" + boundAddress,
                        boundAddressHolder.getAndSet(boundAddress));
            }

            @Override
            public void establishedDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress boundAddress,
                    Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel established indication: session=" + session + ", address=" + boundAddress);
            }
        };

        try (ClientSession session = createNativeSession(listener);
             ExplicitPortForwardingTracker tracker = session.createRemotePortForwardingTracker(new SshdSocketAddress("", 0),
                     new SshdSocketAddress(TEST_LOCALHOST, echoPort))) {
            assertTrue("Tracker not marked as open", tracker.isOpen());
            assertFalse("Tracker not marked as remote", tracker.isLocalForwarding());

            SshdSocketAddress bound = tracker.getBoundAddress();
            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                byte[] buf = new byte[bytes.length + Long.SIZE];

                for (int i = 0; i < 1000; i++) {
                    output.write(bytes);
                    output.flush();

                    int n = input.read(buf);
                    String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                    assertEquals("Mismatched data at iteration #" + i, expected, res);
                }
            } finally {
                tracker.close();
            }
            assertFalse("Tracker not marked as closed", tracker.isOpen());
        } finally {
            client.removePortForwardingEventListener(listener);
        }

        assertNotNull("Local tunnel address not indicated", localAddressHolder.getAndSet(null));
        assertNotNull("Remote tunnel address not indicated", remoteAddressHolder.getAndSet(null));
        assertNotNull("Bound tunnel address not indicated", boundAddressHolder.getAndSet(null));
    }

    @Test
    public void testLocalForwarding() throws Exception {
        Session session = createSession();
        try {
            int forwardedPort = CoreTestSupportUtils.getFreePort();
            session.setPortForwardingL(forwardedPort, TEST_LOCALHOST, echoPort);

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                assertEquals("Mismatched data", expected, res);
            } finally {
                session.delPortForwardingL(forwardedPort);
            }
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testLocalForwardingNative() throws Exception {
        AtomicReference<SshdSocketAddress> localAddressHolder = new AtomicReference<>();
        AtomicReference<SshdSocketAddress> remoteAddressHolder = new AtomicReference<>();
        AtomicReference<SshdSocketAddress> boundAddressHolder = new AtomicReference<>();
        AtomicInteger tearDownSignal = new AtomicInteger(0);
        @SuppressWarnings("checkstyle:anoninnerlength")
        PortForwardingEventListener listener = new PortForwardingEventListener() {
            @Override
            public void tornDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress, Throwable reason)
                    throws IOException {
                assertTrue("Unexpected remote tunnel has been torn down: address=" + address, localForwarding);
                assertEquals("Tear down indication not invoked", 1, tearDownSignal.get());
            }

            @Override
            public void tornDownDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel torn down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void tearingDownExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress address, boolean localForwarding,
                    SshdSocketAddress remoteAddress)
                    throws IOException {
                assertTrue("Unexpected remote tunnel being torn down: address=" + address, localForwarding);
                assertEquals("Duplicate tear down signalling", 1, tearDownSignal.incrementAndGet());
            }

            @Override
            public void tearingDownDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress address)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel tearing down indication: session=" + session + ", address=" + address);
            }

            @Override
            public void establishingExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress remote,
                    boolean localForwarding)
                    throws IOException {
                assertTrue("Unexpected remote tunnel being established: local=" + local + ", remote=" + remote,
                        localForwarding);
                assertNull("Duplicate establishment indication call for local address=" + local,
                        localAddressHolder.getAndSet(local));
                assertNull("Duplicate establishment indication call for remote address=" + remote,
                        remoteAddressHolder.getAndSet(remote));
            }

            @Override
            public void establishingDynamicTunnel(org.apache.sshd.common.session.Session session, SshdSocketAddress local)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel establishing indication: session=" + session + ", address=" + local);
            }

            @Override
            public void establishedExplicitTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local,
                    SshdSocketAddress remote, boolean localForwarding, SshdSocketAddress boundAddress, Throwable reason)
                    throws IOException {
                assertTrue("Unexpected remote tunnel has been established: local=" + local + ", remote=" + remote + ", bound="
                           + boundAddress,
                        localForwarding);
                assertSame("Mismatched established tunnel local address", local, localAddressHolder.get());
                assertSame("Mismatched established tunnel remote address", remote, remoteAddressHolder.get());
                assertNull("Duplicate establishment indication call for bound address=" + boundAddress,
                        boundAddressHolder.getAndSet(boundAddress));
            }

            @Override
            public void establishedDynamicTunnel(
                    org.apache.sshd.common.session.Session session, SshdSocketAddress local, SshdSocketAddress boundAddress,
                    Throwable reason)
                    throws IOException {
                throw new UnsupportedOperationException(
                        "Unexpected dynamic tunnel established indication: session=" + session + ", address=" + boundAddress);
            }
        };

        try (ClientSession session = createNativeSession(listener);
             ExplicitPortForwardingTracker tracker = session.createLocalPortForwardingTracker(new SshdSocketAddress("", 0),
                     new SshdSocketAddress(TEST_LOCALHOST, echoPort))) {
            assertTrue("Tracker not marked as open", tracker.isOpen());
            assertTrue("Tracker not marked as local", tracker.isLocalForwarding());

            SshdSocketAddress bound = tracker.getBoundAddress();
            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                assertTrue("No data read from tunnel", n > 0);

                String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                assertEquals("Mismatched data", expected, res);
            } finally {
                tracker.close();
            }
            assertFalse("Tracker not marked as closed", tracker.isOpen());
        } finally {
            client.removePortForwardingEventListener(listener);
        }

        assertNotNull("Local tunnel address not indicated", localAddressHolder.getAndSet(null));
        assertNotNull("Remote tunnel address not indicated", remoteAddressHolder.getAndSet(null));
        assertNotNull("Bound tunnel address not indicated", boundAddressHolder.getAndSet(null));
    }

    @Test
    public void testLocalForwardingNativeReuse() throws Exception {
        try (ClientSession session = createNativeSession(null)) {
            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);

            session.stopLocalPortForwarding(bound);

            SshdSocketAddress bound2 = session.startLocalPortForwarding(local, remote);
            session.stopLocalPortForwarding(bound2);
        }
    }

    @Test
    public void testLocalForwardingNativeBigPayload() throws Exception {
        try (ClientSession session = createNativeSession(null)) {
            String expected = getCurrentTestName();
            byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
            byte[] buf = new byte[bytes.length + Long.SIZE];

            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);
            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout(SO_TIMEOUT);

                for (int i = 0; i < 1000; i++) {
                    output.write(bytes);
                    output.flush();

                    int n = input.read(buf);
                    assertTrue("No data read from tunnel", n > 0);

                    String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                    assertEquals("Mismatched data at iteration #" + i, expected, res);
                }
            } finally {
                session.stopLocalPortForwarding(bound);
            }
        }
    }

    @Test
    public void testForwardingChannel() throws Exception {
        try (ClientSession session = createNativeSession(null)) {
            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);

            try (ChannelDirectTcpip channel = session.createDirectTcpipChannel(local, remote)) {
                channel.open().verify(OPEN_TIMEOUT);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                try (OutputStream output = channel.getInvertedIn();
                     InputStream input = channel.getInvertedOut()) {
                    output.write(bytes);
                    output.flush();

                    byte[] buf = new byte[bytes.length + Long.SIZE];
                    int n = input.read(buf);
                    String res = new String(buf, 0, n, StandardCharsets.UTF_8);
                    assertEquals("Mismatched data", expected, res);
                }
                channel.close(false);
            }
        }
    }

    @Test(timeout = 45000)
    public void testRemoteForwardingWithDisconnect() throws Exception {
        Session session = createSession();
        try {
            // 1. Create a Port Forward
            int forwardedPort = CoreTestSupportUtils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, DEFAULT_TIMEOUT);

            // 2. Establish a connection through it
            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort)) {
                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                // 3. Simulate the client going away
                rudelyDisconnectJschSession(session);

                // 4. Make sure the NIOprocessor is not stuck
                Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
                // from here, we need to check all the threads running and find a
                // "NioProcessor-"
                // that is stuck on a PortForward.dispose
                ThreadGroup root = Thread.currentThread().getThreadGroup().getParent();
                while (root.getParent() != null) {
                    root = root.getParent();
                }

                for (int index = 0;; index++) {
                    Collection<Thread> pending = findThreads(root, "NioProcessor-");
                    if (GenericUtils.size(pending) <= 0) {
                        log.info("Finished after " + index + " iterations");
                        break;
                    }
                    try {
                        Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
                    } catch (InterruptedException e) {
                        // ignored
                    }
                }

                session.delPortForwardingR(forwardedPort);
            }
        } finally {
            session.disconnect();
        }
    }

    @Test   // see SSHD-1066
    public void testLocalBindingOnDifferentInterfaces() throws Exception {
        InetSocketAddress addr = (InetSocketAddress) GenericUtils.head(sshd.getBoundAddresses());
        log.info("{} - using bound address={}", getCurrentTestName(), addr);

        List<String> allAddresses = getHostAddresses();
        log.info("{} - test on addresses={}", getCurrentTestName(), allAddresses);

        try (ClientSession session = createNativeSession(null)) {
            List<ExplicitPortForwardingTracker> trackers = new ArrayList<>();
            try {
                for (String host : allAddresses) {
                    ExplicitPortForwardingTracker tracker = session.createLocalPortForwardingTracker(
                            new SshdSocketAddress(host, 8080),
                            new SshdSocketAddress("test.javastack.org", 80));
                    SshdSocketAddress boundAddress = tracker.getBoundAddress();
                    log.info("{} - test for binding={}", getCurrentTestName(), boundAddress);
                    testRemoteURL(new Proxy(Proxy.Type.HTTP, boundAddress.toInetSocketAddress()),
                            "http://test.javastack.org/");
                    trackers.add(tracker);
                }
            } finally {
                IoUtils.closeQuietly(trackers);
            }
        }
    }

    private static List<String> getHostAddresses() throws SocketException {
        List<String> addresses = new ArrayList<>();
        Enumeration<NetworkInterface> eni = NetworkInterface.getNetworkInterfaces();
        while (eni.hasMoreElements()) {
            NetworkInterface networkInterface = eni.nextElement();
            Enumeration<InetAddress> eia = networkInterface.getInetAddresses();
            while (eia.hasMoreElements()) {
                InetAddress ia = eia.nextElement();
                if (ia instanceof Inet4Address) {
                    addresses.add(ia.getHostAddress());
                }
            }
        }
        return addresses;
    }

    private static void testRemoteURL(Proxy proxy, String url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);
        connection.setConnectTimeout((int) DEFAULT_TIMEOUT.toMillis());
        connection.setReadTimeout((int) DEFAULT_TIMEOUT.toMillis());
        String result;
        try (InputStream inputStream = connection.getInputStream();
             BufferedReader in = new BufferedReader(new InputStreamReader(inputStream))) {
            result = in.lines().collect(Collectors.joining(System.lineSeparator()));
        }
        assertEquals("Unexpected server response", "OK", result);
    }

    /**
     * Close the socket inside this JSCH session. Use reflection to find it and just close it.
     *
     * @param  session   the Session to violate
     * @throws Exception
     */
    private void rudelyDisconnectJschSession(Session session) throws Exception {
        Field fSocket = session.getClass().getDeclaredField("socket");
        fSocket.setAccessible(true);

        try (Socket socket = (Socket) fSocket.get(session)) {
            assertTrue("socket is not connected", socket.isConnected());
            assertFalse("socket should not be closed", socket.isClosed());
            socket.close();
            assertTrue("socket has not closed", socket.isClosed());
        }
    }

    private Set<Thread> findThreads(ThreadGroup group, String name) {
        int numThreads = group.activeCount();
        Thread[] threads = new Thread[numThreads * 2];
        numThreads = group.enumerate(threads, false);
        Set<Thread> ret = new HashSet<>();

        // Enumerate each thread in `group'
        for (int i = 0; i < numThreads; ++i) {
            Thread t = threads[i];
            // Get thread
            // log.debug("Thread name: " + threads[i].getName());
            if (checkThreadForPortForward(t, name)) {
                ret.add(t);
            }
        }
        // didn't find the thread to check the
        int numGroups = group.activeGroupCount();
        ThreadGroup[] groups = new ThreadGroup[numGroups * 2];
        numGroups = group.enumerate(groups, false);
        for (int i = 0; i < numGroups; ++i) {
            ThreadGroup g = groups[i];
            Collection<Thread> c = findThreads(g, name);
            if (GenericUtils.isEmpty(c)) {
                continue; // debug breakpoint
            }
            ret.addAll(c);
        }
        return ret;
    }

    private boolean checkThreadForPortForward(Thread thread, String name) {
        if (thread == null) {
            return false;
        }

        // does it contain the name we're looking for?
        if (thread.getName().contains(name)) {
            // look at the stack
            StackTraceElement[] stack = thread.getStackTrace();
            if (stack.length == 0) {
                return false;
            }
            // does it have 'org.apache.sshd.server.session.TcpipForwardSupport.close'?
            for (StackTraceElement aStack : stack) {
                String clazzName = aStack.getClassName();
                String methodName = aStack.getMethodName();
                // log.debug("Class: " + clazzName);
                // log.debug("Method: " + methodName);
                if (clazzName.equals("org.apache.sshd.server.session.TcpipForwardSupport")
                        && (methodName.equals("close") || methodName.equals("sessionCreated"))) {
                    log.warn(thread.getName() + " stuck at " + clazzName
                             + "." + methodName + ": "
                             + aStack.getLineNumber());
                    return true;
                }
            }
        }
        return false;
    }

    protected Session createSession() throws JSchException {
        JSch sch = new JSch();
        Session session = sch.getSession(getCurrentTestName(), TEST_LOCALHOST, sshPort);
        session.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
        session.connect();
        return session;
    }

    protected ClientSession createNativeSession(PortForwardingEventListener listener) throws Exception {
        CoreModuleProperties.WINDOW_SIZE.set(client, 2048L);
        CoreModuleProperties.MAX_PACKET_SIZE.set(client, 256L);
        client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        if (listener != null) {
            client.addPortForwardingEventListener(listener);
        }

        return createAuthenticatedClientSession(client, sshPort);
    }
}
