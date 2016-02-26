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

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

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
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.global.CancelTcpipForwardHandler;
import org.apache.sshd.server.global.TcpipForwardHandler;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.apache.sshd.util.test.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PortForwardingTest extends BaseTestSupport {

    private final org.slf4j.Logger log = LoggerFactory.getLogger(getClass());

    private final BlockingQueue<String> requestsQ = new LinkedBlockingDeque<String>();

    private SshServer sshd;
    private int sshPort;
    private int echoPort;
    private IoAcceptor acceptor;
    private SshClient client;

    public PortForwardingTest() {
        super();
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.WINDOW_SIZE, 2048);
        PropertyResolverUtils.updateProperty(sshd, FactoryManager.MAX_PACKET_SIZE, 256);
        sshd.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.start();

        if (!requestsQ.isEmpty()) {
            requestsQ.clear();
        }

        final TcpipForwarderFactory factory = ValidateUtils.checkNotNull(sshd.getTcpipForwarderFactory(), "No TcpipForwarderFactory");
        sshd.setTcpipForwarderFactory(new TcpipForwarderFactory() {
            private final Class<?>[] interfaces = {TcpipForwarder.class};
            private final Map<String, String> method2req = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it...

                {
                    put("localPortForwardingRequested", TcpipForwardHandler.REQUEST);
                    put("localPortForwardingCancelled", CancelTcpipForwardHandler.REQUEST);
                }
            };

            @Override
            public TcpipForwarder create(ConnectionService service) {
                Thread thread = Thread.currentThread();
                ClassLoader cl = thread.getContextClassLoader();

                final TcpipForwarder forwarder = factory.create(service);
                return (TcpipForwarder) Proxy.newProxyInstance(cl, interfaces, new InvocationHandler() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        Object result = method.invoke(forwarder, args);
                        String name = method.getName();
                        String request = method2req.get(name);
                        if (GenericUtils.length(request) > 0) {
                            if (requestsQ.offer(request)) {
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

    private void waitForForwardingRequest(String expected, long timeout) throws InterruptedException {
        for (long remaining = timeout; remaining > 0L;) {
            long waitStart = System.currentTimeMillis();
            String actual = requestsQ.poll(remaining, TimeUnit.MILLISECONDS);
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
    public void testRemoteForwarding() throws Exception {
        Session session = createSession();
        try {
            int forwardedPort = Utils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, TimeUnit.SECONDS.toMillis(5L));

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

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
            int forwardedPort = Utils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, TimeUnit.SECONDS.toMillis(5L));

            session.delPortForwardingR(TEST_LOCALHOST, forwardedPort);
            waitForForwardingRequest(CancelTcpipForwardHandler.REQUEST, TimeUnit.SECONDS.toMillis(5L));

            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, TimeUnit.SECONDS.toMillis(5L));

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

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
        try (ClientSession session = createNativeSession()) {
            SshdSocketAddress remote = new SshdSocketAddress("", 0);
            SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);

            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

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
        try (ClientSession session = createNativeSession()) {
            SshdSocketAddress remote = new SshdSocketAddress("", 0);
            SshdSocketAddress local = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);

            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                byte[] buf = new byte[bytes.length + Long.SIZE];

                for (int i = 0; i < 1000; i++) {
                    output.write(bytes);
                    output.flush();

                    int n = input.read(buf);
                    String res = new String(buf, 0, n);
                    assertEquals("Mismatched data at iteration #" + i, expected, res);
                }
            } finally {
                session.stopRemotePortForwarding(remote);
            }
        }
    }

    @Test
    public void testLocalForwarding() throws Exception {
        Session session = createSession();
        try {
            int forwardedPort = Utils.getFreePort();
            session.setPortForwardingL(forwardedPort, TEST_LOCALHOST, echoPort);

            try (Socket s = new Socket(TEST_LOCALHOST, forwardedPort);
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n);
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
        try (ClientSession session = createNativeSession()) {
            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);

            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                output.write(bytes);
                output.flush();

                byte[] buf = new byte[bytes.length + Long.SIZE];
                int n = input.read(buf);
                String res = new String(buf, 0, n);
                assertEquals("Mismatched data", expected, res);
            } finally {
                session.stopLocalPortForwarding(bound);
            }
        }
    }

    @Test
    public void testLocalForwardingNativeReuse() throws Exception {
        try (ClientSession session = createNativeSession()) {
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
        try (ClientSession session = createNativeSession()) {
            String expected = getCurrentTestName();
            byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
            byte[] buf = new byte[bytes.length + Long.SIZE];

            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);
            SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);
            try (Socket s = new Socket(bound.getHostName(), bound.getPort());
                 OutputStream output = s.getOutputStream();
                 InputStream input = s.getInputStream()) {

                s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                for (int i = 0; i < 1000; i++) {
                    output.write(bytes);
                    output.flush();

                    int n = input.read(buf);
                    String res = new String(buf, 0, n);
                    assertEquals("Mismatched data at iteration #" + i, expected, res);
                }
            } finally {
                session.stopLocalPortForwarding(bound);
            }
        }
    }

    @Test
    public void testForwardingChannel() throws Exception {
        try (ClientSession session = createNativeSession()) {
            SshdSocketAddress local = new SshdSocketAddress("", 0);
            SshdSocketAddress remote = new SshdSocketAddress(TEST_LOCALHOST, echoPort);

            try (ChannelDirectTcpip channel = session.createDirectTcpipChannel(local, remote)) {
                channel.open().verify(9L, TimeUnit.SECONDS);

                String expected = getCurrentTestName();
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);

                try (OutputStream output = channel.getInvertedIn();
                     InputStream input = channel.getInvertedOut()) {
                    output.write(bytes);
                    output.flush();

                    byte[] buf = new byte[bytes.length + Long.SIZE];
                    int n = input.read(buf);
                    String res = new String(buf, 0, n);
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
            int forwardedPort = Utils.getFreePort();
            session.setPortForwardingR(forwardedPort, TEST_LOCALHOST, echoPort);
            waitForForwardingRequest(TcpipForwardHandler.REQUEST, TimeUnit.SECONDS.toMillis(5L));

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

    /**
     * Close the socket inside this JSCH session. Use reflection to find it and
     * just close it.
     *
     * @param session the Session to violate
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
        Set<Thread> ret = new HashSet<Thread>();

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
                continue;   // debug breakpoint
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
            for (int i = 0; i < stack.length; ++i) {
                String clazzName = stack[i].getClassName();
                String methodName = stack[i].getMethodName();
                // log.debug("Class: " + clazzName);
                // log.debug("Method: " + methodName);
                if (clazzName.equals("org.apache.sshd.server.session.TcpipForwardSupport")
                        && (methodName.equals("close") || methodName.equals("sessionCreated"))) {
                    log.warn(thread.getName() + " stuck at " + clazzName
                           + "." + methodName + ": "
                           + stack[i].getLineNumber());
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

    protected ClientSession createNativeSession() throws Exception {
        client = setupTestClient();
        PropertyResolverUtils.updateProperty(client, FactoryManager.WINDOW_SIZE, 2048);
        PropertyResolverUtils.updateProperty(client, FactoryManager.MAX_PACKET_SIZE, 256);
        client.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        client.start();

        ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, sshPort).verify(7L, TimeUnit.SECONDS).getSession();
        session.addPasswordIdentity(getCurrentTestName());
        session.auth().verify(11L, TimeUnit.SECONDS);
        return session;
    }
}


