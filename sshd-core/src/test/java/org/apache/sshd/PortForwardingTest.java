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

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashSet;
import java.util.Set;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.util.BogusForwardingFilter;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import static org.apache.sshd.util.Utils.getFreePort;
import static org.junit.Assert.assertEquals;

/**
 * Port forwarding tests
 */
public class PortForwardingTest {

    private final org.slf4j.Logger log = LoggerFactory.getLogger(getClass());

    private SshServer sshd;
    private int sshPort;
    private int echoPort;
    private IoAcceptor acceptor;

    @Before
    public void setUp() throws Exception {
        sshPort = getFreePort();
        echoPort = getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(sshPort);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setTcpipForwardingFilter(new BogusForwardingFilter());
        sshd.start();

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
        acceptor.bind(new InetSocketAddress(echoPort));
        this.acceptor = acceptor;

    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop();
            Thread.sleep(50);
        }
        if (acceptor != null) {
            acceptor.dispose();
        }
    }

    @Test
    public void testRemoteForwarding() throws Exception {
        Session session = createSession();

        int forwardedPort = getFreePort();
        session.setPortForwardingR(forwardedPort, "localhost", echoPort);
        Thread.sleep(100);

        Socket s = new Socket("localhost", forwardedPort);
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.delPortForwardingR(forwardedPort);
    }

    @Test
    public void testRemoteForwardingNative() throws Exception {
        ClientSession session = createNativeSession();

        int forwardedPort = getFreePort();
        SshdSocketAddress remote = new SshdSocketAddress("", forwardedPort);
        SshdSocketAddress local = new SshdSocketAddress("localhost", echoPort);

        session.startRemotePortForwarding(remote, local);

        Socket s = new Socket(remote.getHostName(), remote.getPort());
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.stopRemotePortForwarding(remote);
    }

    @Test
    public void testRemoteForwardingNativeNoExplicitPort() throws Exception {
        ClientSession session = createNativeSession();

        SshdSocketAddress remote = new SshdSocketAddress("0.0.0.0", 0);
        SshdSocketAddress local = new SshdSocketAddress("localhost", echoPort);

        SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);

        Socket s = new Socket(bound.getHostName(), bound.getPort());
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.stopRemotePortForwarding(bound);
    }

    @Test
    public void testLocalForwarding() throws Exception {
        Session session = createSession();

        int forwardedPort = getFreePort();
        session.setPortForwardingL(forwardedPort, "localhost", echoPort);

        Socket s = new Socket("localhost", forwardedPort);
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.delPortForwardingL(forwardedPort);
    }

    @Test
    public void testLocalForwardingNative() throws Exception {
        ClientSession session = createNativeSession();

        SshdSocketAddress local = new SshdSocketAddress("", getFreePort());
        SshdSocketAddress remote = new SshdSocketAddress("localhost", echoPort);

        SshdSocketAddress bound = session.startLocalPortForwarding(local, remote);

        Socket s = new Socket(bound.getHostName(), bound.getPort());
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.stopLocalPortForwarding(bound);
    }

    @Test
    public void testForwardingChannel() throws Exception {
        ClientSession session = createNativeSession();

        int forwardedPort = getFreePort();
        SshdSocketAddress local = new SshdSocketAddress("", forwardedPort);
        SshdSocketAddress remote = new SshdSocketAddress("localhost", echoPort);

        ChannelDirectTcpip channel = session.createDirectTcpipChannel(local, remote);
        channel.open().await();

        channel.getOut().write("Hello".getBytes());
        channel.getOut().flush();
        byte[] buf = new byte[1024];
        int n = channel.getIn().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        channel.close(false);
    }

    @Test(timeout = 20000)
    public void testRemoteForwardingWithDisconnect() throws Exception {
        Session session = createSession();

        // 1. Create a Port Forward
        int forwardedPort = getFreePort();
        session.setPortForwardingR(forwardedPort, "localhost", echoPort);

        // 2. Establish a connection through it
        new Socket("localhost", forwardedPort);

        // 3. Simulate the client going away
        rudelyDisconnectJschSession(session);

        // 4. Make sure the NIOprocessor is not stuck
        {
            Thread.sleep(1000);
            // from here, we need to check all the threads running and find a
            // "NioProcessor-"
            // that is stuck on a PortForward.dispose
            ThreadGroup root = Thread.currentThread().getThreadGroup().getParent();
            while (root.getParent() != null) {
                root = root.getParent();
            }
            boolean stuck;
            do {
                stuck = false;
                for (Thread t : findThreads(root, "NioProcessor-")) {
                    stuck = true;
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {

                }
            } while (stuck);
        }

        session.delPortForwardingR(forwardedPort);
    }

    /**
     * Close the socket inside this JSCH session. Use reflection to find it and
     * just close it.
     *
     * @param session
     *            the Session to violate
     * @throws Exception
     */
    private void rudelyDisconnectJschSession(Session session) throws Exception {
        Field fSocket = session.getClass().getDeclaredField("socket");
        fSocket.setAccessible(true);
        Socket socket = (Socket) fSocket.get(session);

        Assert.assertTrue("socket is not connected", socket.isConnected());
        Assert.assertFalse("socket should not be closed", socket.isClosed());
        socket.close();
        Assert.assertTrue("socket has not closed", socket.isClosed());
    }

    private Set<Thread> findThreads(ThreadGroup group, String name) {
        HashSet<Thread> ret = new HashSet<Thread>();
        int numThreads = group.activeCount();
        Thread[] threads = new Thread[numThreads * 2];
        numThreads = group.enumerate(threads, false);
        // Enumerate each thread in `group'
        for (int i = 0; i < numThreads; ++i) {
            // Get thread
            // log.debug("Thread name: " + threads[i].getName());
            if (checkThreadForPortForward(threads[i], name)) {
                ret.add(threads[i]);
            }
        }
        // didn't find the thread to check the
        int numGroups = group.activeGroupCount();
        ThreadGroup[] groups = new ThreadGroup[numGroups * 2];
        numGroups = group.enumerate(groups, false);
        for (int i = 0; i < numGroups; ++i) {
            ret.addAll(findThreads(groups[i], name));
        }
        return ret;
    }

    private boolean checkThreadForPortForward(Thread thread, String name) {
        if (thread == null)
            return false;
        // does it contain the name we're looking for?
        if (thread.getName().contains(name)) {
            // look at the stack
            StackTraceElement[] stack = thread.getStackTrace();
            if (stack.length == 0)
                return false;
            else {
                // does it have
                // 'org.apache.sshd.server.session.TcpipForwardSupport.close'?
                for (int i = 0; i < stack.length; ++i) {
                    String clazzName = stack[i].getClassName();
                    String methodName = stack[i].getMethodName();
                    // log.debug("Class: " + clazzName);
                    // log.debug("Method: " + methodName);
                    if (clazzName
                            .equals("org.apache.sshd.server.session.TcpipForwardSupport")
                            && (methodName.equals("close") || methodName
                            .equals("sessionCreated"))) {
                        log.warn(thread.getName() + " stuck at " + clazzName
                                + "." + methodName + ": "
                                + stack[i].getLineNumber());
                        return true;
                    }
                }
            }
        }
        return false;
    }

    protected Session createSession() throws JSchException {
        JSchLogger.init();
        JSch sch = new JSch();
        Session session = sch.getSession("sshd", "localhost", sshPort);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
        return session;
    }

    protected ClientSession createNativeSession() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.setTcpipForwardingFilter(new BogusForwardingFilter());
        client.start();
        ConnectFuture sessionFuture = client.connect("localhost", sshPort);
        sessionFuture.await();
        ClientSession session = sessionFuture.getSession();

        AuthFuture authPassword = session.authPassword("sshd", "sshd");
        authPassword.await();

        return session;
    }


}


