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

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpVersion;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.SshdSocketAddress;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.BogusForwardingFilter;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Port forwarding tests
 */
public class PortForwardingTest {

    private final org.slf4j.Logger log = LoggerFactory.getLogger(getClass());

    private SshServer sshd;
    private int sshPort;
    private int echoPort;
    private IoAcceptor acceptor;

    private static int getFreePort() throws Exception {
        ServerSocket s = new ServerSocket(0);
        try {
            return s.getLocalPort();
        } finally {
            s.close();
        }
    }

    @Before
    public void setUp() throws Exception {
        sshPort = getFreePort();
        echoPort = getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(sshPort);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setForwardingFilter(new BogusForwardingFilter());
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

        int forwardedPort = getFreePort();
        SshdSocketAddress local = new SshdSocketAddress("", forwardedPort);
        SshdSocketAddress remote = new SshdSocketAddress("localhost", echoPort);

        session.startLocalPortForwarding(local, remote);

        Socket s = new Socket(local.getHostName(), local.getPort());
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.stopLocalPortForwarding(local);
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

    @Test
    @Ignore
    public void testRemoteForwardingPayload() throws Exception {
        final int NUM_ITERATIONS = 100;
        final String PAYLOAD = "This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. ";
        Session session = createSession();
        final ServerSocket ss = new ServerSocket(0);
        int forwardedPort = ss.getLocalPort();
        int sinkPort = getFreePort();
        session.setPortForwardingR(sinkPort, "localhost", forwardedPort);
        final boolean started[] = new boolean[1];
        started[0] = false;
        final AtomicInteger conCount = new AtomicInteger(0);

        new Thread() {
            public void run() {
                started[0] = true;
                try {
                    for (int i = 0; i < NUM_ITERATIONS; ++i) {
                        Socket s = ss.accept();
                        conCount.incrementAndGet();
                        s.getOutputStream().write(PAYLOAD.getBytes());
                        s.getOutputStream().flush();
                        s.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
        Thread.sleep(50);
        Assert.assertTrue("Server not started", started[0]);

        final boolean lenOK[] = new boolean[NUM_ITERATIONS];
        final boolean dataOK[] = new boolean[NUM_ITERATIONS];
        for ( int i = 0; i < NUM_ITERATIONS; i++) {
            final int ii = i;
            Socket s = null;
            try {
                s = new Socket("localhost", sinkPort);
                byte b1[] = new byte[PAYLOAD.length() / 2];
                byte b2[] = new byte[PAYLOAD.length()];
                int read1 = s.getInputStream().read(b1);
                Thread.sleep(50);
                int read2 = s.getInputStream().read(b2);
                lenOK[ii] = PAYLOAD.length() == read1 + read2;
                dataOK[ii] = PAYLOAD.equals(new String(b1, 0, read1) + new String(b2, 0, read2));
                if (!lenOK[ii] || !dataOK[ii] ) {
                    throw new Exception("Bad data");
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (s != null) {
                    s.close();
                }
            }
        }
        int ok = 0;
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            ok += lenOK[i] ? 1 : 0;
        }
        Thread.sleep(50);
        for (int i = 0; i < NUM_ITERATIONS; i++) {
            Assert.assertTrue(lenOK[i]);
            Assert.assertTrue(dataOK[i]);
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
        JSch sch = new JSch();
        sch.setLogger(new Logger() {
            public boolean isEnabled(int i) {
                return true;
            }

            public void log(int i, String s) {
                System.out.println("Log(jsch," + i + "): " + s);
            }
        });
        Session session = sch.getSession("sshd", "localhost", sshPort);
        session.setUserInfo(new UserInfo() {
            public String getPassphrase() {
                return null;
            }

            public String getPassword() {
                return "sshd";
            }

            public boolean promptPassword(String message) {
                return true;
            }

            public boolean promptPassphrase(String message) {
                return false;
            }

            public boolean promptYesNo(String message) {
                return true;
            }

            public void showMessage(String message) {
            }
        });
        session.connect();
        return session;
    }

    protected ClientSession createNativeSession() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ConnectFuture sessionFuture = client.connect("localhost", sshPort);
        sessionFuture.await();
        ClientSession session = sessionFuture.getSession();

        AuthFuture authPassword = session.authPassword("sshd", "sshd");
        authPassword.await();

        return session;
    }

    @Test
    @Ignore
    public void testForwardingOnLoad() throws Exception {
//        final String path = "/history/recent/troubles/";
//        final String host = "www.bbc.co.uk";
//        final String path = "";
//        final String host = "www.bahn.de";
        final String path = "";
        final String host = "localhost";
        final int nbThread = 2;
        final int nbDownloads = 2;
        final int nbLoops = 2;

        final int port = getFreePort();
        StringBuilder resp = new StringBuilder();
        resp.append("<html><body>\n");
        for (int i = 0; i < 1000; i++) {
            resp.append("0123456789\n");
        }
        resp.append("</body></html>\n");
        final StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 200 OK").append('\n');
        sb.append("Content-Type: text/HTML").append('\n');
        sb.append("Content-Length: ").append(resp.length()).append('\n');
        sb.append('\n');
        sb.append(resp);
        NioSocketAcceptor acceptor = new NioSocketAcceptor();
        acceptor.setHandler(new IoHandlerAdapter() {
            @Override
            public void messageReceived(IoSession session, Object message) throws Exception {
                session.write(IoBuffer.wrap(sb.toString().getBytes()));
            }
        });
        acceptor.setReuseAddress(true);
        acceptor.bind(new InetSocketAddress(port));


        Session session = createSession();

        final int forwardedPort1 = getFreePort();
        final int forwardedPort2 = getFreePort();
        System.err.println("URL: http://localhost:" + forwardedPort2);

        session.setPortForwardingL(forwardedPort1, host, port);
        session.setPortForwardingR(forwardedPort2, "localhost", forwardedPort1);


        final CountDownLatch latch = new CountDownLatch(nbThread * nbDownloads * nbLoops);

        final Thread[] threads = new Thread[nbThread];
        final List<Throwable> errors = new CopyOnWriteArrayList<Throwable>();
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread() {
                public void run() {
                    for (int j = 0; j < nbLoops; j++)  {
                        final MultiThreadedHttpConnectionManager mgr = new MultiThreadedHttpConnectionManager();
                        final HttpClient client = new HttpClient(mgr);
                        client.getHttpConnectionManager().getParams().setDefaultMaxConnectionsPerHost(100);
                        client.getHttpConnectionManager().getParams().setMaxTotalConnections(1000);
                        for (int i = 0; i < nbDownloads; i++) {
                            try {
                                checkHtmlPage(client, new URL("http://localhost:" + forwardedPort2 + path));
                            } catch (Throwable e) {
                                errors.add(e);
                            } finally {
                                latch.countDown();
                                System.err.println("Remaining: " + latch.getCount());
                            }
                        }
                        mgr.shutdown();
                    }
                }
            };
        }
        for (int i = 0; i < threads.length; i++) {
            threads[i].start();
        }
        latch.await();
        for (Throwable t : errors) {
            t.printStackTrace();
        }
        assertEquals(0, errors.size());
    }

    protected void checkHtmlPage(HttpClient client, URL url) throws IOException {
        client.setHostConfiguration(new HostConfiguration());
        client.getHostConfiguration().setHost(url.getHost(), url.getPort());
        GetMethod get = new GetMethod("");
        get.getParams().setVersion(HttpVersion.HTTP_1_1);
        client.executeMethod(get);
        String str = get.getResponseBodyAsString();
        if (str.indexOf("</html>") <= 0) {
            System.err.println(str);
        }
        assertTrue((str.indexOf("</html>") > 0));
        get.releaseConnection();
//        url.openConnection().setDefaultUseCaches(false);
//        Reader reader = new BufferedReader(new InputStreamReader(url.openStream()));
//        try {
//            StringWriter sw = new StringWriter();
//            char[] buf = new char[8192];
//            while (true) {
//                int len = reader.read(buf);
//                if (len < 0) {
//                    break;
//                }
//                sw.write(buf, 0, len);
//            }
//            assertTrue(sw.toString().indexOf("</html>") > 0);
//        } finally {
//            reader.close();
//        }
    }


}


