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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
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
import org.apache.sshd.util.BaseTest;
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
import static org.junit.Assert.assertTrue;

/**
 * Port forwarding tests
 */
public class PortForwardingLoadTest extends BaseTest {

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
    public void testLocalForwardingPayload() throws Exception {
        final int NUM_ITERATIONS = 100;
        final String PAYLOAD_TMP = "This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. This is significantly longer Test Data. This is significantly "+
                "longer Test Data. ";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append(PAYLOAD_TMP);
        }
        final String PAYLOAD = sb.toString();
        Session session = createSession();
        final ServerSocket ss = new ServerSocket(0);
        int forwardedPort = ss.getLocalPort();
        int sinkPort = getFreePort();
        session.setPortForwardingL(sinkPort, "localhost", forwardedPort);
        final AtomicInteger conCount = new AtomicInteger(0);

        new Thread() {
            public void run() {
                try {
                    for (int i = 0; i < NUM_ITERATIONS; ++i) {
                        Socket s = ss.accept();
                        conCount.incrementAndGet();
                        InputStream is = s.getInputStream();
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int l;
                        while (baos.size() < PAYLOAD.length() && (l = is.read(buf)) > 0) {
                            baos.write(buf, 0, l);
                        }
                        if (!PAYLOAD.equals(baos.toString())) {
                            assertEquals(PAYLOAD, baos.toString());
                        }
                        is = new ByteArrayInputStream(baos.toByteArray());
                        OutputStream os = s.getOutputStream();
                        while ((l = is.read(buf)) > 0) {
                            os.write(buf, 0, l);
                        }
                        s.close();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }.start();
        Thread.sleep(50);

        for ( int i = 0; i < NUM_ITERATIONS; i++) {
            Socket s = null;
            try {
                LoggerFactory.getLogger(getClass()).info("Iteration {}", i);
                s = new Socket("localhost", sinkPort);
                s.getOutputStream().write(PAYLOAD.getBytes());
                s.getOutputStream().flush();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int l;
                while (baos.size() < PAYLOAD.length() && (l = s.getInputStream().read(buf)) > 0) {
                    baos.write(buf, 0, l);
                }
                assertEquals(PAYLOAD, baos.toString());
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (s != null) {
                    s.close();
                }
            }
        }
        session.delPortForwardingL(sinkPort);
    }

    @Test
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

    @Test
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

    protected Session createSession() throws JSchException {
        JSchLogger.init();
        JSch sch = new JSch();
        Session session = sch.getSession("sshd", "localhost", sshPort);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
        return session;
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


