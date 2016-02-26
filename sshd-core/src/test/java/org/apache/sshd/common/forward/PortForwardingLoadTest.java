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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
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
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PortForwardingLoadTest extends BaseTestSupport {
    private final Logger log;
    private SshServer sshd;
    private int sshPort;
    private IoAcceptor acceptor;

    public PortForwardingLoadTest() {
        log = LoggerFactory.getLogger(getClass());
    }

    @BeforeClass
    public static void jschInit() {
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
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
        log.info("setUp() echo address = {}", acceptor.getLocalAddress());
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
    }

    @Test
    @SuppressWarnings("checkstyle:nestedtrydepth")
    public void testLocalForwardingPayload() throws Exception {
        final int numIterations = 100;
        final String payloadTmpData = "This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. ";
        StringBuilder sb = new StringBuilder(payloadTmpData.length() * 1000);
        for (int i = 0; i < 1000; i++) {
            sb.append(payloadTmpData);
        }
        final String payload = sb.toString();

        Session session = createSession();
        try (final ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress((InetAddress) null, 0));
            int forwardedPort = ss.getLocalPort();
            int sinkPort = session.setPortForwardingL(0, TEST_LOCALHOST, forwardedPort);
            final AtomicInteger conCount = new AtomicInteger(0);

            Thread tAcceptor = new Thread(getCurrentTestName() + "Acceptor") {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    try {
                        byte[] buf = new byte[8192];
                        log.info("Started...");
                        for (int i = 0; i < numIterations; ++i) {
                            try (Socket s = ss.accept()) {
                                conCount.incrementAndGet();

                                try (InputStream sockIn = s.getInputStream();
                                     ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                                    while (baos.size() < payload.length()) {
                                        int l = sockIn.read(buf);
                                        if (l < 0) {
                                            break;
                                        }
                                        baos.write(buf, 0, l);
                                    }

                                    assertEquals("Mismatched received data at iteration #" + i, payload, baos.toString());

                                    try (InputStream inputCopy = new ByteArrayInputStream(baos.toByteArray());
                                         OutputStream sockOut = s.getOutputStream()) {

                                        while (true) {
                                            int l = sockIn.read(buf);
                                            if (l < 0) {
                                                break;
                                            }
                                            sockOut.write(buf, 0, l);
                                        }
                                    }
                                }
                            }
                        }
                        log.info("Done");
                    } catch (Exception e) {
                        log.error("Failed to complete run loop", e);
                    }
                }
            };
            tAcceptor.start();
            Thread.sleep(50);

            byte[] buf = new byte[8192];
            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < numIterations; i++) {
                log.info("Iteration {}", Integer.valueOf(i));
                try (Socket s = new Socket(TEST_LOCALHOST, sinkPort);
                     OutputStream sockOut = s.getOutputStream()) {

                    s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                    sockOut.write(bytes);
                    sockOut.flush();

                    try (InputStream sockIn = s.getInputStream();
                         ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length)) {
                        while (baos.size() < payload.length()) {
                            int l = sockIn.read(buf);
                            if (l < 0) {
                                break;
                            }
                            baos.write(buf, 0, l);
                        }
                        assertEquals("Mismatched payload at iteration #" + i, payload, baos.toString());
                    }
                } catch (Exception e) {
                    log.error("Error in iteration #" + i, e);
                }
            }
            session.delPortForwardingL(sinkPort);

            ss.close();
            tAcceptor.join(TimeUnit.SECONDS.toMillis(5L));
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testRemoteForwardingPayload() throws Exception {
        final int numIterations = 100;
        final String payload = "This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. This is significantly longer Test Data. This is significantly "
                + "longer Test Data. ";
        Session session = createSession();
        try (final ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress((InetAddress) null, 0));
            int forwardedPort = ss.getLocalPort();
            int sinkPort = Utils.getFreePort();
            session.setPortForwardingR(sinkPort, TEST_LOCALHOST, forwardedPort);
            final boolean started[] = new boolean[1];
            started[0] = false;
            final AtomicInteger conCount = new AtomicInteger(0);

            Thread tWriter = new Thread(getCurrentTestName() + "Writer") {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    started[0] = true;
                    try {
                        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
                        for (int i = 0; i < numIterations; ++i) {
                            try (Socket s = ss.accept()) {
                                conCount.incrementAndGet();

                                try (OutputStream sockOut = s.getOutputStream()) {
                                    sockOut.write(bytes);
                                    sockOut.flush();
                                }
                            }
                        }
                    } catch (Exception e) {
                        log.error("Failed to complete run loop", e);
                    }
                }
            };
            tWriter.start();
            Thread.sleep(50);
            assertTrue("Server not started", started[0]);

            final RuntimeException lenOK[] = new RuntimeException[numIterations];
            final RuntimeException dataOK[] = new RuntimeException[numIterations];
            byte b2[] = new byte[payload.length()];
            byte b1[] = new byte[b2.length / 2];

            for (int i = 0; i < numIterations; i++) {
                final int ii = i;
                try (Socket s = new Socket(TEST_LOCALHOST, sinkPort);
                    InputStream sockIn = s.getInputStream()) {
                    s.setSoTimeout((int) TimeUnit.SECONDS.toMillis(10L));

                    int read1 = sockIn.read(b1);
                    String part1 = new String(b1, 0, read1, StandardCharsets.UTF_8);
                    Thread.sleep(50);

                    int read2 = sockIn.read(b2);
                    String part2 = new String(b2, 0, read2, StandardCharsets.UTF_8);
                    int totalRead = read1 + read2;
                    lenOK[ii] = (payload.length() == totalRead)
                            ? null
                            : new IndexOutOfBoundsException("Mismatched length: expected=" + payload.length() + ", actual=" + totalRead);

                    String readData = part1 + part2;
                    dataOK[ii] = payload.equals(readData) ? null : new IllegalStateException("Mismatched content");
                    if (lenOK[ii] != null) {
                        throw lenOK[ii];
                    }

                    if (dataOK[ii] != null) {
                        throw dataOK[ii];
                    }
                } catch (Exception e) {
                    if (e instanceof IOException) {
                        log.warn("I/O exception in iteration #" + i, e);
                    } else {
                        log.error("Failed to complete iteration #" + i, e);
                    }
                }
            }
            int ok = 0;
            for (int i = 0; i < numIterations; i++) {
                ok += (lenOK[i] == null) ? 1 : 0;
            }
            log.info("Successful iteration: " + ok + " out of " + numIterations);
            Thread.sleep(55L);
            for (int i = 0; i < numIterations; i++) {
                assertNull("Bad length at iteration " + i, lenOK[i]);
                assertNull("Bad data at iteration " + i, dataOK[i]);
            }
            session.delPortForwardingR(forwardedPort);
            ss.close();
            tWriter.join(TimeUnit.SECONDS.toMillis(5L));
        } finally {
            session.disconnect();
        }
    }

    @Test
    public void testForwardingOnLoad() throws Exception {
//        final String path = "/history/recent/troubles/";
//        final String host = "www.bbc.co.uk";
//        final String path = "";
//        final String host = "www.bahn.de";
        final String path = "";
        final String host = TEST_LOCALHOST;
        final int nbThread = 2;
        final int nbDownloads = 2;
        final int nbLoops = 2;

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
                session.write(IoBuffer.wrap(sb.toString().getBytes(StandardCharsets.UTF_8)));
            }
        });
        acceptor.setReuseAddress(true);
        acceptor.bind(new InetSocketAddress(0));
        final int port = acceptor.getLocalAddress().getPort();

        Session session = createSession();
        try {
            final int forwardedPort1 = session.setPortForwardingL(0, host, port);
            final int forwardedPort2 = Utils.getFreePort();
            session.setPortForwardingR(forwardedPort2, TEST_LOCALHOST, forwardedPort1);
            outputDebugMessage("URL: http://localhost %s", forwardedPort2);

            final CountDownLatch latch = new CountDownLatch(nbThread * nbDownloads * nbLoops);
            final Thread[] threads = new Thread[nbThread];
            final List<Throwable> errors = new CopyOnWriteArrayList<Throwable>();
            for (int i = 0; i < threads.length; i++) {
                threads[i] = new Thread(getCurrentTestName() + "[" + i + "]") {
                    @Override
                    public void run() {
                        for (int j = 0; j < nbLoops; j++) {
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
        } finally {
            session.disconnect();
        }
    }

    protected Session createSession() throws JSchException {
        JSch sch = new JSch();
        Session session = sch.getSession("sshd", TEST_LOCALHOST, sshPort);
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
        assertTrue("Missing HTML close tag", str.indexOf("</html>") > 0);
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


