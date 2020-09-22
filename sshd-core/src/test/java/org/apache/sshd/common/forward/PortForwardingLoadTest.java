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
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
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
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.JSchLogger;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.Assume;
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

    @SuppressWarnings({ "checkstyle:anoninnerlength", "synthetic-access" })
    private final PortForwardingEventListener serverSideListener = new PortForwardingEventListener() {
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
        public void establishingDynamicTunnel(
                org.apache.sshd.common.session.Session session, SshdSocketAddress local)
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

    private SshServer sshd;
    private int sshPort;
    private IoAcceptor acceptor;

    public PortForwardingLoadTest() {
        log = LoggerFactory.getLogger(getClass());
    }

    @BeforeClass
    public static void jschInit() {
        // FIXME inexplicably these tests fail without BC since SSHD-1004
        Assume.assumeTrue("Requires BC security provider", SecurityUtils.isBouncyCastleRegistered());
        JSchLogger.init();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestFullSupportServer();
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
        String payload = sb.toString();

        final byte[] dataBytes = payload.getBytes(StandardCharsets.UTF_8);
        final int reportPhase = dataBytes.length / 10;
        log.info("{} using payload size={}", getCurrentTestName(), dataBytes.length);

        AtomicInteger errors = new AtomicInteger();

        Session session = createSession();
        try (ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress((InetAddress) null, 0));
            int forwardedPort = ss.getLocalPort();
            int sinkPort = session.setPortForwardingL(0, TEST_LOCALHOST, forwardedPort);
            log.info("{} forwardedPort={}, sinkPort={}", getCurrentTestName(), forwardedPort, sinkPort);

            AtomicInteger conCount = new AtomicInteger(0);
            Semaphore iterationsSignal = new Semaphore(0);
            @SuppressWarnings("checkstyle:anoninnerlength")
            Thread tAcceptor = new Thread(getCurrentTestName() + "Acceptor") {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    try {
                        byte[] buf = new byte[8192];
                        log.info("Started...");
                        for (int i = 0; i < numIterations; ++i) {
                            try (Socket s = ss.accept()) {
                                int totalConns = conCount.incrementAndGet();
                                log.info("Accepted connection #{} from {}", totalConns, s.getRemoteSocketAddress());

                                try (InputStream sockIn = s.getInputStream();
                                     ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                                    for (int readSize = 0, lastReport = 0; readSize < dataBytes.length;) {
                                        int l = sockIn.read(buf);
                                        if (l < 0) {
                                            break;
                                        }

                                        baos.write(buf, 0, l);
                                        readSize += l;

                                        if ((readSize - lastReport) >= reportPhase) {
                                            log.info("Read {}/{} bytes of iteration #{}", readSize, dataBytes.length, i);
                                            lastReport = readSize;
                                        }
                                    }

                                    assertPayloadEquals("Mismatched received data at iteration #" + i, dataBytes,
                                            baos.toByteArray());

                                    byte[] outBytes = baos.toByteArray();
                                    try (InputStream inputCopy = new ByteArrayInputStream(outBytes);
                                         OutputStream sockOut = s.getOutputStream()) {

                                        for (int writeSize = 0, lastReport = 0; writeSize < outBytes.length;) {
                                            int l = inputCopy.read(buf);
                                            if (l < 0) {
                                                break;
                                            }
                                            sockOut.write(buf, 0, l);
                                            writeSize += l;
                                            if ((writeSize - lastReport) >= reportPhase) {
                                                log.info("Written {}/{} bytes of iteration #{}", writeSize, dataBytes.length,
                                                        i);
                                                lastReport = writeSize;
                                            }
                                        }
                                    }
                                }
                            }
                            log.info("Finished iteration {}/{}", i, numIterations);
                            iterationsSignal.release();
                        }
                        log.info("Done");
                    } catch (Exception e) {
                        log.error("Failed to complete run loop", e);
                    }
                }
            };
            tAcceptor.start();
            Thread.sleep(TimeUnit.SECONDS.toMillis(1L));

            byte[] buf = new byte[8192];
            for (int i = 0; i < numIterations; i++) {
                log.debug("Iteration {}/{} started", i, numIterations);
                try (Socket s = new Socket(TEST_LOCALHOST, sinkPort);
                     OutputStream sockOut = s.getOutputStream()) {

                    log.debug("Iteration {} connected to {}", i, s.getRemoteSocketAddress());
                    s.setSoTimeout((int) CoreModuleProperties.NIO2_MIN_WRITE_TIMEOUT.getRequiredDefault().toMillis());

                    sockOut.write(dataBytes);
                    sockOut.flush();

                    log.debug("Iteration {} awaiting echoed data", i);
                    try (InputStream sockIn = s.getInputStream();
                         ByteArrayOutputStream baos = new ByteArrayOutputStream(dataBytes.length)) {
                        for (int readSize = 0, lastReport = 0; readSize < dataBytes.length;) {
                            try {
                                int l = sockIn.read(buf);
                                if (l < 0) {
                                    break;
                                }

                                baos.write(buf, 0, l);
                                readSize += l;

                                if ((readSize - lastReport) >= reportPhase) {
                                    log.debug("Read {}/{} bytes of iteration #{}", readSize, dataBytes.length, i);
                                    lastReport = readSize;
                                }
                            } catch (SocketTimeoutException e) {
                                throw new IOException(
                                        "Error reading data at index " + readSize + "/" + dataBytes.length + " of iteration #"
                                                      + i,
                                        e);
                            }
                        }
                        assertPayloadEquals("Mismatched payload at iteration #" + i, dataBytes, baos.toByteArray());
                    }
                } catch (Exception e) {
                    log.error("Error in iteration #" + i, e);
                    errors.incrementAndGet();
                }
            }

            try {
                assertTrue("Failed to await pending iterations=" + numIterations,
                        iterationsSignal.tryAcquire(numIterations, numIterations, TimeUnit.SECONDS));
            } finally {
                log.info("{} remove port forwarding for {}", getCurrentTestName(), sinkPort);
                session.delPortForwardingL(sinkPort);
            }

            ss.close();
            log.info("{} awaiting acceptor finish", getCurrentTestName());
            tAcceptor.join(TimeUnit.SECONDS.toMillis(11L));
        } finally {
            session.disconnect();
        }

        assertEquals("Some errors occured", 0, errors.get());
    }

    private static void assertPayloadEquals(String message, byte[] expectedBytes, byte[] actualBytes) {
        assertEquals(message + ": mismatched payload length", expectedBytes.length, actualBytes.length);

        for (int index = 0; index < expectedBytes.length; index++) {
            if (expectedBytes[index] == actualBytes[index]) {
                continue;
            }

            int startPos = Math.max(0, index - Byte.SIZE);
            int endPos = Math.min(startPos + Short.SIZE, expectedBytes.length);
            if ((endPos - startPos) < Byte.SIZE) {
                startPos = expectedBytes.length - Byte.SIZE;
                endPos = expectedBytes.length;
            }

            String expected = new String(expectedBytes, startPos, endPos - startPos, StandardCharsets.UTF_8);
            String actual = new String(actualBytes, startPos, endPos - startPos, StandardCharsets.UTF_8);
            fail("Mismatched data around offset " + index + ": expected='" + expected + "', actual='" + actual + "'");
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
        try (ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress((InetAddress) null, 0));
            int forwardedPort = ss.getLocalPort();
            int sinkPort = CoreTestSupportUtils.getFreePort();
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
            Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
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
                            : new IndexOutOfBoundsException(
                                    "Mismatched length: expected=" + payload.length() + ", actual=" + totalRead);

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
            log.info("Successful iterations: " + ok + " out of " + numIterations);
            Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
            for (int i = 0; i < numIterations; i++) {
                assertNull("Bad length at iteration " + i, lenOK[i]);
                assertNull("Bad data at iteration " + i, dataOK[i]);
            }
            Thread.sleep(TimeUnit.SECONDS.toMillis(1L));
            session.delPortForwardingR(forwardedPort);
            ss.close();
            tWriter.join(TimeUnit.SECONDS.toMillis(11L));
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
            final int forwardedPort2 = CoreTestSupportUtils.getFreePort();
            session.setPortForwardingR(forwardedPort2, TEST_LOCALHOST, forwardedPort1);
            outputDebugMessage("URL: http://localhost %s", forwardedPort2);

            final CountDownLatch latch = new CountDownLatch(nbThread * nbDownloads * nbLoops);
            final Thread[] threads = new Thread[nbThread];
            final List<Throwable> errors = new CopyOnWriteArrayList<>();
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
                                    log.debug("Remaining: " + latch.getCount());
                                }
                            }
                            mgr.shutdown();
                        }
                    }
                };
            }
            for (Thread thread : threads) {
                thread.start();
            }
            latch.await();
            for (Throwable t : errors) {
                log.warn("{}: {}", t.getClass().getSimpleName(), t.getMessage());
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
