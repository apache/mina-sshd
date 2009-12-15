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

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import com.jcraft.jsch.*;
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
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusForwardingFilter;
import org.apache.sshd.util.EchoShellFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Port forwarding tests
 */
public class PortForwardingTest {

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

        Socket s = new Socket("localhost", forwardedPort);
        s.getOutputStream().write("Hello".getBytes());
        s.getOutputStream().flush();
        byte[] buf = new byte[1024];
        int n = s.getInputStream().read(buf);
        String res = new String(buf, 0, n);
        assertEquals("Hello", res);
        s.close();

        session.delPortForwardingR(forwardedPort);

//        session.setPortForwardingR(8010, "www.amazon.com", 80);
//        Thread.sleep(1000000);
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

//        session.setPortForwardingL(8010, "www.amazon.com", 80);
//        Thread.sleep(1000000);
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


