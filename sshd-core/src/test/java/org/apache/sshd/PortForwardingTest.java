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

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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
}


