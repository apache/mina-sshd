/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.jcraft.jsch.JSch;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.TeeOutputStream;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Test key exchange algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyReExchangeTest extends BaseTestSupport {

    private SshServer sshd;
    private int port;

    @After
    public void tearDown() throws Exception {
        sshd.stop(true);
    }

    protected void setUp(long bytesLimit, long timeLimit) throws Exception {
        sshd = SshServer.setUpDefaultServer();
        if (bytesLimit > 0L) {
            FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.REKEY_BYTES_LIMIT, bytesLimit);
        }
        if (timeLimit > 0L) {
            FactoryManagerUtils.updateProperty(sshd, ServerFactoryManager.REKEY_TIME_LIMIT, timeLimit);
        }

        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.start();
        port = sshd.getPort();
    }

    @Test
    public void testReExchangeFromClient() throws Exception {
        setUp(0, 0);

        JSchLogger.init();
        JSch.setConfig("kex", "diffie-hellman-group-exchange-sha1");
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), "localhost", port);
        try {
            s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));
            s.connect();

            com.jcraft.jsch.Channel c = s.openChannel("shell");
            c.connect();
            try (OutputStream os = c.getOutputStream();
                 InputStream is = c.getInputStream()) {

                String expected = "this is my command\n";
                byte[] bytes = expected.getBytes(StandardCharsets.UTF_8);
                byte[] data = new byte[bytes.length + Long.SIZE];
                for (int i = 0; i < 10; i++) {
                    os.write(bytes);
                    os.flush();

                    int len = is.read(data);
                    String str = new String(data, 0, len);
                    assertEquals("Mismatched data at iteration " + i, expected, str);
                    s.rekey();
                }
            } finally {
                c.disconnect();
            }
        } finally {
            s.disconnect();
        }
    }

    @Test
    public void testReExchangeFromNativeClient() throws Exception {
        setUp(0, 0);

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     ByteArrayOutputStream sent = new ByteArrayOutputStream();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn);
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     ByteArrayOutputStream out = new ByteArrayOutputStream();
                     ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 10; i++) {
                        sb.append("0123456789");
                    }
                    sb.append("\n");

                    byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
                    for (int i = 0; i < 10; i++) {
                        teeOut.write(data);
                        teeOut.flush();
                        session.reExchangeKeys();
                    }
                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    channel.waitFor(ClientChannel.CLOSED, 0);

                    channel.close(false);

                    assertArrayEquals("Mismatched sent data content", sent.toByteArray(), out.toByteArray());
                }
            } finally {
                client.stop();
            }
        }
    }

    @Test
    public void testReExchangeFromServer() throws Exception {
        setUp(8192, 0);

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (ClientSession session = client.connect(getCurrentTestName(), "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(5L, TimeUnit.SECONDS);

                try (ChannelShell channel = session.createShellChannel();
                     ByteArrayOutputStream sent = new ByteArrayOutputStream();
                     PipedOutputStream pipedIn = new PipedOutputStream();
                     OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                     ByteArrayOutputStream out = new ByteArrayOutputStream();
                     ByteArrayOutputStream err = new ByteArrayOutputStream();
                     InputStream inPipe = new PipedInputStream(pipedIn)) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();

                    teeOut.write("this is my command\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 100; i++) {
                        sb.append("0123456789");
                    }
                    sb.append("\n");

                    final AtomicInteger exchanges = new AtomicInteger();
                    session.addListener(new SessionListener() {
                        @Override
                        public void sessionCreated(Session session) {
                            // ignored
                        }

                        @Override
                        public void sessionEvent(Session session, Event event) {
                            if (event == Event.KeyEstablished) {
                                exchanges.incrementAndGet();
                            }
                        }

                        @Override
                        public void sessionClosed(Session session) {
                            // ignored
                        }
                    });
                    for (int i = 0; i < 100; i++) {
                        teeOut.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                        teeOut.flush();
                    }
                    teeOut.write("exit\n".getBytes(StandardCharsets.UTF_8));
                    teeOut.flush();

                    channel.waitFor(ClientChannel.CLOSED, 0);

                    channel.close(false);

                    assertTrue("Expected rekeying", exchanges.get() > 0);
                    assertEquals("Mismatched sent data length", sent.toByteArray().length, out.toByteArray().length);
                    assertArrayEquals("Mismatched sent data content", sent.toByteArray(), out.toByteArray());
                }
            } finally {
                client.stop();
            }
        }
    }
}
