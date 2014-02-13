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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.atomic.AtomicInteger;

import com.jcraft.jsch.JSch;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.TeeOutputStream;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test key exchange algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyReExchangeTest extends BaseTest {

    private SshServer sshd;
    private int port;

    @After
    public void tearDown() throws Exception {
        sshd.stop();
    }

    protected void setUp(long bytesLimit, long timeLimit) throws Exception {
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        if (bytesLimit > 0) {
            sshd.getProperties().put(ServerFactoryManager.REKEY_BYTES_LIMIT, Long.toString(bytesLimit));
        }
        if (timeLimit > 0) {
            sshd.getProperties().put(ServerFactoryManager.REKEY_TIME_LIMIT, Long.toString(timeLimit));
        }
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    @Test
    public void testReExchangeFromClient() throws Exception {
        setUp(0, 0);

        JSchLogger.init();
        JSch.setConfig("kex", "diffie-hellman-group-exchange-sha1");
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", port);
        s.setUserInfo(new SimpleUserInfo("smx"));
        s.connect();
        com.jcraft.jsch.Channel c = s.openChannel("shell");
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        for (int i = 0; i < 10; i++) {
            os.write("this is my command\n".getBytes());
            os.flush();
            byte[] data = new byte[512];
            int len = is.read(data);
            String str = new String(data, 0, len);
            assertEquals("this is my command\n", str);
            s.rekey();
        }
        c.disconnect();
        s.disconnect();
    }

    @Test
    public void testReExchangeFromNativeClient() throws Exception {
        setUp(0, 0);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await();
        ChannelShell channel = session.createShellChannel();

        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new PipedOutputStream();
        channel.setIn(new PipedInputStream(pipedIn));
        OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        teeOut.write("this is my command\n".getBytes());
        teeOut.flush();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");

        for (int i = 0; i < 10; i++) {
            teeOut.write(sb.toString().getBytes());
            teeOut.flush();
            session.reExchangeKeys();
        }
        teeOut.write("exit\n".getBytes());
        teeOut.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test
    public void testReExchangeFromServer() throws Exception {
        setUp(8192, 0);

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await();
        ChannelShell channel = session.createShellChannel();

        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new PipedOutputStream();
        channel.setIn(new PipedInputStream(pipedIn));
        OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        teeOut.write("this is my command\n".getBytes());
        teeOut.flush();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");

        final AtomicInteger exchanges = new AtomicInteger();
        session.addListener(new SessionListener() {
            public void sessionCreated(Session session) {
            }
            public void sessionEvent(Session sesssion, Event event) {
                if (event == Event.KeyEstablished) {
                    exchanges.incrementAndGet();
                }
            }
            public void sessionClosed(Session session) {
            }
        });
        for (int i = 0; i < 100; i++) {
            teeOut.write(sb.toString().getBytes());
            teeOut.flush();
        }
        teeOut.write("exit\n".getBytes());
        teeOut.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertTrue("Expected rekeying", exchanges.get() > 0);
        assertEquals(sent.toByteArray().length, out.toByteArray().length);
        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }
}
