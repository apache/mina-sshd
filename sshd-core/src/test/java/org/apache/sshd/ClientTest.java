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
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;

import org.apache.mina.core.future.WriteFuture;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.mina.MinaSession;
import org.apache.sshd.common.io.nio2.Nio2Session;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.util.*;
import org.junit.After;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                return new UnknownCommand(command);
            }
        });
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
            Thread.sleep(50);
        }
    }

    @Test
    public void testCommandDeadlock() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ChannelExec channel = session.createExecChannel("test");
        channel.setOut(new NoCloseOutputStream(System.out));
        channel.setErr(new NoCloseOutputStream(System.err));
        channel.open().await();
        Thread.sleep(100);
        try {
            for (int i = 0; i < 100; i++) {
                channel.getInvertedIn().write("a".getBytes());
                channel.getInvertedIn().flush();
            }
        } catch (SshException e) {
            // That's ok, the channel is being closed by the other side
        }
        assertEquals(ChannelExec.CLOSED, channel.waitFor(ChannelExec.CLOSED, 0) & ChannelExec.CLOSED);
        session.close(false).await();
        client.stop();
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

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
        for (int i = 0; i < 1000; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");
        teeOut.write(sb.toString().getBytes());

        teeOut.write("exit\n".getBytes());
        teeOut.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test
    public void testClientInverted() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open().await();

        OutputStream pipedIn = new TeeOutputStream(sent, channel.getInvertedIn());

        pipedIn.write("this is my command\n".getBytes());
        pipedIn.flush();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");
        pipedIn.write(sb.toString().getBytes());

        pipedIn.write("exit\n".getBytes());
        pipedIn.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test
    public void testClientClosingStream() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);


        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new PipedOutputStream();
        OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        teeOut.write("this is my command\n".getBytes());
        teeOut.flush();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");
        teeOut.write(sb.toString().getBytes());

        teeOut.close();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test
    public void testClientWithLengthyDialog() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        // Reduce window size and packet size
//        client.getProperties().put(SshClient.WINDOW_SIZE, Integer.toString(0x20000));
//        client.getProperties().put(SshClient.MAX_PACKET_SIZE, Integer.toString(0x1000));
//        sshd.getProperties().put(SshServer.WINDOW_SIZE, Integer.toString(0x20000));
//        sshd.getProperties().put(SshServer.MAX_PACKET_SIZE, Integer.toString(0x1000));
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx");
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new PipedOutputStream();
        OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open().await();

        long t0 = System.currentTimeMillis();

        int bytes = 0;
        for (int i = 0; i < 10000; i++) {
            byte[] data = "01234567890123456789012345678901234567890123456789\n".getBytes();
            teeOut.write(data);
            teeOut.flush();
            bytes += data.length;
            if ((bytes & 0xFFF00000) != ((bytes - data.length) & 0xFFF00000)) {
                System.out.println("Bytes written: " + bytes);
            }
        }
        teeOut.write("exit\n".getBytes());
        teeOut.flush();

        long t1 = System.currentTimeMillis();

        System.out.println("Sent " + (bytes / 1024) + " Kb in " + (t1 - t0) + " ms");

        System.out.println("Waiting for channel to be closed");

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close(false);
        client.stop();

        assertTrue(BufferUtils.equals(sent.toByteArray(), out.toByteArray()));
        //assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test(expected = SshException.class)
    public void testOpenChannelOnClosedSession() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await().isSuccess();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        session.close(false);

        PipedOutputStream pipedIn = new PipedOutputStream();
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();
    }

    @Test
    public void testCloseBeforeAuthSucceed() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        AuthFuture authFuture = session.authPassword("smx", "smx");
        CloseFuture closeFuture = session.close(false);
        authFuture.await();
        closeFuture.await();
        assertNotNull(authFuture.getException());
        assertTrue(closeFuture.isClosed());
    }

    @Test
    public void testCloseCleanBeforeChannelOpened() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        channel.setIn(new ByteArrayInputStream(new byte[0]));
        channel.setOut(new ByteArrayOutputStream());
        channel.setErr(new ByteArrayOutputStream());
        OpenFuture openFuture = channel.open();
        CloseFuture closeFuture = session.close(false);
        openFuture.await();
        closeFuture.await();
        assertNotNull(openFuture.isOpened());
        assertTrue(closeFuture.isClosed());
    }

    @Test
    public void testCloseImmediateBeforeChannelOpened() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("smx", "smx").await();
        ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
        channel.setIn(new ByteArrayInputStream(new byte[0]));
        channel.setOut(new ByteArrayOutputStream());
        channel.setErr(new ByteArrayOutputStream());
        OpenFuture openFuture = channel.open();
        CloseFuture closeFuture = session.close(true);
        openFuture.await();
        closeFuture.await();
        assertNotNull(openFuture.getException());
        assertTrue(closeFuture.isClosed());
    }

    @Test
    public void testPublicKeyAuth() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();

        KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);

        assertTrue(session.authPublicKey("smx", pair).await().isSuccess());
    }

    @Test
    public void testClientDisconnect() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);
        try
        {
            SshClient client = SshClient.setUpDefaultClient();
            client.start();
            ClientSession session = client.connect("localhost", port).await().getSession();
            session.authPassword("smx", "smx");
            ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
            PipedOutputStream pipedIn = new PipedOutputStream();
            channel.setIn(new PipedInputStream(pipedIn));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            channel.setOut(out);
            channel.setErr(err);
            channel.open().await();

//            ((AbstractSession) session).disconnect(SshConstants.SSH2_DISCONNECT_BY_APPLICATION, "Cancel");
            AbstractSession cs = (AbstractSession) session;
            Buffer buffer = cs.createBuffer(SshConstants.SSH_MSG_DISCONNECT, 0);
            buffer.putInt(SshConstants.SSH2_DISCONNECT_BY_APPLICATION);
            buffer.putString("Cancel");
            buffer.putString("");
            IoWriteFuture f = cs.writePacket(buffer);
            f.await();
            suspend(cs.getIoSession());

            TestEchoShellFactory.TestEchoShell.latch.await();
        } finally {
            TestEchoShellFactory.TestEchoShell.latch = null;
        }
    }

    private void suspend(IoSession ioSession) {
        if (ioSession instanceof MinaSession) {
            ((MinaSession) ioSession).suspend();
        } else {
            ((Nio2Session) ioSession).suspend();
        }
    }

    public static class TestEchoShellFactory extends EchoShellFactory {
        @Override
        public Command create() {
            return new TestEchoShell();
        }
        public static class TestEchoShell extends EchoShell {

            public static CountDownLatch latch = new CountDownLatch(1);

            @Override
            public void destroy() {
                if (latch != null) {
                    latch.countDown();
                }
                super.destroy();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SshClient.main(args);
    }
}
