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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.forward.TcpipServerChannel;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.util.AsyncEchoShellFactory;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusPublickeyAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class WindowTest extends BaseTest {

    private SshServer sshd;
    private SshClient client;
    private int port;
    private CountDownLatch authLatch;
    private CountDownLatch channelLatch;

    @Before
    public void setUp() throws Exception {
        authLatch = new CountDownLatch(0);
        channelLatch = new CountDownLatch(0);

        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setShellFactory(new TestEchoShellFactory());
        sshd.setCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                return new UnknownCommand(command);
            }
        });
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setPublickeyAuthenticator(new BogusPublickeyAuthenticator());
        sshd.setServiceFactories(Arrays.asList(
                new ServerUserAuthService.Factory() {
                    @Override
                    public Service create(Session session) throws IOException {
                        return new ServerUserAuthService(session) {
                            @Override
                            public void process(byte cmd, Buffer buffer) throws Exception {
                                authLatch.await();
                                super.process(cmd, buffer);
                            }
                        };
                    }
                },
                new ServerConnectionService.Factory()
        ));
        sshd.setChannelFactories(Arrays.<NamedFactory<Channel>>asList(
                new ChannelSession.Factory() {
                    @Override
                    public Channel create() {
                        return new ChannelSession() {
                            @Override
                            public OpenFuture open(int recipient, int rwsize, int rmpsize, Buffer buffer) {
                                try {
                                    channelLatch.await();
                                } catch (InterruptedException e) {
                                    throw new RuntimeSshException(e);
                                }
                                return super.open(recipient, rwsize, rmpsize, buffer);
                            }

                            @Override
                            public String toString() {
                                return "ChannelSession" + "[id=" + id + ", recipient=" + recipient + "]";
                            }
                        };
                    }
                },
                new TcpipServerChannel.DirectTcpipFactory()));
        sshd.start();
        port = sshd.getPort();

        client = SshClient.setUpDefaultClient();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    public void testWindowConsumptionWithInvertedStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        sshd.getProperties().put(SshServer.WINDOW_SIZE, "1024");
        client.getProperties().put(SshClient.WINDOW_SIZE, "1024");
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        final ChannelShell channel = session.createShellChannel();
        channel.open().verify();

        final Channel serverChannel = sshd.getActiveSessions().iterator().next().getService(ServerConnectionService.class)
                .getChannels().iterator().next();

        Window clientLocal = channel.getLocalWindow();
        Window clientRemote = channel.getRemoteWindow();
        Window serverLocal = serverChannel.getLocalWindow();
        Window serverRemote = serverChannel.getRemoteWindow();

        final String message = "0123456789";
        final int nbMessages = 500;

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(channel.getInvertedIn()));
        BufferedReader reader = new BufferedReader(new InputStreamReader(channel.getInvertedOut()));
        for (int i = 0; i < nbMessages; i++) {
            writer.write(message);
            writer.write("\n");
            writer.flush();

            Thread.sleep(5);
            assertNotEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());

            String line = reader.readLine();
            assertEquals(message, line);

            Thread.sleep(5);

            assertEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());
            assertEquals("client remote and server local", clientRemote.getSize(), serverLocal.getSize());
        }
    }

    @Test
    public void testWindowConsumptionWithDirectStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        sshd.getProperties().put(SshServer.WINDOW_SIZE, "1024");
        client.getProperties().put(SshClient.WINDOW_SIZE, "1024");
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        final ChannelShell channel = session.createShellChannel();

        PipedInputStream inPis = new PipedInputStream();
        PipedOutputStream inPos = new PipedOutputStream(inPis);
        channel.setIn(inPis);
        PipedInputStream outPis = new PipedInputStream();
        PipedOutputStream outPos = new PipedOutputStream(outPis);
        channel.setOut(outPos);
        channel.open().verify();

        final Channel serverChannel = sshd.getActiveSessions().iterator().next().getService(ServerConnectionService.class)
                .getChannels().iterator().next();

        Window clientLocal = channel.getLocalWindow();
        Window clientRemote = channel.getRemoteWindow();
        Window serverLocal = serverChannel.getLocalWindow();
        Window serverRemote = serverChannel.getRemoteWindow();

        final String message = "0123456789";
        final int nbMessages = 500;

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(inPos));
        BufferedReader reader = new BufferedReader(new InputStreamReader(outPis));
        for (int i = 0; i < nbMessages; i++) {
            writer.write(message);
            writer.write("\n");
            writer.flush();

            Thread.sleep(5);
            assertEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());

            String line = reader.readLine();
            assertEquals(message, line);

            Thread.sleep(5);

            assertEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());
            assertEquals("client remote and server local", clientRemote.getSize(), serverLocal.getSize());
        }
    }

    @Test
    public void testWindowConsumptionWithAsyncStreams() throws Exception {
        sshd.setShellFactory(new AsyncEchoShellFactory());
        sshd.getProperties().put(SshServer.WINDOW_SIZE, "1024");
        client.getProperties().put(SshClient.WINDOW_SIZE, "1024");
        client.start();
        ClientSession session = client.connect("smx", "localhost", port).await().getSession();
        session.addPasswordIdentity("smx");
        session.auth().verify();
        final ChannelShell channel = session.createShellChannel();
        channel.setStreaming(ClientChannel.Streaming.Async);
        channel.open().verify();

        final Channel serverChannel = sshd.getActiveSessions().iterator().next().getService(ServerConnectionService.class)
                .getChannels().iterator().next();

        Window clientLocal = channel.getLocalWindow();
        Window clientRemote = channel.getRemoteWindow();
        Window serverLocal = serverChannel.getLocalWindow();
        Window serverRemote = serverChannel.getRemoteWindow();

        final String message = "0123456789";
        final int nbMessages = 500;

        for (int i = 0; i < nbMessages; i++) {

            Buffer buffer = new Buffer((message + "\n").getBytes());
            channel.getAsyncIn().write(buffer).verify();

            Thread.sleep(5);
            assertNotEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());

            Buffer buf = new Buffer(16);
            IoReadFuture future = channel.getAsyncOut().read(buf);
            future.verify();
            assertEquals(11, buf.available());
            assertEquals(message + "\n", new String(buf.array(), buf.rpos(), buf.available()));

            Thread.sleep(5);

            assertEquals("client local and server remote", clientLocal.getSize(), serverRemote.getSize());
            assertEquals("client remote and server local", clientRemote.getSize(), serverLocal.getSize());
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

}
