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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.forward.TcpipServerChannel;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.mina.MinaSession;
import org.apache.sshd.common.io.nio2.Nio2Session;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerConnectionService;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.apache.sshd.util.AsyncEchoShellFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.BogusPublickeyAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.TeeOutputStream;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientTest extends BaseTestSupport {

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
            @Override
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
                            @SuppressWarnings("synthetic-access")
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
                new ChannelSession.ChannelSessionFactory() {
                    @Override
                    public Channel create() {
                        return new ChannelSession() {
                            @SuppressWarnings("synthetic-access")
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
                TcpipServerChannel.DirectTcpipFactory.INSTANCE));
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
    public void testAsyncClient() throws Exception {
        sshd.getProperties().put(FactoryManager.WINDOW_SIZE, "1024");
        sshd.setShellFactory(new AsyncEchoShellFactory());

        client.getProperties().put(FactoryManager.WINDOW_SIZE, "1024");
        client.start();

        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);

            try(final ChannelShell channel = session.createShellChannel()) {
                channel.setStreaming(ClientChannel.Streaming.Async);
                channel.open().verify(5L, TimeUnit.SECONDS);
        
                final byte[] message = "0123456789\n".getBytes();
                final int nbMessages = 1000;
        
                try(final ByteArrayOutputStream baosOut = new ByteArrayOutputStream();
                    final ByteArrayOutputStream baosErr = new ByteArrayOutputStream()) {
                    final AtomicInteger writes = new AtomicInteger(nbMessages);
            
                    channel.getAsyncIn().write(new ByteArrayBuffer(message))
                            .addListener(new SshFutureListener<IoWriteFuture>() {
                                @Override
                                public void operationComplete(IoWriteFuture future) {
                                    try {
                                        if (future.isWritten()) {
                                            if (writes.decrementAndGet() > 0) {
                                                channel.getAsyncIn().write(new ByteArrayBuffer(message)).addListener(this);
                                            } else {
                                                channel.getAsyncIn().close(false);
                                            }
                                        } else {
                                            throw new SshException("Error writing", future.getException());
                                        }
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });
                    channel.getAsyncOut().read(new ByteArrayBuffer())
                            .addListener(new SshFutureListener<IoReadFuture>() {
                                @Override
                                public void operationComplete(IoReadFuture future) {
                                    try {
                                        future.verify(5L, TimeUnit.SECONDS);
                                        Buffer buffer = future.getBuffer();
                                        baosOut.write(buffer.array(), buffer.rpos(), buffer.available());
                                        buffer.rpos(buffer.rpos() + buffer.available());
                                        buffer.compact();
                                        channel.getAsyncOut().read(buffer).addListener(this);
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });
                    channel.getAsyncErr().read(new ByteArrayBuffer())
                            .addListener(new SshFutureListener<IoReadFuture>() {
                                @Override
                                public void operationComplete(IoReadFuture future) {
                                    try {
                                        future.verify(5L, TimeUnit.SECONDS);
                                        Buffer buffer = future.getBuffer();
                                        baosErr.write(buffer.array(), buffer.rpos(), buffer.available());
                                        buffer.rpos(buffer.rpos() + buffer.available());
                                        buffer.compact();
                                        channel.getAsyncErr().read(buffer).addListener(this);
                                    } catch (IOException e) {
                                        if (!channel.isClosing()) {
                                            e.printStackTrace();
                                            channel.close(true);
                                        }
                                    }
                                }
                            });
        
                    channel.waitFor(ClientChannel.CLOSED, 0);
        
                    assertEquals(nbMessages * message.length, baosOut.size());
                }
            }    

            client.close(true);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testCommandDeadlock() throws Exception {
        client.start();
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
            
            try(ChannelExec channel = session.createExecChannel("test");
                OutputStream stdout = new NoCloseOutputStream(System.out);
                OutputStream stderr = new NoCloseOutputStream(System.err)) {

                channel.setOut(stdout);
                channel.setErr(stderr);
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
                assertEquals(ClientChannel.CLOSED, channel.waitFor(ClientChannel.CLOSED, 0) & ClientChannel.CLOSED);
                session.close(false).await();
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClient() throws Exception {
        client.start();

        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
            
            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                ByteArrayOutputStream sent = new ByteArrayOutputStream();
                PipedOutputStream pipedIn = new PipedOutputStream();
                PipedInputStream pipedOut = new PipedInputStream(pipedIn)) {

                channel.setIn(pipedOut);

                try(OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream err = new ByteArrayOutputStream()) {

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
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientInverted() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
            
            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                ByteArrayOutputStream sent = new ByteArrayOutputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setOut(out);
                channel.setErr(err);
                channel.open().await();
        
                try(OutputStream pipedIn = new TeeOutputStream(sent, channel.getInvertedIn())) {
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
                }
        
                channel.waitFor(ClientChannel.CLOSED, 0);
        
                channel.close(false);
                client.stop();
        
                assertArrayEquals(sent.toByteArray(), out.toByteArray());
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithCustomChannel() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
    
            try(ChannelShell channel = new ChannelShell();
                ByteArrayOutputStream sent = new ByteArrayOutputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                session.getService(ConnectionService.class).registerChannel(channel);
                channel.setOut(out);
                channel.setErr(err);
                channel.open().verify(5L, TimeUnit.SECONDS);
                channel.close(false).await();
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientClosingStream() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
    
            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                ByteArrayOutputStream sent = new ByteArrayOutputStream();
                PipedOutputStream pipedIn = new PipedOutputStream();
                InputStream inPipe = new PipedInputStream(pipedIn);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setIn(inPipe);
                channel.setOut(out);
                channel.setErr(err);
                channel.open();

                try(OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {
                    teeOut.write("this is my command\n".getBytes());
                    teeOut.flush();
        
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 1000; i++) {
                        sb.append("0123456789");
                    }
                    sb.append("\n");
                    teeOut.write(sb.toString().getBytes());
                }    
    
                channel.waitFor(ClientChannel.CLOSED, 0);
        
                channel.close(false);
                client.stop();
        
                assertArrayEquals(sent.toByteArray(), out.toByteArray());
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientWithLengthyDialog() throws Exception {
        // Reduce window size and packet size
//        client.getProperties().put(SshClient.WINDOW_SIZE, Integer.toString(0x20000));
//        client.getProperties().put(SshClient.MAX_PACKET_SIZE, Integer.toString(0x1000));
//        sshd.getProperties().put(SshServer.WINDOW_SIZE, Integer.toString(0x20000));
//        sshd.getProperties().put(SshServer.MAX_PACKET_SIZE, Integer.toString(0x1000));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);

            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                ByteArrayOutputStream sent = new ByteArrayOutputStream();
                PipedOutputStream pipedIn = new PipedOutputStream();
                InputStream inPipe = new PipedInputStream(pipedIn); 
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                channel.setIn(inPipe);
                channel.setOut(out);
                channel.setErr(err);
                channel.open().await();
        
        
                int bytes = 0;
                byte[] data = "01234567890123456789012345678901234567890123456789\n".getBytes();
                long t0 = System.currentTimeMillis();
                try(OutputStream teeOut = new TeeOutputStream(sent, pipedIn)) {
                    for (int i = 0; i < 10000; i++) {
                        teeOut.write(data);
                        teeOut.flush();
                        bytes += data.length;
                        if ((bytes & 0xFFF00000) != ((bytes - data.length) & 0xFFF00000)) {
                            System.out.println("Bytes written: " + bytes);
                        }
                    }
                    teeOut.write("exit\n".getBytes());
                    teeOut.flush();
                }        
                long t1 = System.currentTimeMillis();
        
                System.out.println("Sent " + (bytes / 1024) + " Kb in " + (t1 - t0) + " ms");
        
                System.out.println("Waiting for channel to be closed");
        
                channel.waitFor(ClientChannel.CLOSED, 0);
        
                channel.close(false);
                client.stop();
        
                assertArrayEquals(sent.toByteArray(), out.toByteArray());
                //assertArrayEquals(sent.toByteArray(), out.toByteArray());
            }
        } finally {
            client.stop();
        }
    }

    @Test(expected = SshException.class)
    public void testOpenChannelOnClosedSession() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
            
            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL)) {
                session.close(false);
        
                try(PipedOutputStream pipedIn = new PipedOutputStream();
                    InputStream inPipe = new PipedInputStream(pipedIn);
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open();
                }
            }
        }
    }

    @Test
    public void testCloseBeforeAuthSucceed() throws Exception {
        authLatch = new CountDownLatch(1);
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");

            AuthFuture authFuture = session.auth();
            CloseFuture closeFuture = session.close(false);
            authLatch.countDown();
            authFuture.await();
            closeFuture.await();
            assertNotNull("No authentication exception", authFuture.getException());
            assertTrue("Future not closed", closeFuture.isClosed());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testCloseCleanBeforeChannelOpened() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);

            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                InputStream inp = new ByteArrayInputStream(GenericUtils.EMPTY_BYTE_ARRAY);
                OutputStream out = new ByteArrayOutputStream();
                OutputStream err = new ByteArrayOutputStream()) { 

                channel.setIn(inp);
                channel.setOut(out);
                channel.setErr(err);

                OpenFuture openFuture = channel.open();
                CloseFuture closeFuture = session.close(false);
                openFuture.await();
                closeFuture.await();
                assertTrue("Not open", openFuture.isOpened());
                assertTrue("Not closed", closeFuture.isClosed());
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testCloseImmediateBeforeChannelOpened() throws Exception {
        channelLatch = new CountDownLatch(1);
        client.start();

        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);

            try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                InputStream inp = new ByteArrayInputStream(GenericUtils.EMPTY_BYTE_ARRAY);
                OutputStream out = new ByteArrayOutputStream();
                OutputStream err = new ByteArrayOutputStream()) { 

                channel.setIn(inp);
                channel.setOut(out);
                channel.setErr(err);

                OpenFuture openFuture = channel.open();
                CloseFuture closeFuture = session.close(true);
                channelLatch.countDown();
                openFuture.await();
                closeFuture.await();
                assertNotNull("No open exception", openFuture.getException());
                assertTrue("Not closed", closeFuture.isClosed());
            }
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPublicKeyAuth() throws Exception {
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
            session.addPublicKeyIdentity(pair);
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPublicKeyAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthPublicKey.UserAuthPublicKeyFactory.INSTANCE));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPublicKeyIdentity(Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA));
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPublicKeyAuthNewWithFailureOnFirstIdentity() throws Exception {
        final KeyPair pair = Utils.createTestHostKeyProvider().loadKey(KeyPairProvider.SSH_RSA);
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            public boolean authenticate(String username, PublicKey key, ServerSession session) {
                return key.equals(pair.getPublic());
            }
        });
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthPublicKey.UserAuthPublicKeyFactory.INSTANCE));
        client.start();

        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPublicKeyIdentity(new SimpleGeneratorHostKeyProvider(null, "RSA").loadKey(KeyPairProvider.SSH_RSA));
            session.addPublicKeyIdentity(pair);
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPasswordAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPassword.UserAuthPasswordFactory()));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testPasswordAuthNewWithFailureOnFirstIdentity() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPassword.UserAuthPasswordFactory()));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("bad");
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveAuthNew() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthKeyboardInteractive.UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveAuthNewWithFailureOnFirstIdentity() throws Exception {
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(UserAuthKeyboardInteractive.UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("bad");
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveWithFailures() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);

        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthKeyboardInteractive.UserAuthKeyboardInteractiveFactory()));
        client.setUserInteraction(new UserInteraction() {
            @Override
            public void welcome(String banner) {
                // ignored
            }
            @Override
            public String[] interactive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
                count.incrementAndGet();
                return new String[] { "bad" };
            }
        });
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            AuthFuture future = session.auth();
            future.await();
            assertTrue("Unexpected authentication success", future.isFailure());
            assertEquals("Mismatched authentication retry count", MAX_PROMPTS, count.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveInSessionUserInteractive() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);

        client.setUserAuthFactories(Arrays
                        .<NamedFactory<UserAuth>> asList(UserAuthKeyboardInteractive.UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.start();

        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.setUserInteraction(new UserInteraction() {
                    @Override
                    public void welcome(String banner) {
                        // ignored
                    }
        
                    @Override
                    public String[] interactive(String destination, String name, String instruction,
                                                String[] prompt, boolean[] echo) {
                        count.incrementAndGet();
                        return new String[] { "smx" };
                    }
                });
            AuthFuture future = session.auth();
            future.await();
            assertTrue("Authentication not marked as success", future.isSuccess());
            assertFalse("Authentication marked as failure", future.isFailure());
            assertEquals("Mismatched authentication attempts count", 1, count.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testKeyboardInteractiveInSessionUserInteractiveFailure() throws Exception {
        final AtomicInteger count = new AtomicInteger();
        final int MAX_PROMPTS = 3;
        FactoryManagerUtils.updateProperty(client, ClientFactoryManager.PASSWORD_PROMPTS, MAX_PROMPTS);
        client.setUserAuthFactories(Arrays
                        .<NamedFactory<UserAuth>> asList(new UserAuthKeyboardInteractive.UserAuthKeyboardInteractiveFactory()));
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.setUserInteraction(new UserInteraction() {
                @Override
                public void welcome(String banner) {
                    // ignored
                }
    
                @Override
                public String[] interactive(String destination, String name, String instruction,
                                            String[] prompt, boolean[] echo) {
                    count.incrementAndGet();
                    return new String[] { "bad" };
                }
            });
            AuthFuture future = session.auth();
            future.await();
            assertTrue("Authentication not, marked as failure", future.isFailure());
            assertEquals("Mismatched authentication retry count", MAX_PROMPTS, count.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testClientDisconnect() throws Exception {
        TestEchoShellFactory.TestEchoShell.latch = new CountDownLatch(1);
        try {
            client.start();
            
            try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
                session.addPasswordIdentity("smx");
                session.auth().verify(5L, TimeUnit.SECONDS);
                
                try(ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
                    PipedOutputStream pipedIn = new PipedOutputStream();
                    InputStream inPipe = new PipedInputStream(pipedIn); 
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteArrayOutputStream err = new ByteArrayOutputStream()) {

                    channel.setIn(inPipe);
                    channel.setOut(out);
                    channel.setErr(err);
                    channel.open().await();
        
        //            ((AbstractSession) session).disconnect(SshConstants.SSH2_DISCONNECT_BY_APPLICATION, "Cancel");
                    AbstractSession cs = (AbstractSession) session;
                    Buffer buffer = cs.createBuffer(SshConstants.SSH_MSG_DISCONNECT);
                    buffer.putInt(SshConstants.SSH2_DISCONNECT_BY_APPLICATION);
                    buffer.putString("Cancel");
                    buffer.putString("");
                    IoWriteFuture f = cs.writePacket(buffer);
                    f.await();
                    suspend(cs.getIoSession());
    
                    TestEchoShellFactory.TestEchoShell.latch.await();
                }
            } finally {
                client.stop();
            }
        } finally {
            TestEchoShellFactory.TestEchoShell.latch = null;
        }
    }

    @Test
    public void testWaitAuth() throws Exception {
        final AtomicBoolean ok = new AtomicBoolean();
        client.setServerKeyVerifier(
                new ServerKeyVerifier() {
                    @Override
                    public boolean verifyServerKey(
                            ClientSession sshClientSession,
                            SocketAddress remoteAddress,
                            PublicKey serverKey
                    ) {
                        System.out.println(serverKey);
                        ok.set(true);
                        return true;
                    }
                }
        );
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.waitFor(ClientSession.WAIT_AUTH, 10000);
            assertTrue(ok.get());
        } finally {
            client.stop();
        }
    }

    @Test
    public void testSwitchToNoneCipher() throws Exception {
        sshd.getCipherFactories().add(BuiltinCiphers.none);
        client.getCipherFactories().add(BuiltinCiphers.none);
        client.start();
        
        try(ClientSession session = client.connect("smx", "localhost", port).await().getSession()) {
            session.addPasswordIdentity("smx");
            session.auth().verify(5L, TimeUnit.SECONDS);
            session.switchToNoneCipher().await();
    
            try(ClientChannel channel = session.createSubsystemChannel(SftpConstants.SFTP_SUBSYSTEM_NAME)) {
                channel.open().verify(5L, TimeUnit.SECONDS);
            }
        } finally {
            client.stop();
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
