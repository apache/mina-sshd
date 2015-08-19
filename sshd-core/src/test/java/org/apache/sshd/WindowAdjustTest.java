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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.server.AsyncCommand;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * <p>
 * This test simulates heavy traffic coming from the server towards the client making sure the traffic does not get stuck.
 * Especially if the server receives window adjust message while it tries to transfer all the data.
 * </p>
 * {@link AsyncInPendingWrapper} in this test serves as a handler for
 * {@link WritePendingException}, which can occur when sending too many messages one after another.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WindowAdjustTest {

    public static final String END_FILE = "#";

    private SshServer sshServer;
    private int port;

    @Before
    public void setUp() throws Exception {
        sshServer = SshServer.setUpDefaultServer();
        final byte[] msg = Files.readAllBytes(
                Paths.get(getClass().getResource("/big-msg.txt").toURI()));

        sshServer.setShellFactory(new Factory<Command>() {
            @Override
            public Command create() {
                return new FloodingAsyncCommand(msg, 10000, END_FILE);
            }
        });

        sshServer.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshServer.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshServer.start();
        port = sshServer.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshServer != null) {
            sshServer.stop();
            sshServer.close(true);
        }
    }

    @Test(timeout = 60 * 1000L)
    public void testTrafficHeavyLoad() throws Exception {

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.start();

            try (final ClientSession session = client.connect("admin", "localhost", port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity("admin");
                session.auth().verify();

                try (final ClientChannel channel = session.createShellChannel()) {
                    channel.setOut(new VerifyingOutputStream(channel, END_FILE));
                    channel.setErr(new NoCloseOutputStream(System.err));
                    channel.open();

                    channel.waitFor(ClientChannel.CLOSED, 0);
                }
                session.close(true);
            } finally {
                client.stop();
            }
        }
    }

    /**
     * Read all incoming data and if END_FILE symbol is detected, kill client session to end test
     */
    private static class VerifyingOutputStream extends OutputStream {

        private final ClientChannel channel;
        private String endFile;

        public VerifyingOutputStream(ClientChannel channel, final String lastMsg) {
            this.channel = channel;
            this.endFile = lastMsg;
        }

        @Override
        public void write(int b) throws IOException {
            if (String.valueOf((char) b).equals(endFile)) {
                channel.close(true);
            }
        }
    }

    public static final class FloodingAsyncCommand implements AsyncCommand {

        private byte[] msg;
        private int sendCount;
        private String lastMsg;

        public FloodingAsyncCommand(final byte[] msg, final int sendCount, final String lastMsg) {
            this.msg = msg;
            this.sendCount = sendCount;
            this.lastMsg = lastMsg;
        }

        @Override
        public void setIoInputStream(IoInputStream in) {
            // ignored
        }

        @Override
        public void setIoOutputStream(IoOutputStream out) {
            final AsyncInPendingWrapper a = new AsyncInPendingWrapper(out);

            new Thread(new Runnable() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    for (int i = 0; i < sendCount; i++) {
                        a.write(new ByteArrayBuffer(msg));
                    }
                    a.write(new ByteArrayBuffer((lastMsg.getBytes(StandardCharsets.UTF_8))));
                }
            }).start();
        }

        @Override
        public void setIoErrorStream(IoOutputStream err) {
            // ignored
        }

        @Override
        public void setInputStream(InputStream in) {
            // ignored
        }

        @Override
        public void setOutputStream(OutputStream out) {
            // ignored
        }

        @Override
        public void setErrorStream(OutputStream err) {
            // ignored
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            // ignored
        }

        @Override
        public void start(Environment env) throws IOException {
            // ignored
        }

        @Override
        public void destroy() {
            // ignored
        }
    }

    /**
     * Wrapper for asyncIn stream that catches Pending exception and queues the pending messages for later retry (send after previous messages were fully transfered)
     */
    private static class AsyncInPendingWrapper {
        private IoOutputStream asyncIn;

        // Order has to be preserved for queued writes
        private final Deque<Buffer> pending = new LinkedList<Buffer>() {
            // we don't expect to serialize it
            private static final long serialVersionUID = 1L;

            @Override
            public boolean add(Buffer o) {
                return super.add(o);
            }
        };

        public AsyncInPendingWrapper(IoOutputStream out) {
            this.asyncIn = out;
        }

        public synchronized void write(final Object msg) {
            if (asyncIn != null && !asyncIn.isClosed() && !asyncIn.isClosing()) {

                final Buffer ByteBufferMsg = (Buffer) msg;
                if (!pending.isEmpty()) {
                    queueRequest(ByteBufferMsg);
                    return;
                }

                writeWithPendingDetection(ByteBufferMsg, false);
            }
        }

        private void writeWithPendingDetection(final Buffer msg, final boolean wasPending) {
            try {
                asyncIn.write(msg).addListener(new SshFutureListener<IoWriteFuture>() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public void operationComplete(final IoWriteFuture future) {
                        if (wasPending) {
                            pending.remove();
                        }
                        writePendingIfAny();
                    }
                });
            } catch (final WritePendingException e) {
                if (!wasPending) {
                    queueRequest(msg);
                }
            }
        }

        private synchronized void writePendingIfAny() {
            if (pending.peek() == null) {
                return;
            }

            final Buffer msg = pending.peek();
            writeWithPendingDetection(msg, true);
        }

        private void queueRequest(final Buffer msg) {
            msg.rpos(0);
            pending.add(msg);
        }
    }
}