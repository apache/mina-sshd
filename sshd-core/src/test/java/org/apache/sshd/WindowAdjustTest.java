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
package org.apache.sshd;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Deque;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
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
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.AsyncCommand;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * This test simulates heavy traffic coming from the server towards the client making sure the traffic does not get stuck.
 * Especially if the server receives window adjust message while it tries to transfer all the data.
 * </p>
 * {@link AsyncInPendingWrapper} in this test serves as a handler for
 * {@link WritePendingException}, which can occur when sending too many messages one after another.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WindowAdjustTest extends BaseTestSupport {

    public static final byte END_FILE = '#';
    public static final int BIG_MSG_SEND_COUNT = 10000;

    private SshServer sshServer;
    private int port;

    public WindowAdjustTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshServer = setupTestServer();

        final byte[] msg = Files.readAllBytes(
                Paths.get(getClass().getResource("/big-msg.txt").toURI()));
        sshServer.setShellFactory(new Factory<Command>() {
            @Override
            public Command create() {
                return new FloodingAsyncCommand(msg, BIG_MSG_SEND_COUNT, END_FILE);
            }
        });

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

    @Test(timeout = 6L * 60L * 1000L)
    public void testTrafficHeavyLoad() throws Exception {
        try (SshClient client = setupTestClient()) {
            client.start();

            try (final ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(11L, TimeUnit.SECONDS);

                try (final ClientChannel channel = session.createShellChannel()) {
                    channel.setOut(new VerifyingOutputStream(channel, END_FILE));
                    channel.setErr(new NoCloseOutputStream(System.err));
                    channel.open().verify(15L, TimeUnit.SECONDS);

                    Collection<ClientChannelEvent> result =
                            channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.MINUTES.toMillis(2L));
                    assertFalse("Timeout while waiting for channel closure", result.contains(ClientChannelEvent.TIMEOUT));
                }
            } finally {
                client.stop();
            }
        }
    }

    /**
     * Read all incoming data and if END_FILE symbol is detected, kill client session to end test
     */
    private static class VerifyingOutputStream extends OutputStream {
        private final Logger log;
        private final ClientChannel channel;
        private final byte eofSignal;

        VerifyingOutputStream(ClientChannel channel, final byte eofSignal) {
            this.log = LoggerFactory.getLogger(getClass());
            this.channel = channel;
            this.eofSignal = eofSignal;
        }

        @Override
        public void write(int b) throws IOException {
            if (channel.isClosed() || channel.isClosing()) {
                throw new IOException("Channel (" + channel + ") is closing / closed on write single byte");
            }

            if (b == (eofSignal & 0xff)) {
                log.info("Closing channel (" + channel + ") due to single byte EOF");
                channel.close(true);
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (channel.isClosed() || channel.isClosing()) {
                throw new IOException("Channel (" + channel + ") is closing / closed on write " + len + " bytes");
            }

            if (len <= 0) {
                return;
            }

            int lastPos = off + len - 1;
            if ((b[lastPos] & 0xFF) == (eofSignal & 0xFF)) {
                log.info("Closing channel (" + channel + ") due to last byte EOF");
                channel.close(true);
            }
        }
    }

    public static final class FloodingAsyncCommand extends AbstractLoggingBean implements AsyncCommand {
        private static final AtomicInteger POOL_COUNT = new AtomicInteger(0);

        private final AtomicReference<ExecutorService> executorHolder = new AtomicReference<>();
        private final AtomicReference<Future<?>> futureHolder = new AtomicReference<Future<?>>();

        private AsyncInPendingWrapper pendingWrapper;
        private byte[] msg;
        private int sendCount;
        private byte eofSignal;

        public FloodingAsyncCommand(final byte[] msg, final int sendCount, final byte eofSignal) {
            this.msg = msg;
            this.sendCount = sendCount;
            this.eofSignal = eofSignal;
        }

        @Override
        public void setIoInputStream(IoInputStream in) {
            // ignored
        }

        @Override
        public void setIoOutputStream(IoOutputStream out) {
            pendingWrapper = new AsyncInPendingWrapper(out);
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
            log.info("Starting");

            ExecutorService service = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName() + "-" + POOL_COUNT.incrementAndGet());
            executorHolder.set(service);

            futureHolder.set(service.submit(new Runnable() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    log.info("Start heavy load sending " + sendCount + " messages of " + msg.length + " bytes");
                    for (int i = 0; i < sendCount; i++) {
                        pendingWrapper.write(new ByteArrayBuffer(msg));
                    }
                    log.info("Sending EOF signal");
                    pendingWrapper.write(new ByteArrayBuffer(new byte[]{eofSignal}));
                }
            }));
            log.info("Started");
        }

        @Override
        public void destroy() {
            log.info("Destroying");

            Future<?> future = futureHolder.getAndSet(null);
            if ((future != null) && (!future.isDone())) {
                log.info("Cancelling");
                future.cancel(true);
            }

            ExecutorService service = executorHolder.getAndSet(null);
            if ((service != null) && (!service.isShutdown())) {
                log.info("Shutdown");
                service.shutdownNow();
            }
        }
    }

    /**
     * Wrapper for asyncIn stream that catches Pending exception and queues the pending messages for later retry (send after previous messages were fully transfered)
     */
    private static class AsyncInPendingWrapper extends AbstractLoggingBean {
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

        AsyncInPendingWrapper(IoOutputStream out) {
            this.asyncIn = out;
        }

        public synchronized void write(final Object msg) {
            if ((asyncIn != null) && (!asyncIn.isClosed()) && (!asyncIn.isClosing())) {
                final Buffer byteBufferMsg = (Buffer) msg;
                if (!pending.isEmpty()) {
                    queueRequest(byteBufferMsg);
                    return;
                }

                writeWithPendingDetection(byteBufferMsg, false);
            }
        }

        private void writeWithPendingDetection(final Buffer msg, final boolean wasPending) {
            try {
                asyncIn.write(msg).addListener(new SshFutureListener<IoWriteFuture>() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public void operationComplete(IoWriteFuture future) {
                        if (future.isWritten()) {
                            if (wasPending) {
                                pending.remove();
                            }
                            writePendingIfAny();
                        } else {
                            Throwable t = future.getException();
                            log.warn("Failed to write message", t);
                        }
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