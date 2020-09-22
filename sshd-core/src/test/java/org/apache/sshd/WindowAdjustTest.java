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
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AsyncCommand;
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
 * This test simulates heavy traffic coming from the server towards the client making sure the traffic does not get
 * stuck. Especially if the server receives window adjust message while it tries to transfer all the data.
 * </p>
 * {@link AsyncInPendingWrapper} in this test serves as a handler for {@link WritePendingException}, which can occur
 * when sending too many messages one after another.
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

        byte[] msg = IoUtils.toByteArray(getClass().getResourceAsStream("/big-msg.txt"));
        sshServer.setShellFactory(
                channel -> new FloodingAsyncCommand(msg, BIG_MSG_SEND_COUNT, END_FILE));

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

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);

                try (ClientChannel channel = session.createShellChannel()) {
                    channel.setOut(new VerifyingOutputStream(channel, END_FILE));
                    channel.setErr(new NoCloseOutputStream(System.err));
                    channel.open().verify(OPEN_TIMEOUT);

                    Collection<ClientChannelEvent> result
                            = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.MINUTES.toMillis(2L));
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
        private final AtomicReference<Future<?>> futureHolder = new AtomicReference<>();

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
        public void start(ChannelSession channel, Environment env) throws IOException {
            log.info("Starting");

            ExecutorService service
                    = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName() + "-" + POOL_COUNT.incrementAndGet());
            executorHolder.set(service);

            futureHolder.set(service.submit((Runnable) () -> {
                log.info("Start heavy load sending " + sendCount + " messages of " + msg.length + " bytes");
                for (int i = 0; i < sendCount; i++) {
                    try {
                        pendingWrapper.write(new ByteArrayBuffer(msg));
                    } catch (IOException e) {
                        log.error("Failed ({}) to send message #{}/{}: {}",
                                e.getClass().getSimpleName(), i + 1, sendCount, e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
                log.info("Sending EOF signal");

                try {
                    pendingWrapper.write(new ByteArrayBuffer(new byte[] { eofSignal }));
                } catch (IOException e) {
                    log.error("Failed ({}) to send EOF message after {} messages: {}",
                            e.getClass().getSimpleName(), sendCount, e.getMessage());
                    throw new RuntimeException(e);
                }
            }));
            log.info("Started");
        }

        @Override
        public void destroy(ChannelSession channel) {
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
     * Wrapper for asyncIn stream that catches Pending exception and queues the pending messages for later retry (send
     * after previous messages were fully transfered)
     */
    private static class AsyncInPendingWrapper extends AbstractLoggingBean {
        private IoOutputStream asyncIn;

        // Order has to be preserved for queued writes
        private final Deque<Buffer> pending = new LinkedList<>();

        AsyncInPendingWrapper(IoOutputStream out) {
            this.asyncIn = out;
        }

        public synchronized void write(Object msg) throws IOException {
            if ((asyncIn != null) && (!asyncIn.isClosed()) && (!asyncIn.isClosing())) {
                Buffer byteBufferMsg = (Buffer) msg;
                if (!pending.isEmpty()) {
                    queueRequest(byteBufferMsg);
                    return;
                }

                writeWithPendingDetection(byteBufferMsg, false);
            }
        }

        private void writeWithPendingDetection(Buffer msg, boolean wasPending) throws IOException {
            try {
                asyncIn.writeBuffer(msg).addListener(future -> {
                    if (future.isWritten()) {
                        if (wasPending) {
                            pending.remove();
                        }

                        try {
                            writePendingIfAny();
                        } catch (IOException e) {
                            log.error("Failed ({}) to re-write pending: {}", e.getClass().getSimpleName(), e.getMessage());
                        }
                    } else {
                        Throwable t = future.getException();
                        log.warn("Failed to write message", t);
                    }
                });
            } catch (final WritePendingException e) {
                if (!wasPending) {
                    queueRequest(msg);
                }
            }
        }

        private synchronized void writePendingIfAny() throws IOException {
            if (pending.peek() == null) {
                return;
            }

            Buffer msg = pending.peek();
            writeWithPendingDetection(msg, true);
        }

        private void queueRequest(Buffer msg) {
            msg.rpos(0);
            pending.add(msg);
        }
    }
}
