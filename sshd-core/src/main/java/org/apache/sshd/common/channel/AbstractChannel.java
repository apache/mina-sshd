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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannel
        extends CloseableUtils.AbstractInnerCloseable
        implements Channel, ExecutorServiceConfigurer {

    public static final int DEFAULT_WINDOW_SIZE = 0x200000;
    public static final int DEFAULT_PACKET_SIZE = 0x8000;

    public static final long DEFAULT_CHANNEL_CLOSE_TIMEOUT = 5000;

    /**
     * Default growth factor function used to resize response buffers
     */
    public static final Int2IntFunction RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.Utils.add(Byte.SIZE);

    protected static enum GracefulState {
        Opened, CloseSent, CloseReceived, Closed
    }

    protected ExecutorService executor;
    protected boolean shutdownExecutor;
    protected final Window localWindow = new Window(this, null, getClass().getName().contains(".client."), true);
    protected final Window remoteWindow = new Window(this, null, getClass().getName().contains(".client."), false);
    protected ConnectionService service;
    protected Session session;
    protected int id;
    protected int recipient;
    protected final AtomicBoolean eof = new AtomicBoolean(false);
    protected AtomicReference<GracefulState> gracefulState = new AtomicReference<GracefulState>(GracefulState.Opened);
    protected final DefaultCloseFuture gracefulFuture = new DefaultCloseFuture(lock);
    protected final List<RequestHandler<Channel>> handlers = new ArrayList<RequestHandler<Channel>>();

    protected AbstractChannel() {
        super();
    }

    protected AbstractChannel(String discriminator) {
        super(discriminator);
    }

    public void addRequestHandler(RequestHandler<Channel> handler) {
        handlers.add(handler);
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public int getRecipient() {
        return recipient;
    }

    @Override
    public Window getLocalWindow() {
        return localWindow;
    }

    @Override
    public Window getRemoteWindow() {
        return remoteWindow;
    }

    @Override
    public Session getSession() {
        return session;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public void setExecutorService(ExecutorService service) {
        executor = service;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    @Override
    public void setShutdownOnExit(boolean shutdown) {
        shutdownExecutor = shutdown;
    }

    @Override
    public void handleRequest(Buffer buffer) throws IOException {
        String req = buffer.getString();
        boolean wantReply = buffer.getBoolean();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_MSG_CHANNEL_REQUEST {} on channel {} (wantReply {})",
                      req, this, Boolean.valueOf(wantReply));
        }

        for (RequestHandler<Channel> handler : handlers) {
            RequestHandler.Result result;
            try {
                result = handler.process(this, req, wantReply, buffer);
            } catch (Exception e) {
                log.warn("Error processing channel request " + req, e);
                result = RequestHandler.Result.ReplyFailure;
            }
            
            // if Unsupported then check the next handler in line
            if (RequestHandler.Result.Unsupported.equals(result)) {
                if (log.isTraceEnabled()) {
                    log.trace("{}#process({}): {}", handler.getClass().getSimpleName(), req, result);
                }
            } else {
                sendResponse(buffer, req, result, wantReply);
                return;
            }
        }

        // none of the handlers processed the request
        log.warn("Unknown channel request: {}", req);
        sendResponse(buffer, req, RequestHandler.Result.Unsupported, wantReply);
    }

    protected void sendResponse(Buffer buffer, String req, RequestHandler.Result result, boolean wantReply) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) result={}, want-reply={}", req, result, Boolean.valueOf(wantReply));
        }

        if (RequestHandler.Result.Replied.equals(result) || (!wantReply)) {
            return;
        }

        byte cmd = RequestHandler.Result.ReplySuccess.equals(result)
                 ? SshConstants.SSH_MSG_CHANNEL_SUCCESS
                 : SshConstants.SSH_MSG_CHANNEL_FAILURE;
        buffer.clear();
        // leave room for the SSH header
        buffer.ensureCapacity(5 + 1 + (Integer.SIZE / Byte.SIZE), RESPONSE_BUFFER_GROWTH_FACTOR);
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd);
        buffer.putInt(recipient);
        session.writePacket(buffer);
    }

    @Override
    public void init(ConnectionService service, Session session, int id) {
        this.service = service;
        this.session = session;
        this.id = id;
        configureWindow();
    }

    protected void notifyStateChanged() {
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public void handleClose() throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_CLOSE on channel {}", this);
        if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseReceived)) {
            close(false);
        } else if (gracefulState.compareAndSet(GracefulState.CloseSent, GracefulState.Closed)) {
            gracefulFuture.setClosed();
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return new GracefulChannelCloseable();
    }

    public class GracefulChannelCloseable extends CloseableUtils.IoBaseCloseable {

        private final AtomicBoolean closing = new AtomicBoolean(false);

        public GracefulChannelCloseable() {
            super();
        }

        @Override
        public boolean isClosing() {
            return closing.get();
        }

        public void setClosing(boolean on) {
            closing.set(on);
        }

        @Override
        public boolean isClosed() {
            return gracefulFuture.isClosed();
        }

        @Override
        public CloseFuture close(boolean immediately) {
            setClosing(true);
            if (immediately) {
                gracefulFuture.setClosed();
            } else if (!gracefulFuture.isClosed()) {
                log.debug("Send SSH_MSG_CHANNEL_CLOSE on channel {}", AbstractChannel.this);
                Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_CLOSE);
                buffer.putInt(recipient);
                try {
                    long timeout = FactoryManagerUtils.getLongProperty(getSession(), FactoryManager.CHANNEL_CLOSE_TIMEOUT, DEFAULT_CHANNEL_CLOSE_TIMEOUT);
                    session.writePacket(buffer, timeout, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
                        @SuppressWarnings("synthetic-access")
                        @Override
                        public void operationComplete(IoWriteFuture future) {
                            if (future.isWritten()) {
                                log.debug("Message SSH_MSG_CHANNEL_CLOSE written on channel {}", AbstractChannel.this);
                                if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseSent)) {
                                    // Waiting for CLOSE message to come back from the remote side
                                } else if (gracefulState.compareAndSet(GracefulState.CloseReceived, GracefulState.Closed)) {
                                    gracefulFuture.setClosed();
                                }
                            } else {
                                log.debug("Failed to write SSH_MSG_CHANNEL_CLOSE on channel {}", AbstractChannel.this);
                                AbstractChannel.this.close(true);
                            }
                        }
                    });
                } catch (IOException e) {
                    log.debug("Exception caught while writing SSH_MSG_CHANNEL_CLOSE packet on channel " + AbstractChannel.this, e);
                    AbstractChannel.this.close(true);
                }
            }

            ExecutorService service = getExecutorService();
            if ((service != null) && isShutdownOnExit() && (!service.isShutdown())) {
                Collection<?> running = service.shutdownNow();
                if (log.isDebugEnabled()) {
                    log.debug("Shutdown executor service on close - running count=" + GenericUtils.size(running));
                }
            }

            return gracefulFuture;
        }
    }

    @Override
    protected void doCloseImmediately() {
        if (service != null) {
            service.unregisterChannel(AbstractChannel.this);
        }
        super.doCloseImmediately();
    }

    protected void writePacket(Buffer buffer) throws IOException {
        if (!isClosing()) {
            session.writePacket(buffer);
        } else {
            log.debug("Discarding output packet because channel is being closed");
        }
    }

    @Override
    public void handleData(Buffer buffer) throws IOException {
        int len = buffer.getInt();
        if (len < 0 || len > ByteArrayBuffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        log.debug("Received SSH_MSG_CHANNEL_DATA on channel {}", this);
        if (log.isTraceEnabled()) {
            log.trace("Received channel data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
        }
        doWriteData(buffer.array(), buffer.rpos(), len);
    }

    @Override
    public void handleExtendedData(Buffer buffer) throws IOException {
        int ex = buffer.getInt();
        // Only accept extended data for stderr
        if (ex != 1) {
            log.debug("Send SSH_MSG_CHANNEL_FAILURE on channel {}", this);
            buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE);
            buffer.putInt(recipient);
            writePacket(buffer);
            return;
        }
        int len = buffer.getInt();
        if (len < 0 || len > ByteArrayBuffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        log.debug("Received SSH_MSG_CHANNEL_EXTENDED_DATA on channel {}", this);
        if (log.isTraceEnabled()) {
            log.trace("Received channel extended data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
        }
        doWriteExtendedData(buffer.array(), buffer.rpos(), len);
    }

    public boolean isEofSignalled() {
        return eof.get();
    }

    public void setEofSignalled(boolean on) {
        eof.set(on);
    }

    @Override
    public void handleEof() throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_EOF on channel {}", this);
        setEofSignalled(true);
        notifyStateChanged();
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", this);
        int window = buffer.getInt();
        remoteWindow.expand(window);
    }

    @Override
    public void handleFailure() throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_FAILURE on channel {}", this);
        // TODO: do something to report failed requests?
    }

    protected abstract void doWriteData(byte[] data, int off, int len) throws IOException;

    protected abstract void doWriteExtendedData(byte[] data, int off, int len) throws IOException;

    protected void sendEof() throws IOException {
        log.debug("Send SSH_MSG_CHANNEL_EOF on channel {}", this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_EOF);
        buffer.putInt(recipient);
        writePacket(buffer);
    }

    protected void configureWindow() {
        localWindow.init(session);
    }

    protected void sendWindowAdjust(int len) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Send SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", Integer.valueOf(id));
        }
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        buffer.putInt(recipient);
        buffer.putInt(len);
        writePacket(buffer);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + id + ", recipient=" + recipient + "]";
    }
}
