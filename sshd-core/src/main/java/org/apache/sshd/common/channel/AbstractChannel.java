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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RequestHandler;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.CloseableUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannel extends CloseableUtils.AbstractInnerCloseable implements Channel {

    public static final int DEFAULT_WINDOW_SIZE = 0x200000;
    public static final int DEFAULT_PACKET_SIZE = 0x8000;

    public static final long DEFAULT_CHANNEL_CLOSE_TIMEOUT = 5000;

    protected static enum GracefulState {
        Opened, CloseSent, CloseReceived, Closed
    }

    protected final Window localWindow = new Window(this, null, getClass().getName().contains(".client."), true);
    protected final Window remoteWindow = new Window(this, null, getClass().getName().contains(".client."), false);
    protected ConnectionService service;
    protected Session session;
    protected int id;
    protected int recipient;
    protected volatile boolean eof;
    protected AtomicReference<GracefulState> gracefulState = new AtomicReference<GracefulState>(GracefulState.Opened);
    protected final DefaultCloseFuture gracefulFuture = new DefaultCloseFuture(lock);
    protected final List<RequestHandler<Channel>> handlers = new ArrayList<RequestHandler<Channel>>();

    public void addRequestHandler(RequestHandler<Channel> handler) {
        handlers.add(handler);
    }

    public int getId() {
        return id;
    }

    public int getRecipient() {
        return recipient;
    }

    public Window getLocalWindow() {
        return localWindow;
    }

    public Window getRemoteWindow() {
        return remoteWindow;
    }

    public Session getSession() {
        return session;
    }

    public void handleRequest(Buffer buffer) throws IOException {
        String req = buffer.getString();
        boolean wantReply = buffer.getBoolean();
        log.debug("Received SSH_MSG_CHANNEL_REQUEST {} on channel {} (wantReply {})", new Object[] { req, this, wantReply });
        for (RequestHandler<Channel> handler : handlers) {
            RequestHandler.Result result;
            try {
                result = handler.process(this, req, wantReply, buffer);
            } catch (Exception e) {
                log.warn("Error processing channel request " + req, e);
                result = RequestHandler.Result.ReplyFailure;
            }
            switch (result) {
                case Replied:
                    return;
                case ReplySuccess:
                    if (wantReply) {
                        buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_SUCCESS);
                        buffer.putInt(recipient);
                        session.writePacket(buffer);
                    }
                    return;
                case ReplyFailure:
                    if (wantReply) {
                        buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE);
                        buffer.putInt(recipient);
                        session.writePacket(buffer);
                    }
                    return;
            }
        }
        log.warn("Unknown channel request: {}", req);
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE);
            buffer.putInt(recipient);
            session.writePacket(buffer);
        }
    }

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

    public void handleClose() throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_CLOSE on channel {}", this);
        if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseReceived)) {
            close(false);
        } else if (gracefulState.compareAndSet(GracefulState.CloseSent, GracefulState.Closed)) {
            gracefulFuture.setClosed();
        }
    }

    protected Closeable getInnerCloseable() {
        return new GracefulChannelCloseable();
    }

    public class GracefulChannelCloseable implements Closeable {

        protected volatile boolean closing;

        public boolean isClosing() {
            return closing;
        }
        public boolean isClosed() {
            return gracefulFuture.isClosed();
        }
        public CloseFuture close(boolean immediately) {
            closing = true;
            if (immediately) {
                gracefulFuture.setClosed();
            } else if (!gracefulFuture.isClosed()) {
                log.debug("Send SSH_MSG_CHANNEL_CLOSE on channel {}", AbstractChannel.this);
                Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_CLOSE);
                buffer.putInt(recipient);
                try {
                    long timeout = DEFAULT_CHANNEL_CLOSE_TIMEOUT;
                    String val = getSession().getFactoryManager().getProperties().get(FactoryManager.CHANNEL_CLOSE_TIMEOUT);
                    if (val != null) {
                        try {
                            timeout = Long.parseLong(val);
                        } catch (NumberFormatException e) {
                            // Ignore
                        }
                    }
                    session.writePacket(buffer, timeout, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
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
            return gracefulFuture;
        }
    }

    @Override
    protected void doCloseImmediately() {
        service.unregisterChannel(AbstractChannel.this);
        super.doCloseImmediately();
    }

    protected void writePacket(Buffer buffer) throws IOException {
        if (!isClosing()) {
            session.writePacket(buffer);
        } else {
            log.debug("Discarding output packet because channel is being closed");
        }
    }

    public void handleData(Buffer buffer) throws IOException {
        int len = buffer.getInt();
        if (len < 0 || len > Buffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        log.debug("Received SSH_MSG_CHANNEL_DATA on channel {}", this);
        if (log.isTraceEnabled()) {
            log.trace("Received channel data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
        }
        doWriteData(buffer.array(), buffer.rpos(), len);
    }

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
        if (len < 0 || len > Buffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        log.debug("Received SSH_MSG_CHANNEL_EXTENDED_DATA on channel {}", this);
        if (log.isTraceEnabled()) {
            log.trace("Received channel extended data: {}", BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
        }
        doWriteExtendedData(buffer.array(), buffer.rpos(), len);
    }

    public void handleEof() throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_EOF on channel {}", this);
        eof = true;
        notifyStateChanged();
    }

    public void handleWindowAdjust(Buffer buffer) throws IOException {
        log.debug("Received SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", this);
        int window = buffer.getInt();
        remoteWindow.expand(window);
    }

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
        int window = session.getIntProperty(FactoryManager.WINDOW_SIZE, DEFAULT_WINDOW_SIZE);
        int packet = session.getIntProperty(FactoryManager.MAX_PACKET_SIZE, DEFAULT_PACKET_SIZE);
        localWindow.init(window, packet);
    }

    protected void sendWindowAdjust(int len) throws IOException {
        log.debug("Send SSH_MSG_CHANNEL_WINDOW_ADJUST on channel {}", id);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        buffer.putInt(recipient);
        buffer.putInt(len);
        writePacket(buffer);
    }

    public String toString() {
        return getClass().getSimpleName() + "[id=" + id + ", recipient=" + recipient + "]";
    }
}
