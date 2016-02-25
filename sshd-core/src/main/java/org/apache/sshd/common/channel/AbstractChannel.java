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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannel
        extends AbstractInnerCloseable
        implements Channel, ExecutorServiceConfigurer {

    /**
     * Default growth factor function used to resize response buffers
     */
    public static final Int2IntFunction RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.Utils.add(Byte.SIZE);

    protected enum GracefulState {
        Opened, CloseSent, CloseReceived, Closed
    }

    protected ExecutorService executor;
    protected boolean shutdownExecutor;
    protected final Window localWindow;
    protected final Window remoteWindow;
    protected ConnectionService service;
    protected final AtomicBoolean eof = new AtomicBoolean(false);
    protected AtomicReference<GracefulState> gracefulState = new AtomicReference<GracefulState>(GracefulState.Opened);
    protected final DefaultCloseFuture gracefulFuture = new DefaultCloseFuture(lock);
    protected final List<RequestHandler<Channel>> handlers = new ArrayList<RequestHandler<Channel>>();
    /**
     * Channel events listener
     */
    protected final Collection<ChannelListener> channelListeners = new CopyOnWriteArraySet<>();
    protected final ChannelListener channelListenerProxy;

    private int id = -1;
    private int recipient = -1;
    private Session session;
    /**
     * A {@link Map} of sent requests - key = request name, value = timestamp when
     * request was sent.
     */
    private final Map<String, Date> pendingRequests = new ConcurrentHashMap<>();
    private final Map<String, Object> properties = new ConcurrentHashMap<>();

    protected AbstractChannel(boolean client) {
        this("", client);
    }

    protected AbstractChannel(String discriminator, boolean client) {
        super(discriminator);
        localWindow = new Window(this, null, client, true);
        remoteWindow = new Window(this, null, client, false);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, getClass().getClassLoader(), channelListeners);
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

    protected void setRecipient(int recipient) {
        if (log.isDebugEnabled()) {
            log.debug("setRecipient({}) recipient={}", this, recipient);
        }
        this.recipient = recipient;
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
    public PropertyResolver getParentPropertyResolver() {
        return getSession();
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

    /**
     * Add a channel request to the tracked pending ones if reply is expected
     *
     * @param request The request type
     * @param wantReply {@code true} if reply is expected
     * @return The allocated {@link Date} timestamp - {@code null} if no reply
     * is expected (in which case the request is not tracked)
     * @throws IllegalArgumentException If the request is already being tracked
     * @see #removePendingRequest(String)
     */
    protected Date addPendingRequest(String request, boolean wantReply) {
        if (!wantReply) {
            return null;
        }

        Date pending = new Date(System.currentTimeMillis());
        Date prev = pendingRequests.put(request, pending);
        ValidateUtils.checkTrue(prev == null, "Multiple pending requests of type=%s", request);
        if (log.isDebugEnabled()) {
            log.debug("addPendingRequest({}) request={}, pending={}", this, request, pending);
        }
        return pending;
    }

    /**
     * Removes a channel request from the tracked ones
     *
     * @param request The request type
     * @return The allocated {@link Date} timestamp - {@code null} if the
     * specified request type is not being tracked or has not been added to
     * the tracked ones to begin with
     * @see #addPendingRequest(String, boolean)
     */
    protected Date removePendingRequest(String request) {
        Date pending = pendingRequests.remove(request);
        if (log.isDebugEnabled()) {
            log.debug("removePendingRequest({}) request={}, pending={}", this, request, pending);
        }
        return pending;
    }

    @Override
    public void handleRequest(Buffer buffer) throws IOException {
        handleChannelRequest(buffer.getString(), buffer.getBoolean(), buffer);
    }

    protected void handleChannelRequest(String req, boolean wantReply, Buffer buffer) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("handleChannelRequest({}) SSH_MSG_CHANNEL_REQUEST {} wantReply={}", this, req, wantReply);
        }

        for (RequestHandler<Channel> handler : handlers) {
            RequestHandler.Result result;
            try {
                result = handler.process(this, req, wantReply, buffer);
            } catch (Exception e) {
                log.warn("handleRequest({}) {} while {}#process({})[want-reply={}]: {}",
                         this, e.getClass().getSimpleName(), handler.getClass().getSimpleName(),
                         req, wantReply, e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("handleRequest(" + this + ") request=" + req
                            + "[want-reply=" + wantReply + "] processing failure details",
                              e);
                }
                result = RequestHandler.Result.ReplyFailure;
            }

            // if Unsupported then check the next handler in line
            if (RequestHandler.Result.Unsupported.equals(result)) {
                if (log.isTraceEnabled()) {
                    log.trace("handleRequest({})[{}#process({})[want-reply={}]]: {}",
                              this, handler.getClass().getSimpleName(), req, wantReply, result);
                }
            } else {
                sendResponse(buffer, req, result, wantReply);
                return;
            }
        }

        // none of the handlers processed the request
        handleUnknownChannelRequest(req, wantReply, buffer);
    }

    /**
     * Called when none of the register request handlers reported handling the request
     *
     * @param req       The request type
     * @param wantReply Whether reply is requested
     * @param buffer    The {@link Buffer} containing extra request-specific data
     * @throws IOException If failed to send the response (if needed)
     * @see #handleInternalRequest(String, boolean, Buffer)
     */
    protected void handleUnknownChannelRequest(String req, boolean wantReply, Buffer buffer) throws IOException {
        RequestHandler.Result r = handleInternalRequest(req, wantReply, buffer);
        if ((r == null) || RequestHandler.Result.Unsupported.equals(r)) {
            log.warn("handleUnknownChannelRequest({}) Unknown channel request: {}[want-reply={}]", this, req, wantReply);
            sendResponse(buffer, req, RequestHandler.Result.Unsupported, wantReply);
        } else {
            sendResponse(buffer, req, r, wantReply);
        }
    }

    /**
     * Called by {@link #handleUnknownChannelRequest(String, boolean, Buffer)}
     * in order to allow channel request handling if none of the registered handlers
     * processed the request - last chance.
     *
     * @param req       The request type
     * @param wantReply Whether reply is requested
     * @param buffer    The {@link Buffer} containing extra request-specific data
     * @return          The handling result - if {@code null} or {@code Unsupported}
     *                  and reply is required then a failure message will be sent
     * @throws IOException If failed to process the request internally
     */
    protected RequestHandler.Result handleInternalRequest(String req, boolean wantReply, Buffer buffer) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("handleInternalRequest({})[want-reply={}] unknown type: {}",
                      this, wantReply, req);
        }

        return RequestHandler.Result.Unsupported;
    }

    protected void sendResponse(Buffer buffer, String req, RequestHandler.Result result, boolean wantReply) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) request={} result={}, want-reply={}", this, req, result, wantReply);
        }

        if (RequestHandler.Result.Replied.equals(result) || (!wantReply)) {
            return;
        }

        byte cmd = RequestHandler.Result.ReplySuccess.equals(result)
                 ? SshConstants.SSH_MSG_CHANNEL_SUCCESS
                 : SshConstants.SSH_MSG_CHANNEL_FAILURE;
        Session session = getSession();
        Buffer rsp = session.createBuffer(cmd, Integer.SIZE / Byte.SIZE);
        rsp.putInt(recipient);
        session.writePacket(rsp);
    }

    @Override
    public void init(ConnectionService service, Session session, int id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("init() service={} session={} id={}", service, session, id);
        }
        this.service = service;
        this.session = session;
        this.id = id;

        ChannelListener listener = session.getChannelListenerProxy();
        try {
            listener.channelInitialized(this);
        } catch (RuntimeException t) {
            Throwable e = GenericUtils.peelException(t);
            throw new IOException("Failed (" + e.getClass().getSimpleName() + ") to notify channel " + toString() + " initialization: " + e.getMessage(), e);
        }
        // delegate the rest of the notifications to the channel
        addChannelListener(listener);
        configureWindow();
    }

    protected void notifyStateChanged() {
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ValidateUtils.checkNotNull(listener, "addChannelListener(%s) null instance", this);
        // avoid race conditions on notifications while channel is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while channel is closing", this, listener);
            return;
        }

        if (this.channelListeners.add(listener)) {
            log.trace("addChannelListener({})[{}] registered", this, listener);
        } else {
            log.trace("addChannelListener({})[{}] ignored duplicate", this, listener);
        }
    }

    @Override
    public void removeChannelListener(ChannelListener listener) {
        if (this.channelListeners.remove(listener)) {
            log.trace("removeChannelListener({})[{}] removed", this, listener);
        } else {
            log.trace("removeChannelListener({})[{}] not registered", this, listener);
        }
    }

    @Override
    public ChannelListener getChannelListenerProxy() {
        return channelListenerProxy;
    }

    @Override
    public void handleClose() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("handleClose({}) SSH_MSG_CHANNEL_CLOSE on channel", this);
        }
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

    public class GracefulChannelCloseable extends IoBaseCloseable {

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
        public CloseFuture close(final boolean immediately) {
            final Channel channel = AbstractChannel.this;
            if (log.isDebugEnabled()) {
                log.debug("close({})[immediately={}] SSH_MSG_CHANNEL_CLOSE on channel", channel, immediately);
            }

            setClosing(true);
            if (immediately) {
                gracefulFuture.setClosed();
            } else if (!gracefulFuture.isClosed()) {
                Session s = getSession();
                Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_CLOSE, Short.SIZE);
                buffer.putInt(getRecipient());

                try {
                    long timeout = PropertyResolverUtils.getLongProperty(channel, FactoryManager.CHANNEL_CLOSE_TIMEOUT, FactoryManager.DEFAULT_CHANNEL_CLOSE_TIMEOUT);
                    s.writePacket(buffer, timeout, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
                        @SuppressWarnings("synthetic-access")
                        @Override
                        public void operationComplete(IoWriteFuture future) {
                            if (future.isWritten()) {
                                if (log.isDebugEnabled()) {
                                    log.debug("close({})[immediately={}] SSH_MSG_CHANNEL_CLOSE written on channel", channel, immediately);
                                }
                                if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseSent)) {
                                    // Waiting for CLOSE message to come back from the remote side
                                } else if (gracefulState.compareAndSet(GracefulState.CloseReceived, GracefulState.Closed)) {
                                    gracefulFuture.setClosed();
                                }
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("close({})[immediately={}] failed to write SSH_MSG_CHANNEL_CLOSE on channel", channel, immediately);
                                }
                                channel.close(true);
                            }
                        }
                    });
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("close({})[immediately={}] {} while writing SSH_MSG_CHANNEL_CLOSE packet on channel: {}",
                                  channel, immediately, e.getClass().getSimpleName(), e.getMessage());
                    }
                    channel.close(true);
                }
            }

            ExecutorService service = getExecutorService();
            if ((service != null) && isShutdownOnExit() && (!service.isShutdown())) {
                Collection<?> running = service.shutdownNow();
                if (log.isDebugEnabled()) {
                    log.debug("close({})[immediately={}] shutdown executor service on close - running count={}",
                              channel, immediately, GenericUtils.size(running));
                }
            }

            return gracefulFuture;
        }
    }

    @Override
    protected void preClose() {
        ChannelListener listener = getChannelListenerProxy();
        try {
            listener.channelClosed(this);
        } catch (RuntimeException t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn(e.getClass().getSimpleName() + " while signal channel " + toString() + " closed: " + e.getMessage(), e);
        } finally {
            // clear the listeners since we are closing the channel (quicker GC)
            this.channelListeners.clear();
        }

        IOException err = IoUtils.closeQuietly(localWindow, remoteWindow);
        if (err != null) {
            if (log.isDebugEnabled()) {
                log.debug("Failed (" + err.getClass().getSimpleName() + ") to pre-close window(s) of " + this + ": " + err.getMessage());
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = err.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable t : suppressed) {
                        log.trace("Suppressed " + t.getClass().getSimpleName() + ") while pre-close window(s) of " + this + ": " + t.getMessage());
                    }
                }
            }
        }

        super.preClose();
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
            Session s = getSession();
            s.writePacket(buffer);
        } else {
            log.debug("writePacket({}) Discarding output packet because channel is being closed", this);
        }
    }

    @Override
    public void handleData(Buffer buffer) throws IOException {
        int len = buffer.getInt();
        if (len < 0 || len > ByteArrayBuffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        if (log.isDebugEnabled()) {
            log.debug("handleData({}) SSH_MSG_CHANNEL_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            log.trace("handleData({}) data: {}", this, BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
        }
        doWriteData(buffer.array(), buffer.rpos(), len);
    }

    @Override
    public void handleExtendedData(Buffer buffer) throws IOException {
        int ex = buffer.getInt();
        // Only accept extended data for stderr
        if (ex != SshConstants.SSH_EXTENDED_DATA_STDERR) {
            if (log.isDebugEnabled()) {
                log.debug("handleExtendedData({}) send SSH_MSG_CHANNEL_FAILURE - non STDERR type: {}", this, ex);
            }
            Session s = getSession();
            Buffer rsp = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE, Integer.SIZE / Byte.SIZE);
            rsp.putInt(getRecipient());
            writePacket(rsp);
            return;
        }
        int len = buffer.getInt();
        if (len < 0 || len > ByteArrayBuffer.MAX_LEN) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        if (log.isDebugEnabled()) {
            log.debug("handleExtendedData({}) SSH_MSG_CHANNEL_EXTENDED_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            log.trace("handleExtendedData({}) extended data: {}", this, BufferUtils.printHex(buffer.array(), buffer.rpos(), len));
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
        if (log.isDebugEnabled()) {
            log.debug("handleEof({}) SSH_MSG_CHANNEL_EOF", this);
        }
        setEofSignalled(true);
        notifyStateChanged();
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        int window = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("handleWindowAdjust({}) SSH_MSG_CHANNEL_WINDOW_ADJUST window={}", this, window);
        }
        remoteWindow.expand(window);
    }

    @Override
    public void handleSuccess() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("handleFhandleSuccessailure({}) SSH_MSG_CHANNEL_SUCCESS", this);
        }
    }

    @Override
    public void handleFailure() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("handleFailure({}) SSH_MSG_CHANNEL_FAILURE", this);
        }
        // TODO: do something to report failed requests?
    }

    protected abstract void doWriteData(byte[] data, int off, int len) throws IOException;

    protected abstract void doWriteExtendedData(byte[] data, int off, int len) throws IOException;

    protected void sendEof() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendEof({}) SSH_MSG_CHANNEL_EOF", this);
        }
        Session s = getSession();
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_EOF, Short.SIZE);
        buffer.putInt(getRecipient());
        writePacket(buffer);
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    protected void configureWindow() {
        localWindow.init(this);
    }

    protected void sendWindowAdjust(int len) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendWindowAdjust({}) SSH_MSG_CHANNEL_WINDOW_ADJUST len={}", this, len);
        }
        Session s = getSession();
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST, Short.SIZE);
        buffer.putInt(getRecipient());
        buffer.putInt(len);
        writePacket(buffer);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + getId() + ", recipient=" + getRecipient() + "]" + "-" + getSession();
    }
}
