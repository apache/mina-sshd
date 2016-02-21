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

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;

/**
 * Provides common client/server channel functionality
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

    protected ConnectionService service;
    protected final AtomicBoolean initialized = new AtomicBoolean(false);
    protected final AtomicBoolean eofReceived = new AtomicBoolean(false);
    protected final AtomicBoolean eofSent = new AtomicBoolean(false);
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
    private Session sessionInstance;
    private ExecutorService executor;
    private boolean shutdownExecutor;

    private final Window localWindow;
    private final Window remoteWindow;
    /**
     * A {@link Map} of sent requests - key = request name, value = timestamp when
     * request was sent.
     */
    private final Map<String, Date> pendingRequests = new ConcurrentHashMap<>();
    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final Map<AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();

    protected AbstractChannel(boolean client) {
        this("", client);
    }

    protected AbstractChannel(boolean client, Collection<? extends RequestHandler<Channel>> handlers) {
        this("", client, handlers);
    }

    protected AbstractChannel(String discriminator, boolean client) {
        this(discriminator, client, Collections.<RequestHandler<Channel>>emptyList());
    }

    protected AbstractChannel(String discriminator, boolean client, Collection<? extends RequestHandler<Channel>> handlers) {
        super(discriminator);
        localWindow = new Window(this, null, client, true);
        remoteWindow = new Window(this, null, client, false);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, getClass().getClassLoader(), channelListeners);
        addRequestHandlers(handlers);
    }

    public void addRequestHandlers(Collection<? extends RequestHandler<Channel>> handlers) {
        if (GenericUtils.size(handlers) > 0) {
            for (RequestHandler<Channel> h : handlers) {
                addRequestHandler(h);
            }
        }
    }

    public void addRequestHandler(RequestHandler<Channel> handler) {
        handlers.add(ValidateUtils.checkNotNull(handler, "No handler instance"));
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
        return sessionInstance;
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
            } catch (Throwable e) {
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

    protected IoWriteFuture sendResponse(Buffer buffer, String req, RequestHandler.Result result, boolean wantReply) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) request={} result={}, want-reply={}", this, req, result, wantReply);
        }

        if (RequestHandler.Result.Replied.equals(result) || (!wantReply)) {
            return new AbstractIoWriteFuture(null) {
                {
                    setValue(Boolean.TRUE);
                }
            };
        }

        byte cmd = RequestHandler.Result.ReplySuccess.equals(result)
                 ? SshConstants.SSH_MSG_CHANNEL_SUCCESS
                 : SshConstants.SSH_MSG_CHANNEL_FAILURE;
        Session session = getSession();
        Buffer rsp = session.createBuffer(cmd, Integer.SIZE / Byte.SIZE);
        rsp.putInt(recipient);
        return session.writePacket(rsp);
    }

    @Override
    public void init(ConnectionService service, Session session, int id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("init() service={} session={} id={}", service, session, id);
        }
        this.service = service;
        this.sessionInstance = session;
        this.id = id;

        ChannelListener listener = session.getChannelListenerProxy();
        try {
            listener.channelInitialized(this);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new IOException("Failed (" + e.getClass().getSimpleName() + ") to notify channel " + this + " initialization: " + e.getMessage(), e);
            }
        }
        // delegate the rest of the notifications to the channel
        addChannelListener(listener);
        configureWindow();
        initialized.set(true);
    }

    @Override
    public boolean isInitialized() {
        return initialized.get();
    }

    protected void notifyStateChanged(String hint) {
        ChannelListener listener = getChannelListenerProxy();
        try {
            listener.channelStateChanged(this, hint);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn("notifyStateChanged({})[{}] {} while signal channel state change: {}",
                     this, hint, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("notifyStateChanged(" + this + ")[" + hint + "] channel state signalling failure details", e);
            }
        }

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
            log.debug("handleClose({}) SSH_MSG_CHANNEL_CLOSE", this);
        }

        if (!eofSent.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("handleClose({}) prevent sending EOF", this);
            }
        }

        if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseReceived)) {
            close(false);
        } else if (gracefulState.compareAndSet(GracefulState.CloseSent, GracefulState.Closed)) {
            gracefulFuture.setClosed();
        }
    }

    @Override
    public CloseFuture close(boolean immediately) {
        if (!eofSent.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("close({}) prevent sending EOF", this);
            }
        }

        return super.close(immediately);
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
        public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            gracefulFuture.addListener(listener);
        }

        @Override
        public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
            gracefulFuture.removeListener(listener);
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
                log.debug("close({})[immediately={}] processing", channel, immediately);
            }

            setClosing(true);
            if (immediately) {
                gracefulFuture.setClosed();
            } else if (!gracefulFuture.isClosed()) {
                if (log.isDebugEnabled()) {
                    log.debug("close({})[immediately={}] send SSH_MSG_CHANNEL_CLOSE", channel, immediately);
                }

                Session s = getSession();
                Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_CLOSE, Short.SIZE);
                buffer.putInt(getRecipient());

                try {
                    long timeout = PropertyResolverUtils.getLongProperty(channel, FactoryManager.CHANNEL_CLOSE_TIMEOUT, FactoryManager.DEFAULT_CHANNEL_CLOSE_TIMEOUT);
                    s.writePacket(buffer, timeout, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
                        @Override
                        public void operationComplete(IoWriteFuture future) {
                            if (future.isWritten()) {
                                handleClosePacketWritten(channel, immediately);
                            } else {
                                handleClosePacketWriteFailure(channel, immediately, future.getException());
                            }
                        }
                    });
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("close({})[immediately={}] {} while writing SSH_MSG_CHANNEL_CLOSE packet on channel: {}",
                                  channel, immediately, e.getClass().getSimpleName(), e.getMessage());
                    }

                    if (log.isTraceEnabled()) {
                        log.trace("close(" + channel + ")[immediately=" + immediately + "] packet write failure details", e);
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

        protected void handleClosePacketWritten(Channel channel, boolean immediately) {
            if (log.isDebugEnabled()) {
                log.debug("handleClosePacketWritten({})[immediately={}] SSH_MSG_CHANNEL_CLOSE written on channel",
                          channel, immediately);
            }

            if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseSent)) {
                // Waiting for CLOSE message to come back from the remote side
            } else if (gracefulState.compareAndSet(GracefulState.CloseReceived, GracefulState.Closed)) {
                gracefulFuture.setClosed();
            }
        }

        protected void handleClosePacketWriteFailure(Channel channel, boolean immediately, Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("handleClosePacketWriteFailure({})[immediately={}] failed ({}) to write SSH_MSG_CHANNEL_CLOSE on channel: {}",
                          this, immediately, t.getClass().getSimpleName(), t.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("handleClosePacketWriteFailure(" + channel + ") SSH_MSG_CHANNEL_CLOSE failure details", t);
            }
            channel.close(true);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + "[" + AbstractChannel.this + "]";
        }
    }

    @Override
    protected void preClose() {
        ChannelListener listener = getChannelListenerProxy();
        try {
            listener.channelClosed(this, null);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn("preClose({}) {} while signal channel closed: {}", this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("preClose(" + this + ") channel closed signalling failure details", e);
            }
            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("preClose(" + this + ") suppressed closed channel signalling failure", s);
                    }
                }
            }
        } finally {
            // clear the listeners since we are closing the channel (quicker GC)
            this.channelListeners.clear();
        }

        IOException err = IoUtils.closeQuietly(getLocalWindow(), getRemoteWindow());
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

    protected IoWriteFuture writePacket(Buffer buffer) throws IOException {
        if (!isClosing()) {
            Session s = getSession();
            return s.writePacket(buffer);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("writePacket({}) Discarding output packet because channel is being closed", this);
            }
            return new AbstractIoWriteFuture(null) {
                {
                    setValue(new EOFException("Channel is being closed"));
                }
            };
        }
    }

    @Override
    public void handleData(Buffer buffer) throws IOException {
        int len = validateIncomingDataSize(SshConstants.SSH_MSG_CHANNEL_DATA, buffer.getInt());
        if (log.isDebugEnabled()) {
            log.debug("handleData({}) SSH_MSG_CHANNEL_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            BufferUtils.dumpHex(getSimplifiedLogger(), BufferUtils.DEFAULT_HEXDUMP_LEVEL, "handleData(" + this + ")",
                    this, BufferUtils.DEFAULT_HEX_SEPARATOR, buffer.array(), buffer.rpos(), len);
        }
        if (isEofSignalled()) {
            // TODO consider throwing an exception
            log.warn("handleData({}) extra {} bytes sent after EOF", this, len);
        }
        doWriteData(buffer.array(), buffer.rpos(), len);
    }

    @Override
    public void handleExtendedData(Buffer buffer) throws IOException {
        int ex = buffer.getInt();
        // Only accept extended data for stderr
        if (ex != SshConstants.SSH_EXTENDED_DATA_STDERR) {
            if (log.isDebugEnabled()) {
                log.debug("handleExtendedData({}) SSH_MSG_CHANNEL_FAILURE - non STDERR type: {}", this, ex);
            }
            Session s = getSession();
            Buffer rsp = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE, Integer.SIZE / Byte.SIZE);
            rsp.putInt(getRecipient());
            writePacket(rsp);
            return;
        }

        int len = validateIncomingDataSize(SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA, buffer.getInt());
        if (log.isDebugEnabled()) {
            log.debug("handleExtendedData({}) SSH_MSG_CHANNEL_EXTENDED_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            BufferUtils.dumpHex(getSimplifiedLogger(), BufferUtils.DEFAULT_HEXDUMP_LEVEL, "handleExtendedData(" + this + ")",
                    this, BufferUtils.DEFAULT_HEX_SEPARATOR, buffer.array(), buffer.rpos(), len);
        }
        if (isEofSignalled()) {
            // TODO consider throwing an exception
            log.warn("handleExtendedData({}) extra {} bytes sent after EOF", this, len);
        }
        doWriteExtendedData(buffer.array(), buffer.rpos(), len);
    }

    protected int validateIncomingDataSize(int cmd, int len) {
        /*
         * According to RFC 4254 section 5.1
         *
         *      The 'maximum packet size' specifies the maximum size of an
         *      individual data packet that can be sent to the sender
         *
         * The local window reflects our preference - i.e., how much our peer
         * should send at most
         */
        Window wLocal = getLocalWindow();
        int maxLocalSize = wLocal.getPacketSize();

        /*
         * The reason for the +4 is that there seems to be some confusion whether
         * the max. packet size includes the length field or not
         */
        if ((len < 0) || (len > (maxLocalSize + 4))) {
            throw new IllegalStateException("Bad length (" + len + ") "
                    + " for cmd=" + SshConstants.getCommandMessageName(cmd)
                    + " - max. allowed=" + maxLocalSize);
        }

        return len;
    }

    @Override
    public void handleEof() throws IOException {
        if (eofReceived.getAndSet(true)) {
            // TODO consider throwing an exception
            log.warn("handleEof({}) already signalled", this);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("handleEof({}) SSH_MSG_CHANNEL_EOF", this);
            }
        }
        notifyStateChanged("SSH_MSG_CHANNEL_EOF");
    }

    @Override
    public boolean isEofSignalled() {
        return eofReceived.get();
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        int window = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("handleWindowAdjust({}) SSH_MSG_CHANNEL_WINDOW_ADJUST window={}", this, window);
        }

        Window wRemote = getRemoteWindow();
        wRemote.expand(window);
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
        if (eofSent.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("sendEof({}) already sent", this);
            }
            return;
        }

        if (isClosing()) {
            if (log.isDebugEnabled()) {
                log.debug("sendEof({}) already closing or closed", this);
            }
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("sendEof({}) SSH_MSG_CHANNEL_EOF", this);
        }

        Session s = getSession();
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_EOF, Short.SIZE);
        buffer.putInt(getRecipient());
        writePacket(buffer);
    }

    public boolean isEofSent() {
        return eofSent.get();
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeKey<T> key) {
        return (T) attributes.get(ValidateUtils.checkNotNull(key, "No key"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeKey<T> key, T value) {
        return (T) attributes.put(
                ValidateUtils.checkNotNull(key, "No key"),
                ValidateUtils.checkNotNull(value, "No value"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T removeAttribute(AttributeKey<T> key) {
        return (T) attributes.remove(ValidateUtils.checkNotNull(key, "No key"));
    }

    @Override
    public <T> T resolveAttribute(AttributeKey<T> key) {
        return AttributeStore.Utils.resolveAttribute(this, key);
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
