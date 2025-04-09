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
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.exception.SshChannelInvalidPacketException;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolver;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolverManager;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.closeable.IoBaseCloseable;
import org.apache.sshd.common.util.closeable.SimpleCloseable;
import org.apache.sshd.common.util.functors.Int2IntFunction;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Provides common client/server channel functionality
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractChannel extends AbstractInnerCloseable implements Channel, ExecutorServiceCarrier {

    /**
     * Default growth factor function used to resize response buffers
     */
    public static final IntUnaryOperator RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.add(Byte.SIZE);

    /**
     * A default {@link PacketValidator} that enforces that the packet size is not greater than the maximum packet size
     * of the channel's local window.
     */
    // Plus 4 because there seems to be some confusion about whether or not the maximum packet size for a channel
    // includes the packet length field itself.
    public static final PacketValidator DEFAULT_PACKET_VALIDATOR = (
            packetSize, maxPacketSize, extendedData) -> packetSize <= maxPacketSize + 4;

    protected enum GracefulState {
        Opened,
        CloseSent,
        CloseReceived,
        Closed
    }

    protected ConnectionService service;

    protected final AtomicBoolean initialized = new AtomicBoolean(false);
    protected final AtomicBoolean eofReceived = new AtomicBoolean(false);

    /**
     * Obsolete and unused; present only for API backwards compatibility. Use {@link #isEofSent()} to determine whether
     * EOF is already sent on this channel, and {@link #sendEof()} to send EOF. The latter will return {@code null} if
     * EOF already was sent.
     *
     * @deprecated since 2.10.1
     */
    @Deprecated
    protected final AtomicBoolean eofSent = new AtomicBoolean(false);
    protected final AtomicBoolean unregisterSignaled = new AtomicBoolean(false);
    protected final AtomicBoolean closeSignaled = new AtomicBoolean(false);
    protected AtomicReference<GracefulState> gracefulState = new AtomicReference<>(GracefulState.Opened);
    protected final DefaultCloseFuture gracefulFuture;
    /**
     * Channel events listener
     */
    protected final Collection<ChannelListener> channelListeners = new CopyOnWriteArraySet<>();
    protected final ChannelListener channelListenerProxy;

    // Our id for this channel
    private long id = -1L;
    // The peer's id for the channel. For an AbstractClientChannel, set when the SSH_MSG_CHANNEL_OPEN_CONFIRMATION is
    // received.
    private long recipient = -1L;
    private Session sessionInstance;
    private CloseableExecutorService executor;
    private final List<RequestHandler<Channel>> requestHandlers = new CopyOnWriteArrayList<>();

    private final CloseableLocalWindow localWindow;
    private final CloseableRemoteWindow remoteWindow;

    private ChannelStreamWriterResolver channelStreamPacketWriterResolver;

    private AtomicReference<IoWriteFuture> eofFuture = new AtomicReference<>();

    private PacketValidator packetValidator = DEFAULT_PACKET_VALIDATOR;

    /**
     * A {@link Map} of sent requests - key = request name, value = timestamp when request was sent.
     */
    private final Map<String, Date> pendingRequests = new ConcurrentHashMap<>();
    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final Map<AttributeRepository.AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();

    protected AbstractChannel(boolean client) {
        this("", client);
    }

    protected AbstractChannel(boolean client, Collection<? extends RequestHandler<Channel>> handlers) {
        this("", client, handlers, null);
    }

    protected AbstractChannel(String discriminator, boolean client) {
        this(discriminator, client, Collections.emptyList(), null);
    }

    protected AbstractChannel(String discriminator, boolean client,
                              Collection<? extends RequestHandler<Channel>> handlers,
                              CloseableExecutorService executorService) {
        super(discriminator);
        gracefulFuture = new DefaultCloseFuture(discriminator, futureLock);
        localWindow = new CloseableLocalWindow(this, client);
        remoteWindow = new CloseableRemoteWindow(this, client);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, channelListeners);
        executor = executorService;
        addRequestHandlers(handlers);
    }

    @Override
    public List<RequestHandler<Channel>> getRequestHandlers() {
        return requestHandlers;
    }

    @Override
    public void addRequestHandler(RequestHandler<Channel> handler) {
        requestHandlers.add(Objects.requireNonNull(handler, "No handler instance"));
    }

    @Override
    public void removeRequestHandler(RequestHandler<Channel> handler) {
        requestHandlers.remove(Objects.requireNonNull(handler, "No handler instance"));
    }

    @Override
    public long getChannelId() {
        return id;
    }

    @Override
    public long getRecipient() {
        return recipient;
    }

    protected void setRecipient(long recipient) {
        if (log.isDebugEnabled()) {
            log.debug("setRecipient({}) recipient={}", this, recipient);
        }
        this.recipient = recipient;
    }

    @Override
    public LocalWindow getLocalWindow() {
        return localWindow;
    }

    @Override
    public RemoteWindow getRemoteWindow() {
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
    public CloseableExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public ChannelStreamWriterResolver getChannelStreamWriterResolver() {
        return channelStreamPacketWriterResolver;
    }

    @Override
    public void setChannelStreamWriterResolver(ChannelStreamWriterResolver resolver) {
        channelStreamPacketWriterResolver = resolver;
    }

    @Override
    public ChannelStreamWriterResolver resolveChannelStreamWriterResolver() {
        ChannelStreamWriterResolver resolver = getChannelStreamWriterResolver();
        if (resolver != null) {
            return resolver;
        }

        ChannelStreamWriterResolverManager manager = getSession();
        return manager.resolveChannelStreamWriterResolver();
    }

    /**
     * Add a channel request to the tracked pending ones if reply is expected
     *
     * @param  request                  The request type
     * @param  wantReply                {@code true} if reply is expected
     * @return                          The allocated {@link Date} timestamp - {@code null} if no reply is expected (in
     *                                  which case the request is not tracked)
     * @throws IllegalArgumentException If the request is already being tracked
     * @see                             #removePendingRequest(String)
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
     * @param  request The request type
     * @return         The allocated {@link Date} timestamp - {@code null} if the specified request type is not being
     *                 tracked or has not been added to the tracked ones to begin with
     * @see            #addPendingRequest(String, boolean)
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
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleChannelRequest({}) SSH_MSG_CHANNEL_REQUEST {} wantReply={}", this, req, wantReply);
        }

        Collection<? extends RequestHandler<Channel>> handlers = getRequestHandlers();
        boolean traceEnabled = log.isTraceEnabled();
        for (RequestHandler<Channel> handler : handlers) {
            RequestHandler.Result result;
            try {
                result = handler.process(this, req, wantReply, buffer);
            } catch (Throwable e) {
                debug("handleRequest({}) {} while {}#process({})[want-reply={}]: {}", this,
                        e.getClass().getSimpleName(), handler.getClass().getSimpleName(), req, wantReply,
                        e.getMessage(), e);
                result = RequestHandler.Result.ReplyFailure;
            }

            // if Unsupported then check the next handler in line
            if (RequestHandler.Result.Unsupported.equals(result)) {
                if (traceEnabled) {
                    log.trace("handleRequest({})[{}#process({})[want-reply={}]]: {}", this,
                            handler.getClass().getSimpleName(), req, wantReply, result);
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
     * @param  req         The request type
     * @param  wantReply   Whether reply is requested
     * @param  buffer      The {@link Buffer} containing extra request-specific data
     * @throws IOException If failed to send the response (if needed)
     * @see                #handleInternalRequest(String, boolean, Buffer)
     */
    protected void handleUnknownChannelRequest(String req, boolean wantReply, Buffer buffer) throws IOException {
        RequestHandler.Result r = handleInternalRequest(req, wantReply, buffer);
        if ((r == null) || RequestHandler.Result.Unsupported.equals(r)) {
            log.warn("handleUnknownChannelRequest({}) Unknown channel request: {}[want-reply={}]", this, req,
                    wantReply);
            sendResponse(buffer, req, RequestHandler.Result.Unsupported, wantReply);
        } else {
            sendResponse(buffer, req, r, wantReply);
        }
    }

    /**
     * Called by {@link #handleUnknownChannelRequest(String, boolean, Buffer)} in order to allow channel request
     * handling if none of the registered handlers processed the request - last chance.
     *
     * @param  req         The request type
     * @param  wantReply   Whether reply is requested
     * @param  buffer      The {@link Buffer} containing extra request-specific data
     * @return             The handling result - if {@code null} or {@code Unsupported} and reply is required then a
     *                     failure message will be sent
     * @throws IOException If failed to process the request internally
     */
    protected RequestHandler.Result handleInternalRequest(String req, boolean wantReply, Buffer buffer)
            throws IOException {
        if (req.startsWith("keepalive@") || req.startsWith("keep-alive@")) {
            if (log.isDebugEnabled()) {
                log.debug("handleInternalRequest({})[want-reply={}] received keep-alive: {}", this, wantReply, req);
            }
            if (req.equals("keepalive@openssh.com")) {
                return RequestHandler.Result.ReplyFailure;
            }
            return RequestHandler.Result.ReplySuccess;
        }
        if (log.isDebugEnabled()) {
            log.debug("handleInternalRequest({})[want-reply={}] unknown type: {}", this, wantReply, req);
        }
        return RequestHandler.Result.Unsupported;
    }

    protected IoWriteFuture sendResponse(Buffer buffer, String req, RequestHandler.Result result, boolean wantReply)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendResponse({}) request={} result={}, want-reply={}", this, req, result, wantReply);
        }

        if (RequestHandler.Result.Replied.equals(result) || (!wantReply)) {
            return AbstractIoWriteFuture.fulfilled(req, Boolean.TRUE);
        }

        byte cmd = RequestHandler.Result.ReplySuccess.equals(result)
                ? SshConstants.SSH_MSG_CHANNEL_SUCCESS
                : SshConstants.SSH_MSG_CHANNEL_FAILURE;
        Session session = getSession();
        Buffer rsp = session.createBuffer(cmd, Integer.BYTES);
        rsp.putUInt(recipient);
        return session.writePacket(rsp);
    }

    @Override
    public void init(ConnectionService service, Session session, long id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("init() service={} session={} id={}", service, session, id);
        }
        this.service = service;
        this.sessionInstance = session;
        this.id = id;

        signalChannelInitialized();
        configureWindow();
        ((AbstractSession) session).addKexListener(kexStarted -> {
            try {
                localWindow.preventAdjustments(kexStarted);
            } catch (IOException e) {
                getSession().exceptionCaught(e);
            }
            remoteWindow.closeDuringKex(kexStarted);
            if (kexStarted) {
                if (log.isDebugEnabled()) {
                    log.debug("{} {} KEX starts: closing window", getSession(), AbstractChannel.this);
                }
            } else if (!isClosed()) {
                if (log.isDebugEnabled()) {
                    log.debug("{} {} KEX ends: reopening window", getSession(), AbstractChannel.this);
                }
                try {
                    Buffer b = new ByteArrayBuffer(4);
                    b.putUInt(0);
                    handleWindowAdjust(b);
                } catch (IOException e) {
                    getSession().exceptionCaught(e);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("{} {} KEX ends: channel closed", getSession(), AbstractChannel.this);
            }
        });
        initialized.set(true);
    }

    protected void signalChannelInitialized() throws IOException {
        try {
            invokeChannelSignaller(l -> l.channelInitialized(this));

            notifyStateChanged("init");
        } catch (Throwable err) {
            Throwable e = ExceptionUtils.peelException(err);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new IOException("Failed (" + e.getClass().getSimpleName() + ") to notify channel " + this
                                      + " initialization: " + e.getMessage(),
                        e);
            }
        }
    }

    protected void signalChannelOpenSuccess() {
        invokeChannelSignaller(l -> l.channelOpenSuccess(this));
    }

    @Override
    public boolean isInitialized() {
        return initialized.get();
    }

    @Override
    public void handleChannelRegistrationResult(
            ConnectionService service, Session session, long channelId,
            boolean registered) {
        notifyStateChanged("registered=" + registered);
        if (registered) {
            return;
        }

        RuntimeException reason = new IllegalStateException(
                "Channel id=" + channelId + " not registered because session is being closed: " + this);
        signalChannelClosed(reason);
        throw reason;
    }

    protected void signalChannelOpenFailure(Throwable reason) {
        try {
            invokeChannelSignaller(l -> l.channelOpenFailure(this, reason));
        } catch (Throwable err) {
            Throwable ignored = ExceptionUtils.peelException(err);
            debug("signalChannelOpenFailure({}) failed ({}) to inform listener of open failure={}: {}", this,
                    ignored.getClass().getSimpleName(), reason.getClass().getSimpleName(), ignored.getMessage(),
                    ignored);
        }
    }

    protected void notifyStateChanged(String hint) {
        try {
            invokeChannelSignaller(l -> l.channelStateChanged(this, hint));
        } catch (Throwable err) {
            Throwable e = ExceptionUtils.peelException(err);
            debug("notifyStateChanged({})[{}] {} while signal channel state change: {}", this, hint,
                    e.getClass().getSimpleName(), e.getMessage(), e);
        } finally {
            synchronized (futureLock) {
                futureLock.notifyAll();
            }
        }
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ChannelListener.validateListener(listener);
        // avoid race conditions on notifications while channel is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while channel is closing", this, listener);
            return;
        }

        if (this.channelListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addChannelListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addChannelListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removeChannelListener(ChannelListener listener) {
        if (listener == null) {
            return;
        }

        ChannelListener.validateListener(listener);
        if (this.channelListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removeChannelListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removeChannelListener({})[{}] not registered", this, listener);
            }
        }
    }

    @Override
    public ChannelListener getChannelListenerProxy() {
        return channelListenerProxy;
    }

    @Override
    public void handleClose() throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleClose({}) SSH_MSG_CHANNEL_CLOSE", this);
        }

        try {
            IoWriteFuture eofPrevention = AbstractIoWriteFuture.fulfilled(getChannelId(), futureLock);
            if (eofFuture.compareAndSet(null, eofPrevention)) {
                if (debugEnabled) {
                    log.debug("handleClose({}) prevent sending EOF", this);
                }
                eofSent.set(true); // Just for API backwards compatibility
            }

            if (gracefulState.compareAndSet(GracefulState.Opened, GracefulState.CloseReceived)) {
                close(false);
            } else if (gracefulState.compareAndSet(GracefulState.CloseSent, GracefulState.Closed)) {
                gracefulFuture.setClosed();
            }
        } finally {
            notifyStateChanged("SSH_MSG_CHANNEL_CLOSE");
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        Closeable closer = builder() //
                .close(new SimpleCloseable(this, futureLock) {

                    @Override
                    protected void doClose(boolean immediately) {
                        IoWriteFuture eofWritten = eofFuture.get();
                        if (immediately || eofWritten == null) {
                            super.doClose(immediately);
                        } else {
                            eofWritten.addListener(f -> super.doClose(immediately));
                        }
                    }
                }) //
                .sequential(new GracefulChannelCloseable(), getExecutorService()) //
                .run(toString(), () -> {
                    if (service != null) {
                        service.unregisterChannel(AbstractChannel.this);
                    }
                }) //
                .build();
        closer.addCloseFutureListener(future -> clearAttributes());
        return closer;
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
        public CloseFuture close(boolean immediately) {
            Channel channel = AbstractChannel.this;
            boolean debugEnabled = log.isDebugEnabled();
            if (debugEnabled) {
                log.debug("close({})[immediately={}] processing", channel, immediately);
            }

            setClosing(true);
            long recipient = getRecipient();
            if (immediately || recipient < 0) {
                // Recipient < 0: an AbstractClientChannel never got the SSH_MSG_OPEN_CONFIRMATION -- no point in
                // sending a SSH_MSG_CHANNEL_CLOSE
                gracefulFuture.setClosed();
            } else if (!gracefulFuture.isClosed()) {
                if (debugEnabled) {
                    log.debug("close({})[immediately={}] send SSH_MSG_CHANNEL_CLOSE", channel, immediately);
                }

                Session s = getSession();
                Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_CLOSE, Short.SIZE);
                buffer.putUInt(recipient);

                try {
                    Duration timeout = CoreModuleProperties.CHANNEL_CLOSE_TIMEOUT.getRequired(channel);
                    s.writePacket(buffer, timeout).addListener(future -> {
                        if (future.isWritten()) {
                            handleClosePacketWritten(channel, immediately);
                        } else {
                            handleClosePacketWriteFailure(channel, immediately, future.getException());
                        }
                    });
                } catch (IOException e) {
                    debug("close({})[immediately={}] {} while writing SSH_MSG_CHANNEL_CLOSE packet on channel: {}",
                            channel, immediately, e.getClass().getSimpleName(), e.getMessage(), e);
                    channel.close(true);
                }
            }

            CloseableExecutorService service = getExecutorService();
            if ((service != null) && (!service.isShutdown())) {
                Collection<?> running = service.shutdownNow();
                if (debugEnabled) {
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
                return;
            } else if (gracefulState.compareAndSet(GracefulState.CloseReceived, GracefulState.Closed)) {
                gracefulFuture.setClosed();
            }
        }

        protected void handleClosePacketWriteFailure(Channel channel, boolean immediately, Throwable t) {
            debug("handleClosePacketWriteFailure({})[immediately={}] failed ({}) to write SSH_MSG_CHANNEL_CLOSE on channel: {}",
                    this, immediately, t.getClass().getSimpleName(), t.getMessage(), t);
            channel.close(true);
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + "[" + AbstractChannel.this + "]";
        }
    }

    @Override
    protected void preClose() {
        if (!isEofSent()) {
            log.debug("close({}) no EOF sent", this);
        }

        try {
            signalChannelClosed(null);
        } finally {
            // clear the listeners since we are closing the channel (quicker GC)
            this.channelListeners.clear();
        }

        IOException err = IoUtils.closeQuietly(getLocalWindow(), getRemoteWindow());
        if (err != null) {
            debug("Failed ({}) to pre-close window(s) of {}: {}", err.getClass().getSimpleName(), this,
                    err.getMessage(), err);
        }

        super.preClose();
    }

    @Override
    public void handleChannelUnregistration(ConnectionService service) {
        if (!unregisterSignaled.getAndSet(true)) {
            if (log.isTraceEnabled()) {
                log.trace("handleChannelUnregistration({}) via service={}", this, service);
            }
        }

        notifyStateChanged("unregistered");
    }

    public void signalChannelClosed(Throwable reason) {
        String event = (reason == null) ? "signalChannelClosed" : reason.getClass().getSimpleName();
        try {
            if (!closeSignaled.getAndSet(true)) {
                if (log.isTraceEnabled()) {
                    log.trace("signalChannelClosed({})[{}]", this, event);
                }
            }

            invokeChannelSignaller(l -> l.channelClosed(this, reason));
        } catch (Throwable err) {
            Throwable e = ExceptionUtils.peelException(err);
            debug("signalChannelClosed({}) {} while signal channel closed: {}", this, e.getClass().getSimpleName(),
                    e.getMessage(), e);
        } finally {
            notifyStateChanged(event);
        }
    }

    protected void invokeChannelSignaller(Consumer<ChannelListener> invoker) {
        Session session = getSession();
        FactoryManager manager = (session == null) ? null : session.getFactoryManager();
        ChannelListener[] listeners = {
                (manager == null) ? null : manager.getChannelListenerProxy(),
                (session == null) ? null : session.getChannelListenerProxy(), getChannelListenerProxy() };

        Throwable err = null;
        for (ChannelListener l : listeners) {
            if (l == null) {
                continue;
            }
            try {
                invoker.accept(l);
            } catch (RuntimeException e) {
                err = ExceptionUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            ExceptionUtils.rethrowAsRuntimeException(err);
        }
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        if (mayWrite()) {
            Session s = getSession();
            return s.writePacket(buffer);
        }

        if (log.isDebugEnabled()) {
            log.debug("writePacket({}) Discarding output packet because channel state={}", this, state);
        }
        return AbstractIoWriteFuture.fulfilled(toString(), new EOFException("Channel is being closed"));
    }

    protected boolean mayWrite() {
        return !isClosing();
    }

    @Override
    public void handleData(Buffer buffer) throws IOException {
        long len = validateIncomingDataSize(SshConstants.SSH_MSG_CHANNEL_DATA, buffer.getUInt());
        if (log.isDebugEnabled()) {
            log.debug("handleData({}) SSH_MSG_CHANNEL_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            BufferUtils.dumpHex(getSimplifiedLogger(), BufferUtils.DEFAULT_HEXDUMP_LEVEL, "handleData(" + this + ")",
                    this, BufferUtils.DEFAULT_HEX_SEPARATOR, buffer.array(), buffer.rpos(), (int) len);
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
            Buffer rsp = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE, Integer.BYTES);
            rsp.putUInt(getRecipient());
            writePacket(rsp);
            return;
        }

        long len = validateIncomingDataSize(SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA, buffer.getUInt());
        if (log.isDebugEnabled()) {
            log.debug("handleExtendedData({}) SSH_MSG_CHANNEL_EXTENDED_DATA len={}", this, len);
        }
        if (log.isTraceEnabled()) {
            BufferUtils.dumpHex(getSimplifiedLogger(), BufferUtils.DEFAULT_HEXDUMP_LEVEL,
                    "handleExtendedData(" + this + ")", this, BufferUtils.DEFAULT_HEX_SEPARATOR, buffer.array(),
                    buffer.rpos(), (int) len);
        }
        if (isEofSignalled()) {
            // TODO consider throwing an exception
            log.warn("handleExtendedData({}) extra {} bytes sent after EOF", this, len);
        }
        doWriteExtendedData(buffer.array(), buffer.rpos(), len);
    }

    protected long validateIncomingDataSize(
            int cmd, long len /* actually a uint32 */)
            throws IOException {
        if (!BufferUtils.isValidUint32Value(len)) {
            throw new IllegalArgumentException(
                    "Non UINT32 length (" + len + ") for command=" + SshConstants.getCommandMessageName(cmd));
        }

        /*
         * According to RFC 4254 section 5.1
         *
         * The 'maximum packet size' specifies the maximum size of an individual
         * data packet that can be sent to the sender
         *
         * The local window reflects our preference - i.e., how much our peer
         * should send at most
         */
        LocalWindow wLocal = getLocalWindow();
        long maxLocalSize = wLocal.getPacketSize();

        PacketValidator validator = getPacketValidator();
        if (!validator.isValid(len, maxLocalSize, cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA)) {
            throw new SshChannelInvalidPacketException(getChannelId(), "Bad length (" + len + ") " + " for cmd="
                                                                       + SshConstants.getCommandMessageName(cmd)
                                                                       + " - max. allowed=" + maxLocalSize);
        }

        wLocal.consume(len);

        return len;
    }

    /**
     * Retrieves the currently set {@link PacketValidator}.
     *
     * @return the validator, never {@code null}
     */
    public PacketValidator getPacketValidator() {
        return packetValidator;
    }

    /**
     * Sets a {@link PacketValidator}.
     *
     * @param validator the validator to set, if {@code null} the {@link #DEFAULT_PACKET_VALIDATOR} is set
     */
    public void setPacketValidator(PacketValidator validator) {
        if (validator == null) {
            packetValidator = DEFAULT_PACKET_VALIDATOR;
        } else {
            packetValidator = validator;
        }
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
        long window = buffer.getUInt();
        if (log.isDebugEnabled()) {
            log.debug("handleWindowAdjust({}) SSH_MSG_CHANNEL_WINDOW_ADJUST window={}", this, window);
        }

        RemoteWindow wRemote = getRemoteWindow();
        wRemote.expand(window);
        notifyStateChanged("SSH_MSG_CHANNEL_WINDOW_ADJUST");
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

    protected abstract void doWriteData(byte[] data, int off, long len) throws IOException;

    protected abstract void doWriteExtendedData(byte[] data, int off, long len) throws IOException;

    /**
     * Sends {@code SSH_MSG_CHANNEL_EOF} provided not already sent and current channel state allows it.
     *
     * @return             The {@link IoWriteFuture} of the sent packet - {@code null} if message not sent due to
     *                     channel state (or already sent)
     * @throws IOException If failed to send the packet
     */
    protected IoWriteFuture sendEof() throws IOException {
        State channelState = state.get();
        // OK to send EOF if channel is open or being closed gracefully
        if ((channelState != State.Opened) && (channelState != State.Graceful)) {
            if (log.isDebugEnabled()) {
                log.debug("sendEof({}) already closing or closed - state={}", this, state);
            }
            return null;
        }

        AbstractIoWriteFuture eofWritten = new AbstractIoWriteFuture(getChannelId(), futureLock) {
            // Nothin extra
        };
        if (!eofFuture.compareAndSet(null, eofWritten)) {
            if (log.isDebugEnabled()) {
                log.debug("sendEof({}) already sent (state={})", this, channelState);
            }
            return null;
        }
        eofSent.set(true);// Just for API backwards compatibility

        if (log.isDebugEnabled()) {
            log.debug("sendEof({}) SSH_MSG_CHANNEL_EOF (state={})", this, channelState);
        }

        IoWriteFuture inner = null;
        try {
            Session s = getSession();
            Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_EOF, Short.SIZE);
            buffer.putUInt(getRecipient());
            /*
             * The default "writePacket" does not send packets if state is not open so we need to bypass it.
             */
            inner = s.writePacket(buffer);
        } catch (IOException e) {
            // Marks the future as done, so that later channel closing will not be blocked.
            eofWritten.setValue(e);
            throw e;
        } catch (RuntimeException e) {
            eofWritten.setValue(e);
            throw new IOException(e.getMessage(), e);
        }
        return inner.addListener(f -> {
            Throwable error = f.getException();
            eofWritten.setValue(error != null ? error : Boolean.TRUE);
        });
    }

    public boolean isEofSent() {
        return eofFuture.get() != null;
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    public int getAttributesCount() {
        return attributes.size();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.get(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public Collection<AttributeKey<?>> attributeKeys() {
        return attributes.isEmpty() ? Collections.emptySet() : new HashSet<>(attributes.keySet());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public <T> T computeAttributeIfAbsent(
            AttributeRepository.AttributeKey<T> key,
            Function<? super AttributeRepository.AttributeKey<T>, ? extends T> resolver) {
        return (T) attributes.computeIfAbsent(Objects.requireNonNull(key, "No key"), (Function) resolver);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeRepository.AttributeKey<T> key, T value) {
        return (T) attributes.put(Objects.requireNonNull(key, "No key"), Objects.requireNonNull(value, "No value"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T removeAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.remove(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public void clearAttributes() {
        attributes.clear();
    }

    protected void configureWindow() {
        localWindow.init(this);
    }

    protected void sendWindowAdjust(long len) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendWindowAdjust({}) SSH_MSG_CHANNEL_WINDOW_ADJUST len={}", this, len);
        }
        Session s = getSession();
        Buffer buffer = s.createBuffer(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST, Short.SIZE);
        buffer.putUInt(getRecipient());
        buffer.putUInt(len);
        writePacket(buffer);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + getChannelId() + ", recipient=" + getRecipient() + "]" + "-"
               + getSession();
    }

    /**
     * A {@link PacketValidator} can validate packet lengths. Used for {@link SshConstants#SSH_MSG_CHANNEL_DATA} and
     * {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} messages.
     */
    @FunctionalInterface
    public interface PacketValidator {

        /**
         * Tells whether a packet received of {@code len} bytes is valid given a channel's {@code maximumPacketSize}.
         *
         * @param  packetSize        as read from the SSH packet
         * @param  maximumPacketSize from the channel's local window
         * @param  extendedData      whether it's a {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} packet
         * @return                   {@code true} if the packet is to be considered valid.
         */
        boolean isValid(long packetSize, long maximumPacketSize, boolean extendedData);

    }

    private class CloseableRemoteWindow extends RemoteWindow {

        private long inc;

        private boolean zeroed;

        private long initialSize;

        CloseableRemoteWindow(Channel channel, boolean isClient) {
            super(channel, isClient);
        }

        void closeDuringKex(boolean kexStarted) {
            synchronized (lock) {
                zeroed = kexStarted;
                if (kexStarted) {
                    initialSize = getSize();
                    inc = 0;
                    updateSize(0);
                } else {
                    long value = Math.min(initialSize + inc, BufferUtils.MAX_UINT32_VALUE);
                    inc = 0;
                    long sizeNow = getSize();
                    if (sizeNow > value) {
                        value = sizeNow;
                    }
                    updateSize(value);
                }
            }
        }

        @Override
        public void expand(long increment) {
            BufferUtils.validateUint32Value(increment, "Invalid window expansion size: %d");
            synchronized (lock) {
                if (zeroed) {
                    inc += increment;
                } else {
                    super.expand(increment);
                }
            }
        }

    }

    private class CloseableLocalWindow extends LocalWindow {

        private boolean noAdjust;

        private long inc;

        CloseableLocalWindow(AbstractChannel channel, boolean isClient) {
            super(channel, isClient);
        }

        void preventAdjustments(boolean prevent) throws IOException {
            long doRelease = 0;
            synchronized (lock) {
                noAdjust = prevent;
                if (!prevent) {
                    doRelease = inc;
                }
                inc = 0;
            }
            if (doRelease > 0) {
                release(doRelease);
            }
        }

        @Override
        public void release(long len) throws IOException {
            BufferUtils.validateUint32Value(len, "Invalid window expansion size: %d");
            synchronized (lock) {
                if (noAdjust) {
                    inc += len;
                } else {
                    super.release(len);
                }
            }
        }
    }
}
