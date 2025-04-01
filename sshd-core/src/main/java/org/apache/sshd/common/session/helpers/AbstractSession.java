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
package org.apache.sshd.common.session.helpers;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongConsumer;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.compression.CompressionInformation;
import org.apache.sshd.common.filter.BufferInputHandler;
import org.apache.sshd.common.filter.DefaultFilterChain;
import org.apache.sshd.common.filter.FilterChain;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.GlobalRequestFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.global.GlobalRequestException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.kex.extension.KexExtensions;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.filters.CompressionFilter;
import org.apache.sshd.common.session.filters.CryptFilter;
import org.apache.sshd.common.session.filters.DelayKexInitFilter;
import org.apache.sshd.common.session.filters.IdentFilter;
import org.apache.sshd.common.session.filters.InjectIgnoreFilter;
import org.apache.sshd.common.session.filters.SshIdentHandler;
import org.apache.sshd.common.session.filters.kex.KexFilter;
import org.apache.sshd.common.session.filters.kex.KexListener;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * <P>
 * The AbstractSession handles all the basic SSH protocol such as key exchange, authentication, encoding and decoding.
 * Both server side and client side sessions should inherit from this abstract class. Some basic packet processing
 * methods are defined but the actual call to these methods should be done from the {@link #handleMessage(Buffer)}
 * method, which is dependent on the state and side of this session.
 * </P>
 *
 * TODO: if there is any very big packet, decoderBuffer and uncompressBuffer will get quite big and they won't be
 * resized down at any time. Though the packet size is really limited by the channel max packet size
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@SuppressWarnings("checkstyle:MethodCount")
public abstract class AbstractSession extends SessionHelper {
    /**
     * Name of the property where this session is stored in the attributes of the underlying MINA session. See
     * {@link #getSession(IoSession, boolean)} and {@link #attachSession(IoSession, AbstractSession)}.
     */
    public static final String SESSION = "org.apache.sshd.session";

    /**
     * The pseudo random generator
     */
    protected final Random random;

    /**
     * Session listeners container
     */
    protected final Collection<SessionListener> sessionListeners = new CopyOnWriteArraySet<>();
    protected final SessionListener sessionListenerProxy;

    /**
     * Channel events listener container
     */
    protected final Collection<ChannelListener> channelListeners = new CopyOnWriteArraySet<>();
    protected final ChannelListener channelListenerProxy;

    /**
     * Port forwarding events listener container
     */
    protected final Collection<PortForwardingEventListener> tunnelListeners = new CopyOnWriteArraySet<>();
    protected final PortForwardingEventListener tunnelListenerProxy;

    protected final Object requestLock = new Object();

    protected final CurrentService currentService;

    protected String serverVersion;
    protected String clientVersion;

    /**
     * Used to wait for results of global requests sent with {@code want-reply = true}. Note that per RFC 4254, global
     * requests may be sent at any time, but success/failure replies MUST come in the order the requests were sent. Some
     * implementations may also reply with SSH_MSG_UNIMPLEMENTED, on which RFC 4253 says they must be sent in the order
     * the message was received.
     * <p>
     * This implies that it is legal to send "nested" global requests: a client or server may send two (or more) global
     * requests, and then receives two (or more) replies in the correct order: first reply for the first request sent;
     * second reply for the second request sent.
     * </p>
     * <p>
     * We keep a FIFO list of pending global requests for which we expect a reply. We always add new global requests at
     * the head. For success and failure replies, which don't identify the message sequence number of the global
     * request, we apply the reply to the tail of the list. For unimplemented messages, we apply it to the request
     * identified by the message sequence number, which normally also should be the tail.
     * </p>
     * <p>
     * When a reply is received, the corresponding global request is removed from the list.
     * </p>
     * <p>
     * Global requests sent with {@code want-reply = false} are never added to this list; they are fire-and-forget.
     * According to the SSH RFCs, the peer MUST not reply on a message with {@code want-reply = false}. If it does so
     * all the same, it is broken. We might then apply the result to the wrong pending global request if we have any.
     * </p>
     *
     * @see <a href="https://tools.ietf.org/html/rfc4254#section-4">RFC 4254: Global Requests</a>
     * @see <a href="https://tools.ietf.org/html/rfc4253#section-11.4">RFC 4254: Reserved Messages</a>
     * @see #request(Buffer, String, org.apache.sshd.common.future.GlobalRequestFuture.ReplyHandler)
     * @see #requestSuccess(Buffer)
     * @see #requestFailure(Buffer)
     * @see #doInvokeUnimplementedMessageHandler(int, Buffer)
     * @see #preClose()
     */
    private final Deque<GlobalRequestFuture> pendingGlobalRequests = new ConcurrentLinkedDeque<>();

    private final Map<Buffer, LongConsumer> globalSequenceNumbers = new ConcurrentHashMap<>();

    private final FilterChain filters = new DefaultFilterChain();

    private CryptFilter cryptFilter;
    private CompressionFilter compressionFilter;
    private KexFilter kexFilter;

    /**
     * Create a new session.
     *
     * @param serverSession  {@code true} if this is a server session, {@code false} if client one
     * @param factoryManager the factory manager
     * @param ioSession      the underlying I/O session
     */
    protected AbstractSession(boolean serverSession, FactoryManager factoryManager, IoSession ioSession) {
        super(serverSession, factoryManager, ioSession);

        currentService = Objects.requireNonNull(initializeCurrentService(), "No CurrentService set on the session");

        attachSession(ioSession, this);

        Factory<? extends Random> factory = ValidateUtils.checkNotNull(
                factoryManager.getRandomFactory(), "No random factory for %s", ioSession);
        random = ValidateUtils.checkNotNull(
                factory.create(), "No randomizer instance for %s", ioSession);

        sessionListenerProxy = EventListenerUtils.proxyWrapper(
                SessionListener.class, sessionListeners);
        channelListenerProxy = EventListenerUtils.proxyWrapper(
                ChannelListener.class, channelListeners);
        tunnelListenerProxy = EventListenerUtils.proxyWrapper(
                PortForwardingEventListener.class, tunnelListeners);

        try {
            signalSessionEstablished(ioSession);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeSshException(e);
        }
    }

    /**
     * Starts the SSH protocol. Invoked by the framework after the session object was fully created, and after
     * {@link SessionListener#sessionCreated(org.apache.sshd.common.session.Session)} has been invoked.
     *
     * @throws Exception on errors
     */
    protected void start() throws Exception {
        boolean isConfigured = !filters.isEmpty();
        IoFilter ioSessionConnector = new IoFilter() {

            @Override
            public InputHandler in() {
                return owner()::passOn;
            }

            @Override
            public OutputHandler out() {
                return message -> getIoSession().writeBuffer(message);
            }
        };
        filters.addFirst(ioSessionConnector);

        if (!isConfigured) {
            setupFilterChain();
        }

        // Temporary. This is work in progress, and actually a lot is still handled by the SSH session.
        // The idea is to migrate parts step by step into filters on this filter chain.
        IoFilter sessionConnector = new IoFilter() {
            @Override
            public InputHandler in() {
                return new BufferInputHandler() {

                    @Override
                    public void handleMessage(Buffer message) throws Exception {
                        AbstractSession.this.handleMessage(message);
                    }
                };
            }

            @Override
            public OutputHandler out() {
                return owner()::send;
            }
        };
        filters.addLast(sessionConnector);
    }

    protected void setupFilterChain() {
        IdentFilter ident = new IdentFilter();
        ident.setPropertyResolver(this);
        ident.setIdentHandler(new SshIdentHandler() {

            @Override
            public boolean isServer() {
                return isServerSession();
            }

            @Override
            public List<String> readIdentification(Buffer buffer) {
                try {
                    boolean haveIdent = AbstractSession.this.readIdentification(buffer);
                    if (!haveIdent) {
                        return null;
                    }
                } catch (Exception e) {
                    throw new IllegalStateException(e.getMessage(), e);
                }
                return Collections.singletonList(isServer() ? clientVersion : serverVersion);
            }

            @Override
            public List<String> provideIdentification() {
                List<String> lines;
                if (!isServer()) {
                    clientVersion = resolveIdentificationString(CoreModuleProperties.CLIENT_IDENTIFICATION.getName());
                    try {
                        signalSendIdentification(clientVersion, Collections.emptyList());
                    } catch (Exception e) {
                        throw new IllegalStateException(e.getMessage(), e);
                    }
                    lines = Collections.singletonList(clientVersion);
                } else {
                    String headerConfig = CoreModuleProperties.SERVER_EXTRA_IDENTIFICATION_LINES
                            .getOrNull(AbstractSession.this);
                    String[] headers = GenericUtils.split(headerConfig,
                            CoreModuleProperties.SERVER_EXTRA_IDENT_LINES_SEPARATOR);
                    lines = GenericUtils.isEmpty(headers) ? new ArrayList<>() : new ArrayList<>(Arrays.asList(headers));

                    serverVersion = resolveIdentificationString(CoreModuleProperties.SERVER_IDENTIFICATION.getName());
                    try {
                        signalSendIdentification(serverVersion, lines);
                    } catch (Exception e) {
                        throw new IllegalStateException(e.getMessage(), e);
                    }
                    lines.add(serverVersion);
                }
                return lines;
            }
        });
        filters.addLast(ident);

        cryptFilter = new CryptFilter();
        cryptFilter.setSession(this);
        cryptFilter.setRandom(random);
        cryptFilter.addEncryptionListener((buffer, sequenceNumber) -> {
            // SSHD-968 - remember global request outgoing sequence number
            LongConsumer setter = globalSequenceNumbers.remove(buffer);
            if (setter != null) {
                setter.accept(sequenceNumber);
            }
        });
        filters.addLast(cryptFilter);

        compressionFilter = new CompressionFilter();
        compressionFilter.setSession(this);
        filters.addLast(compressionFilter);

        DelayKexInitFilter delayKexFilter = new DelayKexInitFilter();
        delayKexFilter.setSession(this);
        filters.addLast(delayKexFilter);

        filters.addLast(new InjectIgnoreFilter(this, random));

        kexFilter = new KexFilter(this, random, cryptFilter, compressionFilter, new SessionListener() {

            @Override
            public void sessionNegotiationStart(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal) {
                AbstractSession.this.signalNegotiationStart(clientProposal, serverProposal);
            }

            @Override
            public void sessionNegotiationEnd(
                    Session session, Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal, Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                AbstractSession.this.signalNegotiationEnd(clientProposal, serverProposal, negotiatedOptions, reason);
            }

            @Override
            public void sessionEvent(Session session, Event event) {
                try {
                    AbstractSession.this.signalSessionEvent(event);
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e) {
                    throw new RuntimeSshException(e.getMessage(), e);
                }
            }
        }, this::getKexProposal, this::checkKeys);
        filters.addLast(kexFilter);

        ident.addIdentListener((peer, id) -> {
            if (peer == isServerSession()) {
                kexFilter.setClientIdent(id);
            } else {
                kexFilter.setServerIdent(id);
            }
        });
    }

    @Override
    public FilterChain getFilterChain() {
        return filters;
    }

    protected boolean isConnectionSecure() {
        return cryptFilter.isSecure();
    }

    protected CompressionFilter getCompressionFilter() {
        return compressionFilter;
    }

    public void addKexListener(KexListener listener) {
        kexFilter.addKexListener(listener);
    }

    public void removeKexListener(KexListener listener) {
        kexFilter.addKexListener(listener);
    }

    protected void initializeKeyExchangePhase() throws Exception {
        KeyExchangeFuture future = kexFilter.startKex();
        Throwable t = future.getException();
        if (t != null) {
            if (t instanceof Exception) {
                throw (Exception) t;
            } else {
                throw new SshException("Could not start initial KEX", t);
            }
        }
    }

    protected boolean isStrictKex() {
        return kexFilter.isStrictKex();
    }

    /**
     * Creates a new {@link CurrentService} instance managing this session's current SSH service.
     * <p>
     * This initialization method is invoked once from the {@link AbstractSession} constructor. Do not rely on subclass
     * fields being initialized.
     * </p>
     *
     * @return a new {@link CurrentService} instance for the session
     */
    protected CurrentService initializeCurrentService() {
        return new CurrentService(this);
    }

    @Override
    public String getServerVersion() {
        return serverVersion;
    }

    @Override
    public Map<KexProposalOption, String> getServerKexProposals() {
        return kexFilter.getServerProposal();
    }

    @Override
    public String getClientVersion() {
        return clientVersion;
    }

    @Override
    public Map<KexProposalOption, String> getClientKexProposals() {
        return kexFilter.getClientProposal();
    }

    @Override
    public KexState getKexState() {
        return kexFilter.getKexState().get();
    }

    @Override
    public byte[] getSessionId() {
        return kexFilter.getSessionId();
    }

    @Override
    public Map<KexProposalOption, String> getKexNegotiationResult() {
        return kexFilter.getNegotiated();
    }

    @Override
    public String getNegotiatedKexParameter(KexProposalOption paramType) {
        return kexFilter.getNegotiated().get(paramType);
    }

    @Override
    public CipherInformation getCipherInformation(boolean incoming) {
        return incoming ? cryptFilter.getInputSettings().getCipher() : cryptFilter.getOutputSettings().getCipher();
    }

    @Override
    public CompressionInformation getCompressionInformation(boolean incoming) {
        return incoming ? compressionFilter.getInputCompression() : compressionFilter.getOutputCompression();
    }

    @Override
    public MacInformation getMacInformation(boolean incoming) {
        return incoming ? cryptFilter.getInputSettings().getMac() : cryptFilter.getOutputSettings().getMac();
    }

    /**
     * Abstract method for processing incoming decoded packets. The given buffer will hold the decoded packet, starting
     * from the command byte at the read position.
     *
     * @param  buffer    The {@link Buffer} containing the packet - it may be re-used to generate the response once
     *                   request has been decoded
     * @throws Exception if an exception occurs while handling this packet.
     * @see              #doHandleMessage(Buffer)
     */
    protected void handleMessage(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (log.isDebugEnabled()) {
            log.debug("doHandleMessage({}) process #{} {}", this, cryptFilter.getInputSequenceNumber() - 1,
                    SshConstants.getCommandMessageName(cmd));
        }

        switch (cmd) {
            case SshConstants.SSH_MSG_DISCONNECT:
                handleDisconnect(buffer);
                break;
            case SshConstants.SSH_MSG_IGNORE:
                handleIgnore(buffer);
                break;
            case SshConstants.SSH_MSG_UNIMPLEMENTED:
                handleUnimplemented(buffer);
                break;
            case SshConstants.SSH_MSG_DEBUG:
                // Fail after handling -- by default a message will be logged, which might be helpful.
                handleDebug(buffer);
                break;
            case SshConstants.SSH_MSG_SERVICE_REQUEST:
                handleServiceRequest(buffer);
                break;
            case SshConstants.SSH_MSG_SERVICE_ACCEPT:
                handleServiceAccept(buffer);
                break;
            case KexExtensions.SSH_MSG_EXT_INFO:
                handleKexExtension(cmd, buffer);
                break;
            case KexExtensions.SSH_MSG_NEWCOMPRESS:
                handleNewCompression(cmd, buffer);
                break;
            default:
                if (currentService.process(cmd, buffer)) {
                    resetIdleTimeout();
                } else {
                    /*
                     * According to https://tools.ietf.org/html/rfc4253#section-11.4
                     *
                     * An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message
                     * in the order in which the messages were received.
                     */
                    if (log.isDebugEnabled()) {
                        log.debug("process({}) Unsupported command: {}", this, SshConstants.getCommandMessageName(cmd));
                    }
                    notImplemented(cmd, buffer);
                }
                break;
        }
    }

    protected void handleKexExtension(int cmd, Buffer buffer) throws Exception {
        KexExtensionHandler extHandler = getKexExtensionHandler();
        int startPos = buffer.rpos();
        if ((extHandler != null) && extHandler.handleKexExtensionsMessage(this, buffer)) {
            return;
        }

        buffer.rpos(startPos); // restore original read position
        notImplemented(cmd, buffer);
    }

    protected void handleNewCompression(int cmd, Buffer buffer) throws Exception {
        KexExtensionHandler extHandler = getKexExtensionHandler();
        int startPos = buffer.rpos();
        if ((extHandler != null) && extHandler.handleKexCompressionMessage(this, buffer)) {
            return;
        }

        buffer.rpos(startPos); // restore original read position
        notImplemented(cmd, buffer);
    }

    protected void handleServiceRequest(Buffer buffer) throws Exception {
        String serviceName = buffer.getString();
        handleServiceRequest(serviceName, buffer);
    }

    protected boolean handleServiceRequest(String serviceName, Buffer buffer) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleServiceRequest({}) SSH_MSG_SERVICE_REQUEST '{}'", this, serviceName);
        }

        try {
            startService(serviceName, buffer);
        } catch (Throwable e) {
            debug("handleServiceRequest({}) Service {} rejected: {} = {}",
                    this, serviceName, e.getClass().getSimpleName(), e.getMessage(), e);
            disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + serviceName);
            return false;
        }

        if (debugEnabled) {
            log.debug("handleServiceRequest({}) Accepted service {}", this, serviceName);
        }

        Buffer response = createBuffer(
                SshConstants.SSH_MSG_SERVICE_ACCEPT, Byte.SIZE + GenericUtils.length(serviceName));
        response.putString(serviceName);
        writePacket(response);
        return true;
    }

    protected void handleServiceAccept(Buffer buffer) throws Exception {
        handleServiceAccept(buffer.getString(), buffer);
    }

    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleServiceAccept({}) SSH_MSG_SERVICE_ACCEPT service={}", this, serviceName);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        Closeable closer = builder()
                .parallel(toString(), getServices())
                .close(getIoSession())
                .build();
        closer.addCloseFutureListener(future -> clearAttributes());
        return closer;
    }

    @Override
    protected void preClose() {
        if (kexFilter != null) {
            kexFilter.shutdown();
        }

        // if anyone waiting for global response notify them about the closing session
        boolean debugEnabled = log.isDebugEnabled();
        for (;;) {
            GlobalRequestFuture future = pendingGlobalRequests.pollLast();
            if (future == null) {
                break;
            }
            if (debugEnabled) {
                log.debug("preClose({}): Session closing; failing still pending global request {}", this, future.getId());
            }
            future.setValue(new SshException("Session is closing"));
        }

        // Fire 'close' event
        try {
            signalSessionClosed();
        } finally {
            // clear the listeners since we are closing the session (quicker GC)
            this.sessionListeners.clear();
            this.channelListeners.clear();
            this.tunnelListeners.clear();
        }

        super.preClose();
    }

    protected List<Service> getServices() {
        Service service = currentService.getService();
        return (service != null)
                ? Collections.singletonList(service)
                : Collections.emptyList();
    }

    @Override
    public <T extends Service> T getService(Class<T> clazz) {
        Collection<? extends Service> registeredServices = getServices();
        ValidateUtils.checkState(GenericUtils.isNotEmpty(registeredServices),
                "No registered services to look for %s", clazz.getSimpleName());

        for (Service s : registeredServices) {
            if (clazz.isInstance(s)) {
                return clazz.cast(s);
            }
        }

        throw new IllegalStateException("Attempted to access unknown service " + clazz.getSimpleName());
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        return filters.getLast().out().send(buffer);
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        long timeoutMillis = unit.toMillis(timeout);
        IoWriteFuture writeFuture;
        try {
            long start = System.currentTimeMillis();
            writeFuture = writePacket(buffer);
            long elapsed = System.currentTimeMillis() - start;
            if (elapsed >= timeoutMillis) {
                // We just barely made it. Give it a tiny grace period.
                timeoutMillis = 1;
            } else {
                timeoutMillis -= elapsed;
            }
        } catch (InterruptedIOException e) {
            // Already timed out
            PendingWriteFuture timedOut = new PendingWriteFuture(this, buffer);
            Throwable t = new TimeoutException("Timeout writing packet: " + timeout + " " + unit);
            t.initCause(e);
            if (log.isDebugEnabled()) {
                log.debug("writePacket({}): {}", AbstractSession.this, t.getMessage());
            }
            timedOut.setValue(t);
            return timedOut;
        }
        if (writeFuture.isDone()) {
            // No need to schedule anything.
            return writeFuture;
        }
        @SuppressWarnings("unchecked")
        DefaultSshFuture<IoWriteFuture> future = (DefaultSshFuture<IoWriteFuture>) writeFuture;
        FactoryManager factoryManager = getFactoryManager();
        ScheduledExecutorService executor = factoryManager.getScheduledExecutorService();
        ScheduledFuture<?> sched = executor.schedule(() -> {
            Throwable t = new TimeoutException("Timeout writing packet: " + timeout + " " + unit);
            if (log.isDebugEnabled()) {
                log.debug("writePacket({}): {}", AbstractSession.this, t.getMessage());
            }
            future.setValue(t);
        }, timeoutMillis, TimeUnit.MILLISECONDS);
        future.addListener(f -> sched.cancel(false));
        return writeFuture;
    }

    private boolean wantReply(Buffer buffer) {
        // Examine the buffer to get the want-reply flag
        int rpos = buffer.rpos();
        buffer.getByte(); // Skip command
        buffer.getString(); // Skip request name
        boolean replyFlag = buffer.getBoolean();
        buffer.rpos(rpos); // reset buffer
        return replyFlag;
    }

    @Override
    public Buffer request(String request, Buffer buffer, long maxWaitMillis) throws IOException {
        ValidateUtils.checkTrue(maxWaitMillis > 0,
                "Requested timeout for " + request + " is not strictly greater than zero: " + maxWaitMillis);
        boolean debugEnabled = log.isDebugEnabled();
        boolean withReply = wantReply(buffer);
        GlobalRequestFuture future = request(buffer, request, null);
        Object result;
        boolean done = false;
        try {
            if (debugEnabled) {
                log.debug("request({}) request={}, timeout={}ms", this, request, maxWaitMillis);
            }
            done = future.await(maxWaitMillis);
            result = future.getValue();
        } catch (InterruptedIOException e) {
            throw (InterruptedIOException) new InterruptedIOException(
                    "Interrupted while waiting for request=" + request + " result").initCause(e);
        }

        if (!isOpen()) {
            throw new IOException("Session was closed or closing while awaiting reply for request=" + request);
        }

        if (withReply) {
            if (debugEnabled) {
                log.debug("request({}) request={}, timeout={}ms, requestSeqNo={}, done {}, result received={}", this, request,
                        maxWaitMillis, future.getSequenceNumber(), done, result instanceof Buffer);
            }

            if (!done || result == null) {
                throw new SocketTimeoutException("No response received after " + maxWaitMillis + "ms for request=" + request);
            }
            // The operation is specified to return null if the request could be made, but got an error reply.
            // The caller cannot distinguish between SSH_MSG_UNIMPLEMENTED and SSH_MSG_REQUEST_FAILURE.
            if (result instanceof GlobalRequestException) {
                if (debugEnabled) {
                    log.debug("request({}) request={}, requestSeqNo={}: received={}", this, request, future.getSequenceNumber(),
                            SshConstants.getCommandMessageName(((GlobalRequestException) result).getCode()));
                }
                return null;
            }
        }

        if (result instanceof Throwable) {
            throw new IOException("Exception on request " + request, (Throwable) result);
        }
        if (result instanceof Buffer) {
            return (Buffer) result;
        }
        return null;
    }

    @Override
    public GlobalRequestFuture request(Buffer buffer, String request, GlobalRequestFuture.ReplyHandler replyHandler)
            throws IOException {
        GlobalRequestFuture globalRequest;
        if (!wantReply(buffer)) {
            if (!isOpen()) {
                throw new IOException("Global request " + request + ": session is closing or closed.");
            }
            // Fire-and-forget global requests (want-reply = false) are always allowed; we don't need to register the
            // future, nor do we have to wait for anything. Client code can wait on the returned future if it wants to
            // be sure the message has been sent.
            globalRequest = new GlobalRequestFuture(request, replyHandler) {

                @Override
                public void operationComplete(IoWriteFuture future) {
                    if (future.isWritten()) {
                        if (log.isDebugEnabled()) {
                            log.debug("makeGlobalRequest({})[{}] want-reply=false sent", this, getId());
                        }
                        setValue(new ByteArrayBuffer(new byte[0]));
                        GlobalRequestFuture.ReplyHandler handler = getHandler();
                        if (handler != null) {
                            handler.accept(SshConstants.SSH_MSG_REQUEST_SUCCESS, getBuffer());
                        }
                    }
                    super.operationComplete(future);
                }
            };
            writePacket(buffer).addListener(globalRequest);
            return globalRequest;
        }
        // We do expect a reply. The packet may get queued or otherwise delayed for an unknown time. We must
        // consider this request pending only once its sequence number is known. If sending the message fails,
        // the writeFuture will set an exception on the globalRequest, or will fail it.
        globalRequest = new GlobalRequestFuture(request, replyHandler) {

            @Override
            public void operationComplete(IoWriteFuture future) {
                if (!future.isWritten()) {
                    // If it was not written after all, make sure it's not considered pending anymore.
                    pendingGlobalRequests.removeFirstOccurrence(this);
                }
                // Super call will fulfill the future if not written
                super.operationComplete(future);
                if (future.isWritten() && getHandler() != null) {
                    // Fulfill this future now. The GlobalRequestFuture can thus be used to wait for the
                    // successful sending of the request, the framework will invoke the handler whenever
                    // the reply arrives. The buffer cannot be obtained though the future.
                    setValue(null);
                }
            }
        };
        if (!isOpen()) {
            throw new IOException("Global request " + request + ": session is closing or closed.");
        }
        // This consumer will be invoked once before the packet actually goes out. Some servers respond to global
        // requests with SSH_MSG_UNIMPLEMENTED instead of SSH_MSG_REQUEST_FAILURE (see SSHD-968), so we need to make
        // sure we do know the sequence number.
        globalSequenceNumbers.put(buffer, seqNo -> {
            globalRequest.setSequenceNumber(seqNo);
            if (log.isDebugEnabled()) {
                log.debug("makeGlobalRequest({})[{}] want-reply=true with seqNo={}", this, globalRequest.getId(), seqNo);
            }
            // Insert at front
            pendingGlobalRequests.push(globalRequest);
        });
        writePacket(buffer).addListener(f -> {
            Throwable t = f.getException();
            if (t != null) {
                // Just in case we get an exception before preProcessEncodeBuffer was even called
                globalSequenceNumbers.remove(buffer);
            }
        }).addListener(globalRequest); // Report errors through globalRequest, fulfilling globalRequest
        return globalRequest;
    }

    @Override
    protected boolean doInvokeUnimplementedMessageHandler(int cmd, Buffer buffer) throws Exception {
        /*
         * SSHD-968 Some servers respond to global requests with SSH_MSG_UNIMPLEMENTED instead of
         * SSH_MSG_REQUEST_FAILURE (as mandated by https://tools.ietf.org/html/rfc4254#section-4) so deal with it.
         */
        if (!pendingGlobalRequests.isEmpty() && cmd == SshConstants.SSH_MSG_UNIMPLEMENTED) {
            // We do have ongoing global requests.
            long msgSeqNo = buffer.rawUInt(buffer.rpos());

            // Find the global request this applies to
            GlobalRequestFuture future = pendingGlobalRequests.stream().filter(f -> f.getSequenceNumber() == msgSeqNo).findAny()
                    .orElse(null);
            if (future != null && pendingGlobalRequests.removeFirstOccurrence(future)) {
                // This SSH_MSG_UNIMPLEMENTED was the reply to a global request.
                if (log.isDebugEnabled()) {
                    log.debug("doInvokeUnimplementedMessageHandler({}) report global request={} failure for seqNo={}", this,
                            future.getId(), msgSeqNo);
                }
                GlobalRequestFuture.ReplyHandler handler = future.getHandler();
                if (handler != null) {
                    Buffer resultBuf = ByteArrayBuffer.getCompactClone(buffer.array(), buffer.rpos(), buffer.available());
                    handler.accept(cmd, resultBuf);
                } else {
                    future.setValue(new GlobalRequestException(cmd));
                }
                return true; // message handled internally
            } else if (future != null) {
                // The SSH_MSG_UNIMPLEMENTED was for a global request, but that request is no longer in the list: it
                // got terminated otherwise.
                return true;
            }
            if (log.isTraceEnabled()) {
                log.trace(
                        "doInvokeUnimplementedMessageHandler({}) SSH_MSG_UNIMPLEMENTED with message seqNo={} not for a global request",
                        this, msgSeqNo);
            }
        }

        return super.doInvokeUnimplementedMessageHandler(cmd, buffer);
    }

    @Override
    public Buffer createBuffer(byte cmd, int len) {
        if (len <= 0) {
            return prepareBuffer(cmd, new PacketBuffer());
        }

        // Since the caller claims to know how many bytes they will need
        // increase their request to account for our headers/footers if
        // they actually send exactly this amount.
        int finalLength;
        if (cryptFilter != null) {
            finalLength = cryptFilter.precomputeBufferLength(len);
        } else {
            // Can occur in some tests
            finalLength = len + SshConstants.SSH_PACKET_HEADER_LEN + 255 + 32;
        }
        return prepareBuffer(cmd, new PacketBuffer(new byte[finalLength], false));
    }

    @Override
    public Buffer prepareBuffer(byte cmd, Buffer buffer) {
        buffer = validateTargetBuffer(cmd & 0xFF, buffer);
        buffer.rpos(SshConstants.SSH_PACKET_HEADER_LEN);
        buffer.wpos(SshConstants.SSH_PACKET_HEADER_LEN);
        buffer.putByte(cmd);
        return buffer;
    }

    /**
     * Makes sure that the buffer used for output is not {@code null}.
     *
     * @param  <B>                      The {@link Buffer} type being validated
     * @param  cmd                      The most likely command this buffer refers to (not guaranteed to be correct)
     * @param  buffer                   The buffer to be examined
     * @return                          The validated target instance - default same as input
     * @throws IllegalArgumentException if any of the conditions is violated
     */
    protected <B extends Buffer> B validateTargetBuffer(int cmd, B buffer) {
        ValidateUtils.checkNotNull(buffer, "No target buffer to examine for command=%d", cmd);
        return buffer;
    }

    /**
     * Read the other side identification. This method is specific to the client or server side, but both should call
     * {@link #doReadIdentification(Buffer, boolean)} and store the result in the needed property.
     *
     * @param  buffer    The {@link Buffer} containing the remote identification
     * @return           <code>true</code> if the identification has been fully read or <code>false</code> if more data
     *                   is needed
     * @throws Exception if an error occurs such as a bad protocol version or unsuccessful KEX was involved
     */
    protected abstract boolean readIdentification(Buffer buffer) throws Exception;

    /**
     * Send a {@code SSH_MSG_UNIMPLEMENTED} packet. This packet should contain the sequence id of the unsupported
     * packet: this number is assumed to be the last packet received.
     *
     * @param  cmd       The un-implemented command value
     * @param  buffer    The {@link Buffer} that contains the command. <b>Note:</b> the buffer's read position is just
     *                   beyond the command.
     * @return           An {@link IoWriteFuture} that can be used to wait for packet write completion - {@code null} if
     *                   the registered {@link ReservedSessionMessagesHandler} decided to handle the command internally
     * @throws Exception if an error occurred while handling the packet.
     * @see              #sendNotImplemented(long)
     */
    protected IoWriteFuture notImplemented(int cmd, Buffer buffer) throws Exception {
        if (doInvokeUnimplementedMessageHandler(cmd, buffer)) {
            return null;
        }

        int seq = cryptFilter.getInputSequenceNumber() - 1;
        return sendNotImplemented(seq & 0xFFFF_FFFFL);
    }

    /**
     * Indicates the reception of a {@code SSH_MSG_REQUEST_SUCCESS} message
     *
     * @param  buffer    The {@link Buffer} containing the message data
     * @throws Exception If failed to handle the message
     */
    protected void requestSuccess(Buffer buffer) throws Exception {
        resetIdleTimeout();
        // Remove at end
        GlobalRequestFuture request = pendingGlobalRequests.pollLast();
        if (request != null) {
            // use a copy of the original data in case it is re-used on return
            Buffer resultBuf = ByteArrayBuffer.getCompactClone(buffer.array(), buffer.rpos(), buffer.available());
            GlobalRequestFuture.ReplyHandler handler = request.getHandler();
            if (handler != null) {
                handler.accept(SshConstants.SSH_MSG_REQUEST_SUCCESS, resultBuf);
            } else {
                request.setValue(resultBuf);
            }
        }
    }

    /**
     * Indicates the reception of a {@code SSH_MSG_REQUEST_FAILURE} message
     *
     * @param  buffer    The {@link Buffer} containing the message data
     * @throws Exception If failed to handle the message
     */
    protected void requestFailure(Buffer buffer) throws Exception {
        resetIdleTimeout();
        // Remove at end
        GlobalRequestFuture request = pendingGlobalRequests.pollLast();
        if (request != null) {
            GlobalRequestFuture.ReplyHandler handler = request.getHandler();
            if (handler != null) {
                Buffer resultBuf = ByteArrayBuffer.getCompactClone(buffer.array(), buffer.rpos(), buffer.available());
                handler.accept(SshConstants.SSH_MSG_REQUEST_FAILURE, resultBuf);
            } else {
                request.setValue(new GlobalRequestException(SshConstants.SSH_MSG_REQUEST_FAILURE));
            }
        }
    }

    @Override
    public void addSessionListener(SessionListener listener) {
        SessionListener.validateListener(listener);
        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addSessionListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.sessionListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addSessionListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addSessionListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removeSessionListener(SessionListener listener) {
        if (listener == null) {
            return;
        }

        SessionListener.validateListener(listener);
        if (this.sessionListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removeSessionListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removeSessionListener({})[{}] not registered", this, listener);
            }
        }
    }

    @Override
    public SessionListener getSessionListenerProxy() {
        return sessionListenerProxy;
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ChannelListener.validateListener(listener);
        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while session is closing", this, listener);
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
    public PortForwardingEventListener getPortForwardingEventListenerProxy() {
        return tunnelListenerProxy;
    }

    @Override
    public void addPortForwardingEventListener(PortForwardingEventListener listener) {
        PortForwardingEventListener.validateListener(listener);
        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addPortForwardingEventListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.tunnelListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addPortForwardingEventListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addPortForwardingEventListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removePortForwardingEventListener(PortForwardingEventListener listener) {
        if (listener == null) {
            return;
        }

        PortForwardingEventListener.validateListener(listener);
        if (this.tunnelListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removePortForwardingEventListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removePortForwardingEventListener({})[{}] not registered", this, listener);
            }
        }
    }

    @Override
    public KeyExchangeFuture reExchangeKeys() throws IOException {
        try {
            return kexFilter.startKex();
        } catch (GeneralSecurityException e) {
            debug("reExchangeKeys({}) failed ({}) to request new keys: {}",
                    this, e.getClass().getSimpleName(), e.getMessage(), e);
            throw ValidateUtils.initializeExceptionCause(
                    new ProtocolException("Failed (" + e.getClass().getSimpleName() + ")"
                                          + " to generate keys for exchange: " + e.getMessage()),
                    e);
        } catch (Exception e) {
            ExceptionUtils.rethrowAsIoException(e);
            return null;    // actually dead code
        }
    }

    @Override
    protected String resolveSessionKexProposal(String hostKeyTypes) throws IOException {
        String proposal = super.resolveSessionKexProposal(hostKeyTypes);
        // see https://tools.ietf.org/html/rfc8308
        KexExtensionHandler extHandler = getKexExtensionHandler();
        if ((extHandler == null) || (!extHandler.isKexExtensionsAvailable(this, AvailabilityPhase.PROPOSAL))) {
            return proposal;
        }

        String extType = isServerSession() ? KexExtensions.SERVER_KEX_EXTENSION : KexExtensions.CLIENT_KEX_EXTENSION;
        if (GenericUtils.isEmpty(proposal)) {
            return extType;
        } else {
            return proposal + "," + extType;
        }
    }

    /**
     * Indicates the the key exchange is completed and the exchanged keys can now be verified - e.g., client can verify
     * the server's key
     *
     * @throws IOException If validation failed
     */
    protected abstract void checkKeys() throws IOException;

    /**
     * Retrieve the SSH session from the I/O session. If the session has not been attached, an exception will be thrown
     *
     * @param  ioSession                       The {@link IoSession}
     * @return                                 The SSH session attached to the I/O session
     * @see                                    #getSession(IoSession, boolean)
     * @throws MissingAttachedSessionException if no attached SSH session
     */
    public static AbstractSession getSession(IoSession ioSession)
            throws MissingAttachedSessionException {
        return getSession(ioSession, false);
    }

    /**
     * Attach an SSH {@link AbstractSession} to the I/O session
     *
     * @param  ioSession                        The {@link IoSession}
     * @param  session                          The SSH session to attach
     * @throws MultipleAttachedSessionException If a previous session already attached
     */
    public static void attachSession(IoSession ioSession, AbstractSession session)
            throws MultipleAttachedSessionException {
        Objects.requireNonNull(ioSession, "No I/O session");
        Objects.requireNonNull(session, "No SSH session");
        Object prev = ioSession.setAttributeIfAbsent(SESSION, session);
        if (prev != null) {
            throw new MultipleAttachedSessionException(
                    "Multiple attached session to " + ioSession + ": " + prev + " and " + session);
        }
    }

    /**
     * Retrieve the session SSH from the I/O session. If the session has not been attached and <tt>allowNull</tt> is
     * <code>false</code>, an exception will be thrown, otherwise a {@code null} will be returned.
     *
     * @param  ioSession                       The {@link IoSession}
     * @param  allowNull                       If <code>true</code>, a {@code null} value may be returned if no session
     *                                         is attached
     * @return                                 the session attached to the I/O session or {@code null}
     * @throws MissingAttachedSessionException if no attached session and <tt>allowNull=false</tt>
     */
    public static AbstractSession getSession(IoSession ioSession, boolean allowNull)
            throws MissingAttachedSessionException {
        AbstractSession session = (AbstractSession) ioSession.getAttribute(SESSION);
        if ((session == null) && (!allowNull)) {
            throw new MissingAttachedSessionException("No session attached to " + ioSession);
        }

        return session;
    }
}
