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
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.kex.extension.KexExtensions;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.filters.CryptFilter;
import org.apache.sshd.common.session.filters.SshIdentHandler;
import org.apache.sshd.common.session.filters.SshTransportFilter;
import org.apache.sshd.common.session.filters.kex.KexListener;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Encapsulates common behavior for both client and server sessions. In particular, holds the {@link FilterChain}
 * implementing the SSH transport protocol, and provides convenience methods to write SSH packets or make Channel global
 * requests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
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

    protected final CurrentService currentService;

    protected String serverVersion;
    protected String clientVersion;

    private final FilterChain filters = new DefaultFilterChain();

    private SshTransportFilter sshTransport;

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
    }

    /**
     * Starts the SSH protocol. Invoked by the framework after the session object was fully created, and after
     * {@link SessionListener#sessionCreated(org.apache.sshd.common.session.Session)} has been invoked.
     *
     * @throws Exception on errors
     */
    protected void start() throws Exception {
        if (filters.isEmpty()) {
            setupFilterChain();
        }
        signalSessionStarting();

        IoFilter ioSessionConnector = new IoFilter() {

            @Override
            public InputHandler in() {
                return owner()::passOn;
            }

            @Override
            public OutputHandler out() {
                return (cmd, message) -> getIoSession().writeBuffer(message);
            }
        };
        filters.addFirst(ioSessionConnector);

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
        SshIdentHandler identities = new SshIdentHandler() {

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
        };
        SessionListener sessionEvents = new SessionListener() {

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
        };
        sshTransport = new SshTransportFilter(this, random, identities, sessionEvents, this::getKexProposal, this::checkKeys);
        filters.addLast(sshTransport);
    }

    @Override
    public FilterChain getFilterChain() {
        return filters;
    }

    protected SshTransportFilter getTransport() {
        return sshTransport;
    }

    protected boolean isConnectionSecure() {
        return sshTransport.isSecure();
    }

    public void addKexListener(KexListener listener) {
        sshTransport.addKexListener(listener);
    }

    public void removeKexListener(KexListener listener) {
        sshTransport.addKexListener(listener);
    }

    protected void initializeKeyExchangePhase() throws Exception {
        KeyExchangeFuture future = sshTransport.startKex();
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
        return sshTransport.isStrictKex();
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
        return sshTransport.getServerProposal();
    }

    @Override
    public String getClientVersion() {
        return clientVersion;
    }

    @Override
    public Map<KexProposalOption, String> getClientKexProposals() {
        return sshTransport.getClientProposal();
    }

    @Override
    public KexState getKexState() {
        return sshTransport.getKexState().get();
    }

    @Override
    public byte[] getSessionId() {
        return sshTransport.getSessionId();
    }

    @Override
    public Map<KexProposalOption, String> getKexNegotiationResult() {
        return sshTransport.getNegotiated();
    }

    @Override
    public String getNegotiatedKexParameter(KexProposalOption paramType) {
        return sshTransport.getNegotiated().get(paramType);
    }

    @Override
    public CipherInformation getCipherInformation(boolean incoming) {
        return sshTransport.getCipherInformation(incoming);
    }

    @Override
    public CompressionInformation getCompressionInformation(boolean incoming) {
        return sshTransport.getCompressionInformation(incoming);
    }

    @Override
    public MacInformation getMacInformation(boolean incoming) {
        return sshTransport.getMacInformation(incoming);
    }

    /**
     * Abstract method for processing incoming decoded packets. The given buffer will hold the decoded packet, starting
     * from the command byte at the read position.
     *
     * @param  buffer    The {@link Buffer} containing the packet - it may be re-used to generate the response once
     *                   request has been decoded
     * @throws Exception if an exception occurs while handling this packet.
     */
    protected void handleMessage(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (log.isDebugEnabled()) {
            log.debug("doHandleMessage({}) process #{} {}", this, sshTransport.getLastInputSequenceNumber(),
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
        if (sshTransport != null) {
            sshTransport.shutdown();
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
        int cmd = buffer.rawByte(buffer.rpos()) & 0xFF;
        return filters.getLast().out().send(cmd, buffer);
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

    @Override
    public Buffer request(String request, Buffer buffer, long maxWaitMillis) throws IOException {
        ConnectionService service = getCurrentService(ConnectionService.class);
        ValidateUtils.checkNotNull(service, "Current service is not a ConnectionService");
        return service.request(request, buffer, maxWaitMillis);
    }

    @Override
    public GlobalRequestFuture request(Buffer buffer, String request, GlobalRequestFuture.ReplyHandler replyHandler)
            throws IOException {
        ConnectionService service = getCurrentService(ConnectionService.class);
        ValidateUtils.checkNotNull(service, "Current service is not a ConnectionService");
        return service.request(buffer, request, replyHandler);
    }

    @Override
    protected boolean doInvokeUnimplementedMessageHandler(int cmd, Buffer buffer) throws Exception {
        ReservedSessionMessagesHandler service = getCurrentService(ReservedSessionMessagesHandler.class);
        if (service != null && service.handleUnimplementedMessage(this, cmd, buffer)) {
            return true;
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
        int finalLength = len + SshConstants.SSH_PACKET_HEADER_LEN + CryptFilter.MAX_PADDING + CryptFilter.MAX_TAG_LENGTH;
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
        return sendNotImplemented(sshTransport.getLastInputSequenceNumber());
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
            return sshTransport.startKex();
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

    protected <T> T getCurrentService(Class<? extends T> type) {
        Service service = currentService.getService();
        if (type.isInstance(service)) {
            return type.cast(service);
        }
        return null;
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
