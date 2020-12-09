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
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.agent.common.DefaultAgentForwardSupport;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.channel.exception.SshChannelNotFoundException;
import org.apache.sshd.common.channel.exception.SshChannelOpenException;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.forward.ForwarderFactory;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.forward.PortForwardingEventListenerManager;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.UnknownChannelReferenceHandler;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.x11.DefaultX11ForwardSupport;
import org.apache.sshd.server.x11.X11ForwardSupport;

/**
 * Base implementation of ConnectionService.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractConnectionService
        extends AbstractInnerCloseable
        implements ConnectionService {

    /**
     * Default growth factor function used to resize response buffers
     */
    public static final IntUnaryOperator RESPONSE_BUFFER_GROWTH_FACTOR = Int2IntFunction.add(Byte.SIZE);

    /** Used in {@code SSH_MSH_IGNORE} messages for the keep-alive mechanism */
    public static final String DEFAULT_SESSION_IGNORE_HEARTBEAT_STRING = "ignore@sshd.apache.org";

    /**
     * Map of channels keyed by the identifier
     */
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<>();
    /**
     * Next channel identifier
     */
    protected final AtomicInteger nextChannelId = new AtomicInteger(0);
    protected final AtomicLong heartbeatCount = new AtomicLong(0L);
    private ScheduledFuture<?> heartBeat;

    private final AtomicReference<AgentForwardSupport> agentForwardHolder = new AtomicReference<>();
    private final AtomicReference<X11ForwardSupport> x11ForwardHolder = new AtomicReference<>();
    private final AtomicReference<Forwarder> forwarderHolder = new AtomicReference<>();
    private final AtomicBoolean allowMoreSessions = new AtomicBoolean(true);
    private final Collection<PortForwardingEventListener> listeners = new CopyOnWriteArraySet<>();
    private final Collection<PortForwardingEventListenerManager> managersHolder = new CopyOnWriteArraySet<>();
    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final PortForwardingEventListener listenerProxy;
    private final AbstractSession sessionInstance;
    private UnknownChannelReferenceHandler unknownChannelReferenceHandler;

    protected AbstractConnectionService(AbstractSession session) {
        sessionInstance = Objects.requireNonNull(session, "No session");
        listenerProxy = EventListenerUtils.proxyWrapper(PortForwardingEventListener.class, listeners);
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    public PortForwardingEventListener getPortForwardingEventListenerProxy() {
        return listenerProxy;
    }

    @Override
    public void addPortForwardingEventListener(PortForwardingEventListener listener) {
        listeners.add(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public void removePortForwardingEventListener(PortForwardingEventListener listener) {
        if (listener == null) {
            return;
        }

        listeners.remove(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public UnknownChannelReferenceHandler getUnknownChannelReferenceHandler() {
        return unknownChannelReferenceHandler;
    }

    @Override
    public void setUnknownChannelReferenceHandler(UnknownChannelReferenceHandler handler) {
        unknownChannelReferenceHandler = handler;
    }

    @Override
    public Collection<PortForwardingEventListenerManager> getRegisteredManagers() {
        return managersHolder.isEmpty() ? Collections.emptyList() : new ArrayList<>(managersHolder);
    }

    @Override
    public boolean addPortForwardingEventListenerManager(PortForwardingEventListenerManager manager) {
        return managersHolder.add(Objects.requireNonNull(manager, "No manager"));
    }

    @Override
    public boolean removePortForwardingEventListenerManager(PortForwardingEventListenerManager manager) {
        if (manager == null) {
            return false;
        }

        return managersHolder.remove(manager);
    }

    public Collection<Channel> getChannels() {
        return channels.values();
    }

    @Override
    public AbstractSession getSession() {
        return sessionInstance;
    }

    @Override
    public void start() {
        heartBeat = startHeartBeat();
    }

    protected synchronized ScheduledFuture<?> startHeartBeat() {
        stopHeartBeat(); // make sure any existing heartbeat is stopped

        HeartbeatType heartbeatType = getSessionHeartbeatType();
        Duration interval = getSessionHeartbeatInterval();
        Session session = getSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("startHeartbeat({}) heartbeat type={}, interval={}", session, heartbeatType, interval);
        }

        if ((heartbeatType == null) || (heartbeatType == HeartbeatType.NONE) || (GenericUtils.isNegativeOrNull(interval))) {
            return null;
        }

        FactoryManager manager = session.getFactoryManager();
        ScheduledExecutorService service = manager.getScheduledExecutorService();
        return service.scheduleAtFixedRate(
                this::sendHeartBeat, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    /**
     * Sends a heartbeat message/packet
     *
     * @return {@code true} if heartbeat successfully sent
     */
    protected boolean sendHeartBeat() {
        HeartbeatType heartbeatType = getSessionHeartbeatType();
        Duration interval = getSessionHeartbeatInterval();
        Session session = getSession();
        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("sendHeartbeat({}) heartbeat type={}, interval={}",
                    session, heartbeatType, interval);
        }

        if ((heartbeatType == null) || (GenericUtils.isNegativeOrNull(interval)) || (heartBeat == null)) {
            return false;
        }

        // SSHD-1059
        KexState kexState = session.getKexState();
        if ((heartbeatType != HeartbeatType.NONE)
                && (kexState != KexState.DONE)) {
            if (traceEnabled) {
                log.trace("sendHeartbeat({}) heartbeat type={}, interval={} - skip due to KEX state={}",
                        session, heartbeatType, interval, kexState);
            }
            return false;
        }

        try {
            switch (heartbeatType) {
                case NONE:
                    return false;
                case IGNORE: {
                    Buffer buffer = session.createBuffer(
                            SshConstants.SSH_MSG_IGNORE, DEFAULT_SESSION_IGNORE_HEARTBEAT_STRING.length() + Byte.SIZE);
                    buffer.putString(DEFAULT_SESSION_IGNORE_HEARTBEAT_STRING);

                    IoWriteFuture future = session.writePacket(buffer);
                    future.addListener(this::futureDone);
                    return true;
                }
                case RESERVED: {
                    ReservedSessionMessagesHandler handler = Objects.requireNonNull(
                            session.getReservedSessionMessagesHandler(),
                            "No customized heartbeat handler registered");
                    return handler.sendReservedHeartbeat(this);
                }
                default:
                    throw new UnsupportedOperationException("Unsupported heartbeat type: " + heartbeatType);
            }

        } catch (Throwable e) {
            session.exceptionCaught(e);
            warn("sendHeartBeat({}) failed ({}) to send heartbeat #{} request={}: {}",
                    session, e.getClass().getSimpleName(), heartbeatCount, heartbeatType, e.getMessage(), e);
            return false;
        }
    }

    protected void futureDone(IoWriteFuture future) {
        Throwable t = future.getException();
        if (t != null) {
            Session session = getSession();
            session.exceptionCaught(t);
        }
    }

    protected synchronized void stopHeartBeat() {
        boolean debugEnabled = log.isDebugEnabled();
        Session session = getSession();
        if (heartBeat == null) {
            if (debugEnabled) {
                log.debug("stopHeartBeat({}) no heartbeat to stop", session);
            }
            return;
        }

        if (debugEnabled) {
            log.debug("stopHeartBeat({}) stopping", session);
        }

        try {
            heartBeat.cancel(true);
        } finally {
            heartBeat = null;
        }

        if (debugEnabled) {
            log.debug("stopHeartBeat({}) stopped", session);
        }
    }

    @Override
    public Forwarder getForwarder() {
        Forwarder forwarder;
        Session session = getSession();
        synchronized (forwarderHolder) {
            forwarder = forwarderHolder.get();
            if (forwarder != null) {
                return forwarder;
            }

            forwarder = ValidateUtils.checkNotNull(
                    createForwardingFilter(session), "No forwarder created for %s", session);
            forwarderHolder.set(forwarder);
        }

        if (log.isDebugEnabled()) {
            log.debug("getForwardingFilter({}) created instance", session);
        }
        return forwarder;
    }

    @Override
    protected void preClose() {
        stopHeartBeat();
        this.listeners.clear();
        this.managersHolder.clear();
        super.preClose();
    }

    protected Forwarder createForwardingFilter(Session session) {
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        ForwarderFactory factory = Objects.requireNonNull(manager.getForwarderFactory(), "No forwarder factory");
        Forwarder forwarder = factory.create(this);
        forwarder.addPortForwardingEventListenerManager(this);
        return forwarder;
    }

    @Override
    public X11ForwardSupport getX11ForwardSupport() {
        X11ForwardSupport x11Support;
        Session session = getSession();
        synchronized (x11ForwardHolder) {
            x11Support = x11ForwardHolder.get();
            if (x11Support != null) {
                return x11Support;
            }

            x11Support = ValidateUtils.checkNotNull(
                    createX11ForwardSupport(session), "No X11 forwarder created for %s", session);
            x11ForwardHolder.set(x11Support);
        }

        if (log.isDebugEnabled()) {
            log.debug("getX11ForwardSupport({}) created instance", session);
        }
        return x11Support;
    }

    protected X11ForwardSupport createX11ForwardSupport(Session session) {
        return new DefaultX11ForwardSupport(this);
    }

    @Override
    public AgentForwardSupport getAgentForwardSupport() {
        AgentForwardSupport agentForward;
        Session session = getSession();
        synchronized (agentForwardHolder) {
            agentForward = agentForwardHolder.get();
            if (agentForward != null) {
                return agentForward;
            }

            agentForward = ValidateUtils.checkNotNull(
                    createAgentForwardSupport(session), "No agent forward created for %s", session);
            agentForwardHolder.set(agentForward);
        }

        if (log.isDebugEnabled()) {
            log.debug("getAgentForwardSupport({}) created instance", session);
        }

        return agentForward;
    }

    protected AgentForwardSupport createAgentForwardSupport(Session session) {
        return new DefaultAgentForwardSupport(this);
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .sequential(forwarderHolder.get(), agentForwardHolder.get(), x11ForwardHolder.get())
                .parallel(toString(), getChannels())
                .build();
    }

    protected int getNextChannelId() {
        return nextChannelId.getAndIncrement();
    }

    @Override
    public int registerChannel(Channel channel) throws IOException {
        Session session = getSession();
        int maxChannels = CoreModuleProperties.MAX_CONCURRENT_CHANNELS.getRequired(this);
        int curSize = channels.size();
        if (curSize > maxChannels) {
            throw new IllegalStateException("Currently active channels (" + curSize + ") at max.: " + maxChannels);
        }

        int channelId = getNextChannelId();
        channel.init(this, session, channelId);

        boolean registered = false;
        synchronized (channels) {
            if (!isClosing()) {
                channels.put(channelId, channel);
                registered = true;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("registerChannel({})[id={}, registered={}] {}", this, channelId, registered, channel);
        }

        channel.handleChannelRegistrationResult(this, session, channelId, registered);
        return channelId;
    }

    /**
     * Remove this channel from the list of managed channels
     *
     * @param channel the channel
     */
    @Override
    public void unregisterChannel(Channel channel) {
        int channelId = channel.getId();
        Channel result;
        synchronized (channels) {
            result = channels.remove(channelId);
        }

        if (log.isDebugEnabled()) {
            log.debug("unregisterChannel({}) result={}", channel, result);
        }

        if (result != null) {
            result.handleChannelUnregistration(this);
        }
    }

    @Override
    public void process(int cmd, Buffer buffer) throws Exception {
        switch (cmd) {
            case SshConstants.SSH_MSG_CHANNEL_OPEN:
                channelOpen(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                channelOpenConfirmation(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE:
                channelOpenFailure(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_REQUEST:
                channelRequest(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_DATA:
                channelData(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA:
                channelExtendedData(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_FAILURE:
                channelFailure(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_SUCCESS:
                channelSuccess(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                channelWindowAdjust(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_EOF:
                channelEof(buffer);
                break;
            case SshConstants.SSH_MSG_CHANNEL_CLOSE:
                channelClose(buffer);
                break;
            case SshConstants.SSH_MSG_GLOBAL_REQUEST:
                globalRequest(buffer);
                break;
            case SshConstants.SSH_MSG_REQUEST_SUCCESS:
                requestSuccess(buffer);
                break;
            case SshConstants.SSH_MSG_REQUEST_FAILURE:
                requestFailure(buffer);
                break;
            default: {
                /*
                 * According to https://tools.ietf.org/html/rfc4253#section-11.4
                 *
                 * An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message in
                 * the order in which the messages were received.
                 */
                AbstractSession session = getSession();
                if (log.isDebugEnabled()) {
                    log.debug("process({}) Unsupported command: {}",
                            session, SshConstants.getCommandMessageName(cmd));
                }
                session.notImplemented(cmd, buffer);
            }
        }
    }

    @Override
    public boolean isAllowMoreSessions() {
        return allowMoreSessions.get();
    }

    @Override
    public void setAllowMoreSessions(boolean allow) {
        if (log.isDebugEnabled()) {
            log.debug("setAllowMoreSessions({}): {}", this, allow);
        }
        allowMoreSessions.set(allow);
    }

    public void channelOpenConfirmation(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        int sender = buffer.getInt();
        long rwsize = buffer.getUInt();
        long rmpsize = buffer.getUInt();
        if (log.isDebugEnabled()) {
            log.debug("channelOpenConfirmation({}) SSH_MSG_CHANNEL_OPEN_CONFIRMATION sender={}, window-size={}, packet-size={}",
                    channel, sender, rwsize, rmpsize);
        }
        /*
         * NOTE: the 'sender' of the SSH_MSG_CHANNEL_OPEN_CONFIRMATION is the recipient on the client side - see rfc4254
         * section 5.1:
         *
         * 'sender channel' is the channel number allocated by the other side
         *
         * in our case, the server
         */
        channel.handleOpenSuccess(sender, rwsize, rmpsize, buffer);
    }

    public void channelOpenFailure(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        int id = channel.getId();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("channelOpenFailure({}) Received SSH_MSG_CHANNEL_OPEN_FAILURE", channel);
        }

        Channel removed;
        synchronized (channels) {
            removed = channels.remove(id);
        }

        if (debugEnabled) {
            log.debug("channelOpenFailure({}) unregistered {}", channel, removed);
        }

        channel.handleOpenFailure(buffer);
    }

    /**
     * Process incoming data on a channel
     *
     * @param  buffer      the buffer containing the data
     * @throws IOException if an error occurs
     */
    public void channelData(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_DATA, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleData(buffer);
    }

    /**
     * Process incoming extended data on a channel
     *
     * @param  buffer      the buffer containing the data
     * @throws IOException if an error occurs
     */
    public void channelExtendedData(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleExtendedData(buffer);
    }

    /**
     * Process a window adjust packet on a channel
     *
     * @param  buffer      the buffer containing the window adjustment parameters
     * @throws IOException if an error occurs
     */
    public void channelWindowAdjust(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleWindowAdjust(buffer);
    }

    /**
     * Process end of file on a channel
     *
     * @param  buffer      the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelEof(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_EOF, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleEof();
    }

    /**
     * Close a channel due to a close packet received
     *
     * @param  buffer      the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelClose(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_CLOSE, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleClose();
    }

    /**
     * Service a request on a channel
     *
     * @param  buffer      the buffer containing the request
     * @throws IOException if an error occurs
     */
    public void channelRequest(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_REQUEST, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleRequest(buffer);
    }

    /**
     * Process a failure on a channel
     *
     * @param  buffer      the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelFailure(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_FAILURE, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleFailure();
    }

    /**
     * Process a success on a channel
     *
     * @param  buffer      the buffer containing the packet
     * @throws IOException if an error occurs
     */
    public void channelSuccess(Buffer buffer) throws IOException {
        Channel channel = getChannel(SshConstants.SSH_MSG_CHANNEL_SUCCESS, buffer);
        if (channel == null) {
            return; // debug breakpoint
        }

        channel.handleSuccess();
    }

    /**
     * Retrieve the channel designated by the given packet
     *
     * @param  cmd         The command being processed for the channel
     * @param  buffer      the incoming packet
     * @return             the target channel
     * @throws IOException if the channel does not exists
     */
    protected Channel getChannel(byte cmd, Buffer buffer) throws IOException {
        return getChannel(cmd, buffer.getInt(), buffer);
    }

    protected Channel getChannel(byte cmd, int recipient, Buffer buffer) throws IOException {
        Channel channel = channels.get(recipient);
        if (channel != null) {
            return channel;
        }

        UnknownChannelReferenceHandler handler = resolveUnknownChannelReferenceHandler();
        if (handler == null) {
            // Throw a special exception - SSHD-777
            throw new SshChannelNotFoundException(
                    recipient,
                    "Received " + SshConstants.getCommandMessageName(cmd) + " on unknown channel " + recipient);
        }

        channel = handler.handleUnknownChannelCommand(this, cmd, recipient, buffer);
        return channel;
    }

    @Override
    public UnknownChannelReferenceHandler resolveUnknownChannelReferenceHandler() {
        UnknownChannelReferenceHandler handler = getUnknownChannelReferenceHandler();
        if (handler != null) {
            return handler;
        }

        Session s = getSession();
        return (s == null) ? null : s.resolveUnknownChannelReferenceHandler();
    }

    protected void channelOpen(Buffer buffer) throws Exception {
        String type = buffer.getString();
        int sender = buffer.getInt();
        long rwsize = buffer.getUInt();
        long rmpsize = buffer.getUInt();
        /*
         * NOTE: the 'sender' is the identifier assigned by the remote side - the server in this case
         */
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("channelOpen({}) SSH_MSG_CHANNEL_OPEN sender={}, type={}, window-size={}, packet-size={}",
                    this, sender, type, rwsize, rmpsize);
        }

        if (isClosing()) {
            // TODO add language tag configurable control
            sendChannelOpenFailure(buffer, sender, SshConstants.SSH_OPEN_CONNECT_FAILED,
                    "Server is shutting down while attempting to open channel type=" + type, "");
            return;
        }

        if (!isAllowMoreSessions()) {
            // TODO add language tag configurable control
            sendChannelOpenFailure(buffer, sender, SshConstants.SSH_OPEN_CONNECT_FAILED, "additional sessions disabled", "");
            return;
        }

        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        Channel channel = ChannelFactory.createChannel(session, manager.getChannelFactories(), type);
        if (channel == null) {
            // TODO add language tag configurable control
            sendChannelOpenFailure(buffer, sender,
                    SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unsupported channel type: " + type, "");
            return;
        }

        int channelId = registerChannel(channel);
        OpenFuture openFuture = channel.open(sender, rwsize, rmpsize, buffer);
        openFuture.addListener(future -> {
            try {
                if (future.isOpened()) {
                    Window window = channel.getLocalWindow();
                    if (debugEnabled) {
                        log.debug(
                                "operationComplete({}) send SSH_MSG_CHANNEL_OPEN_CONFIRMATION recipient={}, sender={}, window-size={}, packet-size={}",
                                channel, sender, channelId, window.getSize(), window.getPacketSize());
                    }
                    Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, Integer.SIZE);
                    buf.putInt(sender); // remote (server side) identifier
                    buf.putInt(channelId); // local (client side) identifier
                    buf.putInt(window.getSize());
                    buf.putInt(window.getPacketSize());
                    session.writePacket(buf);
                } else {
                    int reasonCode = 0;
                    String message = "Generic error while opening channel: " + channelId;
                    Throwable exception = future.getException();
                    if (exception != null) {
                        if (exception instanceof SshChannelOpenException) {
                            reasonCode = ((SshChannelOpenException) exception).getReasonCode();
                        } else {
                            message = exception.getClass().getSimpleName() + " while opening channel: " + message;
                        }
                    } else {
                        log.warn("operationComplete({}) no exception on closed future={}",
                                AbstractConnectionService.this, future);
                    }

                    Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE, message.length() + Long.SIZE);
                    sendChannelOpenFailure(buf, sender, reasonCode, message, "");
                }
            } catch (IOException e) {
                warn("operationComplete({}) {}: {}",
                        AbstractConnectionService.this, e.getClass().getSimpleName(), e.getMessage(), e);
                session.exceptionCaught(e);
            }
        });
    }

    protected IoWriteFuture sendChannelOpenFailure(
            Buffer buffer, int sender, int reasonCode, String message, String lang)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendChannelOpenFailure({}) sender={}, reason={}, lang={}, message='{}'",
                    this, sender, SshConstants.getOpenErrorCodeName(reasonCode), lang, message);
        }

        Session session = getSession();
        Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE,
                Long.SIZE + GenericUtils.length(message) + GenericUtils.length(lang));
        buf.putInt(sender);
        buf.putInt(reasonCode);
        buf.putString(message);
        buf.putString(lang);
        return session.writePacket(buf);
    }

    /**
     * Process global requests
     *
     * @param  buffer    The request {@link Buffer}
     * @return           An {@link IoWriteFuture} representing the sent packet - <B>Note:</B> if no reply sent then an
     *                   &quot;empty&quot; future is returned - i.e., any added listeners are triggered immediately with
     *                   a synthetic &quot;success&quot;
     * @throws Exception If failed to process the request
     */
    protected IoWriteFuture globalRequest(Buffer buffer) throws Exception {
        String req = buffer.getString();
        boolean wantReply = buffer.getBoolean();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("globalRequest({}) received SSH_MSG_GLOBAL_REQUEST {} want-reply={}", this, req, wantReply);
        }

        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        Collection<RequestHandler<ConnectionService>> handlers = manager.getGlobalRequestHandlers();
        if (GenericUtils.size(handlers) > 0) {
            boolean traceEnabled = log.isTraceEnabled();
            for (RequestHandler<ConnectionService> handler : handlers) {
                RequestHandler.Result result;
                try {
                    result = handler.process(this, req, wantReply, buffer);
                } catch (Throwable e) {
                    warn("globalRequest({})[{}, want-reply={}] failed ({}) to process: {}",
                            this, req, wantReply, e.getClass().getSimpleName(), e.getMessage(), e);
                    result = RequestHandler.Result.ReplyFailure;
                }

                // if Unsupported then check the next handler in line
                if (RequestHandler.Result.Unsupported.equals(result)) {
                    if (traceEnabled) {
                        log.trace("globalRequest({}) {}#process({})[want-reply={}] : {}",
                                this, handler.getClass().getSimpleName(), req, wantReply, result);
                    }
                } else {
                    return sendGlobalResponse(buffer, req, result, wantReply);
                }
            }
        }

        return handleUnknownRequest(buffer, req, wantReply);
    }

    protected IoWriteFuture handleUnknownRequest(Buffer buffer, String req, boolean wantReply) throws IOException {
        log.warn("handleUnknownRequest({}) unknown global request: {}", this, req);
        return sendGlobalResponse(buffer, req, RequestHandler.Result.Unsupported, wantReply);
    }

    protected IoWriteFuture sendGlobalResponse(
            Buffer buffer, String req, RequestHandler.Result result, boolean wantReply)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendGlobalResponse({})[{}] result={}, want-reply={}", this, req, result, wantReply);
        }

        if (RequestHandler.Result.Replied.equals(result) || (!wantReply)) {
            return new AbstractIoWriteFuture(req, null) {
                {
                    setValue(Boolean.TRUE);
                }
            };
        }

        byte cmd = RequestHandler.Result.ReplySuccess.equals(result)
                ? SshConstants.SSH_MSG_REQUEST_SUCCESS
                : SshConstants.SSH_MSG_REQUEST_FAILURE;
        Session session = getSession();
        Buffer rsp = session.createBuffer(cmd, 2);
        return session.writePacket(rsp);
    }

    protected void requestSuccess(Buffer buffer) throws Exception {
        AbstractSession s = getSession();
        s.requestSuccess(buffer);
    }

    protected void requestFailure(Buffer buffer) throws Exception {
        AbstractSession s = getSession();
        s.requestFailure(buffer);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSession() + "]";
    }
}
