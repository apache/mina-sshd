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
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.throttle.ChannelStreamPacketWriterResolver;
import org.apache.sshd.common.channel.throttle.ChannelStreamPacketWriterResolverManager;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.forward.ForwardingFilter;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.AbstractKexFactoryManager;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.UnknownChannelReferenceHandler;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Invoker;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * Contains split code in order to make {@link AbstractSession} class smaller
 */
public abstract class SessionHelper extends AbstractKexFactoryManager implements Session {
    /**
     * Client or server side
     */
    private final boolean serverSession;
    /**
     * The underlying network session
     */
    private final IoSession ioSession;

    /**
     * The session specific properties
     */
    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    /**
     * Session specific attributes
     */
    private final Map<AttributeRepository.AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();

    // Session timeout measurements
    private long authTimeoutStart = System.currentTimeMillis();
    private long idleTimeoutStart = System.currentTimeMillis();
    private final AtomicReference<TimeoutStatus> timeoutStatus = new AtomicReference<>(TimeoutStatus.NoTimeout);

    private ReservedSessionMessagesHandler reservedSessionMessagesHandler;
    private UnknownChannelReferenceHandler unknownChannelReferenceHandler;
    private ChannelStreamPacketWriterResolver channelStreamPacketWriterResolver;

    /**
     * The name of the authenticated user
     */
    private String username;
    /**
     * Boolean indicating if this session has been authenticated or not
     */
    private boolean authed;

    /**
     * Create a new session.
     *
     * @param serverSession  {@code true} if this is a server session, {@code false} if client one
     * @param factoryManager the factory manager
     * @param ioSession      the underlying I/O session
     */
    protected SessionHelper(boolean serverSession, FactoryManager factoryManager, IoSession ioSession) {
        super(Objects.requireNonNull(factoryManager, "No factory manager provided"));
        this.serverSession = serverSession;
        this.ioSession = Objects.requireNonNull(ioSession, "No IoSession provided");
    }

    @Override
    public IoSession getIoSession() {
        return ioSession;
    }

    public boolean isServerSession() {
        return serverSession;
    }

    @Override
    public FactoryManager getFactoryManager() {
        return (FactoryManager) getDelegate();
    }

    @Override
    public PropertyResolver getParentPropertyResolver() {
        return getFactoryManager();
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
            AttributeRepository.AttributeKey<T> key, Function<? super AttributeRepository.AttributeKey<T>, ? extends T> resolver) {
        return (T) attributes.computeIfAbsent(Objects.requireNonNull(key, "No key"), (Function) resolver);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeRepository.AttributeKey<T> key, T value) {
        return (T) attributes.put(
            Objects.requireNonNull(key, "No key"),
            Objects.requireNonNull(value, "No value"));
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

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public boolean isAuthenticated() {
        return authed;
    }

    @Override
    public void setAuthenticated() throws IOException {
        this.authed = true;
        signalSessionEvent(SessionListener.Event.Authenticated);
    }

    /**
     * Checks whether the session has timed out (both auth and idle timeouts are checked).
     * If the session has timed out, a DISCONNECT message will be sent.
     *
     * @throws IOException If failed to check
     * @see #checkAuthenticationTimeout(long, long)
     * @see #checkIdleTimeout(long, long)
     */
    protected void checkForTimeouts() throws IOException {
        if ((!isOpen()) || isClosing() || isClosed()) {
            if (log.isDebugEnabled()) {
                log.debug("checkForTimeouts({}) session closing", this);
                return;
            }
        }

        long now = System.currentTimeMillis();
        Map.Entry<TimeoutStatus, String> result = checkAuthenticationTimeout(now, getAuthTimeout());
        if (result == null) {
            result = checkIdleTimeout(now, getIdleTimeout());
        }

        TimeoutStatus status = (result == null) ? TimeoutStatus.NoTimeout : result.getKey();
        if ((status == null) || TimeoutStatus.NoTimeout.equals(status)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("checkForTimeouts({}) disconnect - reason={}", this, status);
        }

        timeoutStatus.set(status);
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, result.getValue());
    }

    @Override
    public long getAuthTimeoutStart() {
        return authTimeoutStart;
    }

    @Override
    public long resetAuthTimeout() {
        long value = getAuthTimeoutStart();
        this.authTimeoutStart = System.currentTimeMillis();
        return value;
    }

    /**
     * Checks if authentication timeout expired
     *
     * @param now           The current time in millis
     * @param authTimeoutMs The configured timeout in millis - if non-positive then no timeout
     * @return A {@link SimpleImmutableEntry} specifying the timeout status and disconnect reason
     * message if timeout expired, {@code null} or {@code NoTimeout} if no timeout occurred
     * @see #getAuthTimeout()
     */
    protected SimpleImmutableEntry<TimeoutStatus, String> checkAuthenticationTimeout(long now, long authTimeoutMs) {
        long authDiff = now - getAuthTimeoutStart();
        if ((!isAuthenticated()) && (authTimeoutMs > 0L) && (authDiff > authTimeoutMs)) {
            return new SimpleImmutableEntry<>(
                TimeoutStatus.AuthTimeout,
                "Session has timed out waiting for authentication after " + authTimeoutMs + " ms.");
        } else {
            return null;
        }
    }

    @Override
    public long getIdleTimeoutStart() {
        return idleTimeoutStart;
    }

    /**
     * Checks if idle timeout expired
     *
     * @param now           The current time in millis
     * @param idleTimeoutMs The configured timeout in millis - if non-positive then no timeout
     * @return A {@link SimpleImmutableEntry} specifying the timeout status and disconnect reason
     * message if timeout expired, {@code null} or {@code NoTimeout} if no timeout occurred
     * @see #getIdleTimeout()
     */
    protected SimpleImmutableEntry<TimeoutStatus, String> checkIdleTimeout(long now, long idleTimeoutMs) {
        long idleDiff = now - getIdleTimeoutStart();
        if ((idleTimeoutMs > 0L) && (idleDiff > idleTimeoutMs)) {
            return new SimpleImmutableEntry<>(
                TimeoutStatus.IdleTimeout,
                "User session has timed out idling after " + idleTimeoutMs + " ms.");
        } else {
            return null;
        }
    }

    @Override
    public long resetIdleTimeout() {
        long value = getIdleTimeoutStart();
        this.idleTimeoutStart = System.currentTimeMillis();
        return value;
    }

    @Override
    public TimeoutStatus getTimeoutStatus() {
        return timeoutStatus.get();
    }

    public Object getLock() {
        return lock;
    }

    @Override
    public ReservedSessionMessagesHandler getReservedSessionMessagesHandler() {
        return resolveEffectiveProvider(ReservedSessionMessagesHandler.class,
            reservedSessionMessagesHandler, getFactoryManager().getReservedSessionMessagesHandler());
    }

    @Override
    public void setReservedSessionMessagesHandler(ReservedSessionMessagesHandler handler) {
        reservedSessionMessagesHandler = handler;
    }

    protected void handleIgnore(Buffer buffer) throws Exception {
        // malformed ignore message - ignore (even though we don't have to, but we can be tolerant in this case)
        if (!buffer.isValidMessageStructure(byte[].class)) {
            if (log.isTraceEnabled()) {
                log.trace("handleIgnore({}) ignore malformed message", this);
            }
            return;
        }
        resetIdleTimeout();

        ReservedSessionMessagesHandler handler = resolveReservedSessionMessagesHandler();
        handler.handleIgnoreMessage(this, buffer);
    }

    /**
     * Sends a {@code SSH_MSG_UNIMPLEMENTED} message
     *
     * @param seqNoValue The referenced sequence number
     * @return An {@link IoWriteFuture} that can be used to wait for packet write completion
     * @throws IOException if an error occurred sending the packet
     */
    protected IoWriteFuture sendNotImplemented(long seqNoValue) throws IOException {
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_UNIMPLEMENTED, Byte.SIZE);
        buffer.putInt(seqNoValue);
        return writePacket(buffer);
    }

    protected void handleUnimplemented(Buffer buffer) throws Exception {
        if (!buffer.isValidMessageStructure(int.class)) {
            if (log.isTraceEnabled()) {
                log.trace("handleUnimplemented({}) ignore malformed message", this);
            }
            return;
        }
        resetIdleTimeout();

        ReservedSessionMessagesHandler handler = resolveReservedSessionMessagesHandler();
        handler.handleUnimplementedMessage(this, SshConstants.SSH_MSG_UNIMPLEMENTED, buffer);
    }

    @Override
    public IoWriteFuture sendDebugMessage(boolean display, Object msg, String lang) throws IOException {
        String text = Objects.toString(msg, "");
        lang = (lang == null) ? "" : lang;

        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DEBUG,
            text.length() + lang.length() + Integer.SIZE /* a few extras */);
        buffer.putBoolean(display);
        buffer.putString(text);
        buffer.putString(lang);
        return writePacket(buffer);
    }

    protected void handleDebug(Buffer buffer) throws Exception {
        // malformed ignore message - ignore (even though we don't have to, but we can be tolerant in this case)
        if (!buffer.isValidMessageStructure(boolean.class, String.class, String.class)) {
            if (log.isTraceEnabled()) {
                log.trace("handleDebug({}) ignore malformed message", this);
            }
            return;
        }
        resetIdleTimeout();

        ReservedSessionMessagesHandler handler = resolveReservedSessionMessagesHandler();
        handler.handleDebugMessage(this, buffer);
    }

    protected ReservedSessionMessagesHandler resolveReservedSessionMessagesHandler() {
        ReservedSessionMessagesHandler handler = getReservedSessionMessagesHandler();
        return (handler == null) ? ReservedSessionMessagesHandlerAdapter.DEFAULT : handler;
    }

    @Override
    public UnknownChannelReferenceHandler getUnknownChannelReferenceHandler() {
        return unknownChannelReferenceHandler;
    }

    @Override
    public void setUnknownChannelReferenceHandler(UnknownChannelReferenceHandler unknownChannelReferenceHandler) {
        this.unknownChannelReferenceHandler = unknownChannelReferenceHandler;
    }

    @Override
    public UnknownChannelReferenceHandler resolveUnknownChannelReferenceHandler() {
        UnknownChannelReferenceHandler handler = getUnknownChannelReferenceHandler();
        if (handler != null) {
            return handler;
        }

        FactoryManager mgr = getFactoryManager();
        return (mgr == null) ? null : mgr.resolveUnknownChannelReferenceHandler();
    }

    @Override
    public ChannelStreamPacketWriterResolver getChannelStreamPacketWriterResolver() {
        return channelStreamPacketWriterResolver;
    }

    @Override
    public void setChannelStreamPacketWriterResolver(ChannelStreamPacketWriterResolver resolver) {
        channelStreamPacketWriterResolver = resolver;
    }

    @Override
    public ChannelStreamPacketWriterResolver resolveChannelStreamPacketWriterResolver() {
        ChannelStreamPacketWriterResolver resolver = getChannelStreamPacketWriterResolver();
        if (resolver != null) {
            return resolver;
        }

        ChannelStreamPacketWriterResolverManager manager = getFactoryManager();
        return manager.resolveChannelStreamPacketWriterResolver();
    }

    @Override
    public IoWriteFuture sendIgnoreMessage(byte... data) throws IOException {
        data = (data == null) ? GenericUtils.EMPTY_BYTE_ARRAY : data;
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_IGNORE, data.length + Byte.SIZE);
        buffer.putBytes(data);
        return writePacket(buffer);
    }

    @SuppressWarnings("unchecked")
    @Override
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        IoWriteFuture writeFuture = writePacket(buffer);
        DefaultSshFuture<IoWriteFuture> future = (DefaultSshFuture<IoWriteFuture>) writeFuture;
        FactoryManager factoryManager = getFactoryManager();
        ScheduledExecutorService executor = factoryManager.getScheduledExecutorService();
        ScheduledFuture<?> sched = executor.schedule(() -> {
            Throwable t = new TimeoutException("Timeout writing packet: " + timeout + " " + unit);
            if (log.isDebugEnabled()) {
                log.debug("writePacket({}): {}", SessionHelper.this, t.getMessage());
            }
            future.setValue(t);
        }, timeout, unit);
        future.addListener(f -> sched.cancel(false));
        return writeFuture;
    }

    protected void signalSessionCreated(IoSession ioSession) throws Exception {
        try {
            invokeSessionSignaller(l -> {
                signalSessionCreated(l);
                return null;
            });
        } catch (Throwable err) {
            Throwable e = GenericUtils.peelException(err);
            if (log.isDebugEnabled()) {
                log.debug("Failed ({}) to announce session={} created: {}",
                      e.getClass().getSimpleName(), ioSession, e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("Session=" + ioSession + " creation failure details", e);
            }
            if (e instanceof Exception) {
                throw (Exception) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }
    }

    protected void signalSessionCreated(SessionListener listener) {
        if (listener == null) {
            return;
        }
        listener.sessionCreated(this);
    }

    /**
     * Sends a session event to all currently registered session listeners
     *
     * @param event The event to send
     * @throws IOException If any of the registered listeners threw an exception.
     */
    protected void signalSessionEvent(SessionListener.Event event) throws IOException {
        try {
            invokeSessionSignaller(l -> {
                signalSessionEvent(l, event);
                return null;
            });
        } catch (Throwable err) {
            Throwable t = GenericUtils.peelException(err);
            if (log.isDebugEnabled()) {
                log.debug("sendSessionEvent({})[{}] failed ({}) to inform listeners: {}",
                       this, event, t.getClass().getSimpleName(), t.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("sendSessionEvent(" + this + ")[" + event + "] listener inform details", t);
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            } else if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else {
                throw new IOException("Failed (" + t.getClass().getSimpleName() + ") to send session event: " + t.getMessage(), t);
            }
        }
    }

    protected void signalSessionEvent(SessionListener listener, SessionListener.Event event) throws IOException {
        if (listener == null) {
            return;
        }

        listener.sessionEvent(this, event);
    }

    protected void invokeSessionSignaller(Invoker<SessionListener, Void> invoker) throws Throwable {
        FactoryManager manager = getFactoryManager();
        SessionListener[] listeners = {
            (manager == null) ? null : manager.getSessionListenerProxy(),
            getSessionListenerProxy()
        };

        Throwable err = null;
        for (SessionListener l : listeners) {
            if (l == null) {
                continue;
            }
            try {
                invoker.invoke(l);
            } catch (Throwable t) {
                err = GenericUtils.accumulateException(err, t);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    /**
     * Method used while putting new keys into use that will resize the key used to
     * initialize the cipher to the needed length.
     *
     * @param e       the key to resize
     * @param kdfSize the cipher key-derivation-factor (in bytes)
     * @param hash    the hash algorithm
     * @param k       the key exchange k parameter
     * @param h       the key exchange h parameter
     * @return the resized key
     * @throws Exception if a problem occur while resizing the key
     */
    protected byte[] resizeKey(byte[] e, int kdfSize, Digest hash, byte[] k, byte[] h) throws Exception {
        for (Buffer buffer = null; kdfSize > e.length; buffer = BufferUtils.clear(buffer)) {
            if (buffer == null) {
                buffer = new ByteArrayBuffer();
            }

            buffer.putMPInt(k);
            buffer.putRawBytes(h);
            buffer.putRawBytes(e);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[e.length + foo.length];
            System.arraycopy(e, 0, bar, 0, e.length);
            System.arraycopy(foo, 0, bar, e.length, foo.length);
            e = bar;
        }
        return e;
    }

    /**
     * @param knownAddress Any externally set peer address - e.g., due to some
     * proxy mechanism meta-data
     * @return The external address if not {@code null} otherwise, the {@code IoSession}
     * peer address
     */
    protected SocketAddress resolvePeerAddress(SocketAddress knownAddress) {
        if (knownAddress != null) {
            return knownAddress;
        }

        IoSession s = getIoSession();
        return (s == null) ? null : s.getRemoteAddress();
    }

    protected long calculateNextIgnorePacketCount(Random r, long freq, int variance) {
        if ((freq <= 0L) || (variance < 0)) {
            return -1L;
        }

        if (variance == 0) {
            return freq;
        }

        int extra = r.random((variance < 0) ? (0 - variance) : variance);
        long count = (variance < 0) ? (freq - extra) : (freq + extra);
        if (log.isTraceEnabled()) {
            log.trace("calculateNextIgnorePacketCount({}) count={}", this, count);
        }

        return count;
    }

    /**
     * Resolves the identification to send to the peer session by consulting
     * the associated {@link FactoryManager}. If a value is set, then it is
     * <U>appended</U> to the standard {@link SessionContext#DEFAULT_SSH_VERSION_PREFIX}.
     * Otherwise a default value is returned consisting of the prefix and
     * the core artifact name + version in <U>uppercase</U> - e.g.,'
     * &quot;SSH-2.0-APACHE-SSHD-1.2.3.4&quot;
     *
     * @param configPropName The property used to query the factory manager
     * @return The resolved identification value
     */
    protected String resolveIdentificationString(String configPropName) {
        FactoryManager manager = getFactoryManager();
        String ident = manager.getString(configPropName);
        return SessionContext.DEFAULT_SSH_VERSION_PREFIX + (GenericUtils.isEmpty(ident) ? manager.getVersion() : ident);
    }

    /**
     * Send our identification.
     *
     * @param ident our identification to send
     * @return {@link IoWriteFuture} that can be used to wait for notification
     * that identification has been send
     * @throws IOException If failed to send the packet
     */
    protected IoWriteFuture sendIdentification(String ident) throws IOException {
        byte[] data = (ident + "\r\n").getBytes(StandardCharsets.UTF_8);
        if (log.isDebugEnabled()) {
            log.debug("sendIdentification({}): {}", this, ident.replace('\r', '|').replace('\n', '|'));
        }

        IoSession networkSession = getIoSession();
        return networkSession.writePacket(new ByteArrayBuffer(data));
    }

    /**
     * Read the remote identification from this buffer.
     * If more data is needed, the buffer will be reset to its original state
     * and a {@code null} value will be returned. Else the identification
     * string will be returned and the data read will be consumed from the buffer.
     *
     * @param buffer the buffer containing the identification string
     * @param server {@code true} if it is called by the server session,
     * {@code false} if by the client session
     * @return A {@link List} of all received remote identification lines until
     * the version line was read or {@code null} if more data is needed.
     * The identification line is the <U>last</U> one in the list
     */
    protected List<String> doReadIdentification(Buffer buffer, boolean server) {
        int maxIdentSize = PropertyResolverUtils.getIntProperty(this,
            FactoryManager.MAX_IDENTIFICATION_SIZE, FactoryManager.DEFAULT_MAX_IDENTIFICATION_SIZE);
        List<String> ident = null;
        int rpos = buffer.rpos();
        for (byte[] data = new byte[SessionContext.MAX_VERSION_LINE_LENGTH];;) {
            int pos = 0;    // start accumulating line from scratch
            for (boolean needLf = false;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }

                byte b = buffer.getByte();
                /*
                 * According to RFC 4253 section 4.2:
                 *
                 *      "The null character MUST NOT be sent"
                 */
                if (b == 0) {
                    throw new IllegalStateException("Incorrect identification (null characters not allowed) - "
                            + " at line " + (GenericUtils.size(ident) + 1) + " character #" + (pos + 1)
                            + " after '" + new String(data, 0, pos, StandardCharsets.UTF_8) + "'");
                }
                if (b == '\r') {
                    needLf = true;
                    continue;
                }

                if (b == '\n') {
                    break;
                }

                if (needLf) {
                    throw new IllegalStateException("Incorrect identification (bad line ending) "
                            + " at line " + (GenericUtils.size(ident) + 1)
                            + ": " + new String(data, 0, pos, StandardCharsets.UTF_8));
                }

                if (pos >= data.length) {
                    throw new IllegalStateException("Incorrect identification (line too long): "
                            + " at line " + (GenericUtils.size(ident) + 1)
                            + ": " + new String(data, 0, pos, StandardCharsets.UTF_8));
                }

                data[pos++] = b;
            }

            String str = new String(data, 0, pos, StandardCharsets.UTF_8);
            if (log.isDebugEnabled()) {
                log.debug("doReadIdentification({}) line='{}'", this, str);
            }

            if (ident == null) {
                ident = new ArrayList<>();
            }
            ident.add(str);

            // if this is a server then only one line is expected from the client
            if (server || str.startsWith("SSH-")) {
                return ident;
            }

            if (buffer.rpos() > maxIdentSize) {
                throw new IllegalStateException("Incorrect identification (too many header lines): size > " + maxIdentSize);
            }
        }
    }

    /**
     * Create our proposal for SSH negotiation
     *
     * @param hostKeyTypes The comma-separated list of supported host key types
     * @return The proposal {@link Map}
     */
    protected Map<KexProposalOption, String> createProposal(String hostKeyTypes) {
        Map<KexProposalOption, String> proposal = new EnumMap<>(KexProposalOption.class);
        proposal.put(KexProposalOption.ALGORITHMS,
            NamedResource.getNames(
                ValidateUtils.checkNotNullAndNotEmpty(getKeyExchangeFactories(), "No KEX factories")));
        proposal.put(KexProposalOption.SERVERKEYS, hostKeyTypes);

        String ciphers = NamedResource.getNames(
            ValidateUtils.checkNotNullAndNotEmpty(getCipherFactories(), "No cipher factories"));
        proposal.put(KexProposalOption.S2CENC, ciphers);
        proposal.put(KexProposalOption.C2SENC, ciphers);

        String macs = NamedResource.getNames(
            ValidateUtils.checkNotNullAndNotEmpty(getMacFactories(), "No MAC factories"));
        proposal.put(KexProposalOption.S2CMAC, macs);
        proposal.put(KexProposalOption.C2SMAC, macs);

        String compressions = NamedResource.getNames(
            ValidateUtils.checkNotNullAndNotEmpty(getCompressionFactories(), "No compression factories"));
        proposal.put(KexProposalOption.S2CCOMP, compressions);
        proposal.put(KexProposalOption.C2SCOMP, compressions);

        proposal.put(KexProposalOption.S2CLANG, "");    // TODO allow configuration
        proposal.put(KexProposalOption.C2SLANG, "");    // TODO allow configuration
        return proposal;
    }

    // returns the proposal argument
    protected Map<KexProposalOption, String> mergeProposals(
            Map<KexProposalOption, String> current, Map<KexProposalOption, String> proposal) {
        // Checking references by design
        if (current == proposal) {
            return proposal; // nothing to merge
        }

        synchronized (current) {
            if (!current.isEmpty()) {
                current.clear();    // debug breakpoint
            }

            if (GenericUtils.isEmpty(proposal)) {
                return proposal; // debug breakpoint
            }

            current.putAll(proposal);
        }

        return proposal;
    }

    protected void signalNegotiationStart(Map<KexProposalOption, String> c2sOptions, Map<KexProposalOption, String> s2cOptions) {
        try {
            invokeSessionSignaller(l -> {
                signalNegotiationStart(l, c2sOptions, s2cOptions);
                return null;
            });
        } catch (Throwable err) {
            if (err instanceof RuntimeException) {
                throw (RuntimeException) err;
            } else if (err instanceof Error) {
                throw (Error) err;
            } else {
                throw new RuntimeException(err);
            }
        }
    }

    protected void signalNegotiationStart(
            SessionListener listener, Map<KexProposalOption, String> c2sOptions, Map<KexProposalOption, String> s2cOptions) {
        if (listener == null) {
            return;
        }

        listener.sessionNegotiationStart(this, c2sOptions, s2cOptions);
    }

    protected void signalNegotiationEnd(
            Map<KexProposalOption, String> c2sOptions, Map<KexProposalOption, String> s2cOptions,
            Map<KexProposalOption, String> negotiatedGuess, Throwable reason) {
        try {
            invokeSessionSignaller(l -> {
                signalNegotiationEnd(l, c2sOptions, s2cOptions, negotiatedGuess, reason);
                return null;
            });
        } catch (Throwable err) {
            if (err instanceof RuntimeException) {
                throw (RuntimeException) err;
            } else if (err instanceof Error) {
                throw (Error) err;
            } else {
                throw new RuntimeException(err);
            }
        }
    }

    protected void signalNegotiationEnd(SessionListener listener,
            Map<KexProposalOption, String> c2sOptions, Map<KexProposalOption, String> s2cOptions,
            Map<KexProposalOption, String> negotiatedGuess, Throwable reason) {
        if (listener == null) {
            return;
        }

        listener.sessionNegotiationEnd(this, c2sOptions, s2cOptions, negotiatedGuess, null);
    }

    /**
     * Send a message to put new keys into use.
     *
     * @return An {@link IoWriteFuture} that can be used to wait and
     * check the result of sending the packet
     * @throws IOException if an error occurs sending the message
     */
    protected IoWriteFuture sendNewKeys() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendNewKeys({}) Send SSH_MSG_NEWKEYS", this);
        }
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_NEWKEYS, Byte.SIZE);
        return writePacket(buffer);
    }

    @Override
    public void disconnect(int reason, String msg) throws IOException {
        log.info("Disconnecting({}): {} - {}", this, SshConstants.getDisconnectReasonName(reason), msg);
        String languageTag = "";    // TODO configure language...
        signalDisconnect(reason, msg, languageTag, true);

        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DISCONNECT, msg.length() + Short.SIZE);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");

        // Write the packet with a timeout to ensure a timely close of the session
        // in case the consumer does not read packets anymore.
        long disconnectTimeoutMs = this.getLongProperty(
            FactoryManager.DISCONNECT_TIMEOUT, FactoryManager.DEFAULT_DISCONNECT_TIMEOUT);
        IoWriteFuture packetFuture = writePacket(buffer, disconnectTimeoutMs, TimeUnit.MILLISECONDS);
        packetFuture.addListener(future -> {
            Throwable t = future.getException();
            if (log.isDebugEnabled()) {
                if (t == null) {
                    log.debug("disconnect({}) operation successfully completed for reason={} [{}]",
                        SessionHelper.this, SshConstants.getDisconnectReasonName(reason), msg);
                } else {
                    log.debug("disconnect({}) operation failed ({}) for reason={} [{}]: {}",
                        SessionHelper.this, t.getClass().getSimpleName(),
                        SshConstants.getDisconnectReasonName(reason), msg, t.getMessage());
                }
            }

            if (t != null) {
                if (log.isTraceEnabled()) {
                    log.trace("disconnect(" + SessionHelper.this + ")"
                        + " reason=" + SshConstants.getDisconnectReasonName(reason) + " failure details",
                        t);
                }
            }

            close(true);
        });
    }

    protected void handleDisconnect(Buffer buffer) throws Exception  {
        int code = buffer.getInt();
        String message = buffer.getString();
        String languageTag;
        // SSHD-738: avoid spamming the log with uninteresting
        // messages caused by buggy OpenSSH < 5.5
        if (buffer.available() > 0) {
            languageTag = buffer.getString();
        } else {
            languageTag = "";
        }
        handleDisconnect(code, message, languageTag, buffer);
    }

    protected void handleDisconnect(int code, String msg, String lang, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleDisconnect({}) SSH_MSG_DISCONNECT reason={}, [lang={}] msg={}",
                  this, SshConstants.getDisconnectReasonName(code), lang, msg);
        }

        signalDisconnect(code, msg, lang, false);
        close(true);
    }

    protected void signalDisconnect(int code, String msg, String lang, boolean initiator) {
        try {
            invokeSessionSignaller(l -> {
                signalDisconnect(l, code, msg, lang, initiator);
                return null;
            });
        } catch (Throwable err) {
            Throwable e = GenericUtils.peelException(err);
            if (log.isDebugEnabled()) {
                log.debug("signalDisconnect(" + this + ") signal session disconnect details", e);
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("signalDisconnect(" + this + ") suppressed session disconnect signalling", s);
                    }
                }
            }
        }
    }

    protected void signalDisconnect(
            SessionListener listener, int code, String msg, String lang, boolean initiator) {
        if (listener == null) {
            return;
        }

        listener.sessionDisconnect(this, code, msg, lang, initiator);
    }

    /**
     * Handle any exceptions that occurred on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an {@link SshException}.
     *
     * @param t the exception to process
     */
    @Override
    public void exceptionCaught(Throwable t) {
        State curState = state.get();
        // Ignore exceptions that happen while closing immediately
        if ((!State.Opened.equals(curState)) && (!State.Graceful.equals(curState))) {
            if (log.isDebugEnabled()) {
                log.debug("exceptionCaught({}) ignore {} due to state={}, message='{}'",
                      this, t.getClass().getSimpleName(), curState, t.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("exceptionCaught(" + this + ")[state=" + curState + "] ignored exception details", t);
            }
            return;
        }

        log.warn("exceptionCaught({})[state={}] {}: {}", this, curState, t.getClass().getSimpleName(), t.getMessage());
        if (log.isDebugEnabled()) {
            log.debug("exceptionCaught(" + this + ")[state=" + curState + "] details", t);
        }

        signalExceptionCaught(t);

        if (State.Opened.equals(curState) && (t instanceof SshException)) {
            int code = ((SshException) t).getDisconnectCode();
            if (code > 0) {
                try {
                    disconnect(code, t.getMessage());
                } catch (Throwable t2) {
                    if (log.isDebugEnabled()) {
                        log.debug("exceptionCaught({}) {} while disconnect with code={}: {}",
                              this, t2.getClass().getSimpleName(), SshConstants.getDisconnectReasonName(code), t2.getMessage());
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("exceptionCaught(" + this + ")[code=" + SshConstants.getDisconnectReasonName(code) + "] disconnect exception details", t2);
                    }
                }
                return;
            }
        }

        close(true);
    }

    protected void signalExceptionCaught(Throwable t) {
        try {
            invokeSessionSignaller(l -> {
                signalExceptionCaught(l, t);
                return null;
            });
        } catch (Throwable err) {
            Throwable e = GenericUtils.peelException(err);
            if (log.isDebugEnabled()) {
                log.debug("signalExceptionCaught(" + this + ") signal session exception details", e);
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("signalExceptionCaught(" + this + ") suppressed session exception signalling", s);
                    }
                }
            }
        }
    }

    protected void signalExceptionCaught(SessionListener listener, Throwable t) {
        if (listener == null) {
            return;
        }

        listener.sessionException(this, t);
    }

    protected void signalSessionClosed() {
        try {
            invokeSessionSignaller(l -> {
                signalSessionClosed(l);
                return null;
            });
        } catch (Throwable err) {
            Throwable e = GenericUtils.peelException(err);
            log.warn("signalSessionClosed({}) {} while signal session closed: {}",
                this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("signalSessionClosed(" + this + ") signal session closed exception details", e);
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("signalSessionClosed(" + this + ") suppressed session closed signalling", s);
                    }
                }
            }
        }
    }

    protected void signalSessionClosed(SessionListener listener) {
        if (listener == null) {
            return;
        }

        listener.sessionClosed(this);
    }

    protected abstract ConnectionService getConnectionService();

    protected ForwardingFilter getForwardingFilter() {
        ConnectionService service = getConnectionService();
        return (service == null) ? null : service.getForwardingFilter();
    }

    @Override
    public List<Map.Entry<Integer, SshdSocketAddress>> getLocalForwardsBindings() {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? Collections.emptyList() : filter.getLocalForwardsBindings();
    }

    @Override
    public boolean isLocalPortForwardingStartedForPort(int port) {
        ForwardingFilter filter = getForwardingFilter();
        return (filter != null) && filter.isLocalPortForwardingStartedForPort(port);
    }

    @Override
    public NavigableSet<Integer> getStartedLocalPortForwards() {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? Collections.emptyNavigableSet() : filter.getStartedLocalPortForwards();
    }

    @Override
    public SshdSocketAddress getBoundLocalPortForward(int port) {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? null : filter.getBoundLocalPortForward(port);
    }

    @Override
    public List<Map.Entry<Integer, SshdSocketAddress>> getRemoteForwardsBindings() {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? Collections.emptyList() : filter.getRemoteForwardsBindings();
    }

    @Override
    public boolean isRemotePortForwardingStartedForPort(int port) {
        ForwardingFilter filter = getForwardingFilter();
        return (filter != null) && filter.isRemotePortForwardingStartedForPort(port);
    }

    @Override
    public NavigableSet<Integer> getStartedRemotePortForwards() {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? Collections.emptyNavigableSet() : filter.getStartedRemotePortForwards();
    }

    @Override
    public SshdSocketAddress getBoundRemotePortForward(int port) {
        ForwardingFilter filter = getForwardingFilter();
        return (filter == null) ? null : filter.getBoundRemotePortForward(port);
    }

    @Override
    public long getAuthTimeout() {
        return this.getLongProperty(FactoryManager.AUTH_TIMEOUT, FactoryManager.DEFAULT_AUTH_TIMEOUT);
    }

    @Override
    public long getIdleTimeout() {
        return this.getLongProperty(FactoryManager.IDLE_TIMEOUT, FactoryManager.DEFAULT_IDLE_TIMEOUT);
    }

    @Override
    public String toString() {
        IoSession networkSession = getIoSession();
        SocketAddress peerAddress = (networkSession == null) ? null : networkSession.getRemoteAddress();
        return getClass().getSimpleName() + "[" + getUsername() + "@" + peerAddress + "]";
    }
}
