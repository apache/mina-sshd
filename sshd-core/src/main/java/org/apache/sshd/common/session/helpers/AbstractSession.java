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
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionInformation;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.AbstractKexFactoryManager;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.SessionWorkBuffer;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * <P>
 * The AbstractSession handles all the basic SSH protocol such as key exchange, authentication,
 * encoding and decoding. Both server side and client side sessions should inherit from this
 * abstract class. Some basic packet processing methods are defined but the actual call to these
 * methods should be done from the {@link #handleMessage(Buffer)}
 * method, which is dependent on the state and side of this session.
 * </P>
 *
 * TODO: if there is any very big packet, decoderBuffer and uncompressBuffer will get quite big
 * and they won't be resized down at any time. Though the packet size is really limited
 * by the channel max packet size
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSession extends AbstractKexFactoryManager implements Session {
    /**
     * Name of the property where this session is stored in the attributes of the
     * underlying MINA session. See {@link #getSession(IoSession, boolean)}
     * and {@link #attachSession(IoSession, AbstractSession)}.
     */
    public static final String SESSION = "org.apache.sshd.session";

    /**
     * Client or server side
     */
    protected final boolean isServer;
    /**
     * The underlying MINA session
     */
    protected final IoSession ioSession;
    /**
     * The pseudo random generator
     */
    protected final Random random;
    /**
     * Boolean indicating if this session has been authenticated or not
     */
    protected boolean authed;
    /**
     * The name of the authenticated user
     */
    protected String username;

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

    /*
     * Key exchange support
     */
    protected byte[] sessionId;
    protected String serverVersion;
    protected String clientVersion;
    // if empty then means not-initialized
    protected final Map<KexProposalOption, String> serverProposal = new EnumMap<>(KexProposalOption.class);
    protected final Map<KexProposalOption, String> clientProposal = new EnumMap<>(KexProposalOption.class);
    protected final Map<KexProposalOption, String> negotiationResult = new EnumMap<>(KexProposalOption.class);
    protected byte[] i_c; // the payload of the client's SSH_MSG_KEXINIT
    protected byte[] i_s; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected KeyExchange kex;
    protected Boolean firstKexPacketFollows;
    protected final AtomicReference<KexState> kexState = new AtomicReference<>(KexState.UNKNOWN);
    protected final AtomicReference<DefaultKeyExchangeFuture> kexFutureHolder = new AtomicReference<>(null);

    /*
     * SSH packets encoding / decoding support
     */
    protected Cipher outCipher;
    protected Cipher inCipher;
    protected int outCipherSize = 8;
    protected int inCipherSize = 8;
    protected Mac outMac;
    protected Mac inMac;
    protected byte[] inMacResult;
    protected Compression outCompression;
    protected Compression inCompression;
    protected long seqi;
    protected long seqo;
    protected SessionWorkBuffer uncompressBuffer;
    protected final SessionWorkBuffer decoderBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    protected final Object decodeLock = new Object();
    protected final Object requestLock = new Object();

    // Session timeout measurements
    protected long authTimeoutStart = System.currentTimeMillis();
    protected long idleTimeoutStart = System.currentTimeMillis();
    protected final AtomicReference<TimeoutStatus> timeoutStatus = new AtomicReference<>(TimeoutStatus.NoTimeout);

    /*
     * Rekeying
     */
    protected final AtomicLong inPacketsCount = new AtomicLong(0L);
    protected final AtomicLong outPacketsCount = new AtomicLong(0L);
    protected final AtomicLong inBytesCount = new AtomicLong(0L);
    protected final AtomicLong outBytesCount = new AtomicLong(0L);
    protected final AtomicLong inBlocksCount = new AtomicLong(0L);
    protected final AtomicLong outBlocksCount = new AtomicLong(0L);
    protected final AtomicLong lastKeyTimeValue = new AtomicLong(0L);
    // we initialize them here in case super constructor calls some methods that use these values
    protected long maxRekyPackets = FactoryManager.DEFAULT_REKEY_PACKETS_LIMIT;
    protected long maxRekeyBytes = FactoryManager.DEFAULT_REKEY_BYTES_LIMIT;
    protected long maxRekeyInterval = FactoryManager.DEFAULT_REKEY_TIME_LIMIT;
    protected final Queue<PendingWriteFuture> pendingPackets = new LinkedList<>();

    protected Service currentService;

    // SSH_MSG_IGNORE stream padding
    protected int ignorePacketDataLength = FactoryManager.DEFAULT_IGNORE_MESSAGE_SIZE;
    protected long ignorePacketsFrequency = FactoryManager.DEFAULT_IGNORE_MESSAGE_FREQUENCY;
    protected int ignorePacketsVariance = FactoryManager.DEFAULT_IGNORE_MESSAGE_VARIANCE;

    protected final AtomicLong maxRekeyBlocks = new AtomicLong(FactoryManager.DEFAULT_REKEY_BYTES_LIMIT / 16);
    protected final AtomicLong ignorePacketsCount = new AtomicLong(FactoryManager.DEFAULT_IGNORE_MESSAGE_FREQUENCY);

    /**
     * The factory manager used to retrieve factories of Ciphers, Macs and other objects
     */
    private final FactoryManager factoryManager;

    /**
     * The session specific properties
     */
    private final Map<String, Object> properties = new ConcurrentHashMap<>();

    /**
     * Used to wait for global requests result synchronous wait
     */
    private final AtomicReference<Object> requestResult = new AtomicReference<>();

    /**
     * Session specific attributes
     */
    private final Map<AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();
    private ReservedSessionMessagesHandler reservedSessionMessagesHandler;

    /**
     * Create a new session.
     *
     * @param isServer       {@code true} if this is a server session, {@code false} if client one
     * @param factoryManager the factory manager
     * @param ioSession      the underlying MINA session
     */
    protected AbstractSession(boolean isServer, FactoryManager factoryManager, IoSession ioSession) {
        super(ValidateUtils.checkNotNull(factoryManager, "No factory manager provided"));
        this.isServer = isServer;
        this.factoryManager = factoryManager;
        this.ioSession = ioSession;
        this.decoderBuffer = new SessionWorkBuffer(this);

        Factory<Random> factory = ValidateUtils.checkNotNull(factoryManager.getRandomFactory(), "No random factory for %s", ioSession);
        random = ValidateUtils.checkNotNull(factory.create(), "No randomizer instance for %s", ioSession);

        refreshConfiguration();

        ClassLoader loader = getClass().getClassLoader();
        sessionListenerProxy = EventListenerUtils.proxyWrapper(SessionListener.class, loader, sessionListeners);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, loader, channelListeners);

        // Delegate the task of further notifications to the session
        addSessionListener(factoryManager.getSessionListenerProxy());
        addChannelListener(factoryManager.getChannelListenerProxy());
    }

    /**
     * Retrieve the session from the MINA session.
     * If the session has not been attached, an {@link IllegalStateException}
     * will be thrown
     *
     * @param ioSession the MINA session
     * @return the session attached to the MINA session
     * @see #getSession(IoSession, boolean)
     */
    public static AbstractSession getSession(IoSession ioSession) {
        return getSession(ioSession, false);
    }

    /**
     * Retrieve the session from the MINA session.
     * If the session has not been attached and <tt>allowNull</tt> is <code>false</code>,
     * an {@link IllegalStateException} will be thrown, else a {@code null} will
     * be returned
     *
     * @param ioSession the MINA session
     * @param allowNull if <code>true</code>, a {@code null} value may be
     *                  returned if no session is attached
     * @return the session attached to the MINA session or {@code null}
     */
    public static AbstractSession getSession(IoSession ioSession, boolean allowNull) {
        AbstractSession session = (AbstractSession) ioSession.getAttribute(SESSION);
        if ((session == null) && (!allowNull)) {
            throw new IllegalStateException("No session available");
        }
        return session;
    }

    /**
     * Attach a session to the MINA session
     *
     * @param ioSession the MINA session
     * @param session   the session to attach
     */
    public static void attachSession(IoSession ioSession, AbstractSession session) {
        ValidateUtils.checkNotNull(ioSession, "No I/O session").setAttribute(SESSION, ValidateUtils.checkNotNull(session, "No SSH session"));
    }

    @Override
    public String getServerVersion() {
        return serverVersion;
    }

    @Override
    public String getClientVersion() {
        return clientVersion;
    }

    @Override
    public KeyExchange getKex() {
        return kex;
    }

    @Override
    public byte[] getSessionId() {
        // return a clone to avoid anyone changing the internal value
        return NumberUtils.isEmpty(sessionId) ? sessionId : sessionId.clone();
    }

    @Override
    public IoSession getIoSession() {
        return ioSession;
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

    @Override
    public FactoryManager getFactoryManager() {
        return factoryManager;
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
    public String getNegotiatedKexParameter(KexProposalOption paramType) {
        if (paramType == null) {
            return null;
        }

        synchronized (negotiationResult) {
            return negotiationResult.get(paramType);
        }
    }

    @Override
    public CipherInformation getCipherInformation(boolean incoming) {
        return incoming ? inCipher : outCipher;
    }

    @Override
    public CompressionInformation getCompressionInformation(boolean incoming) {
        return incoming ? inCompression : outCompression;
    }

    @Override
    public MacInformation getMacInformation(boolean incoming) {
        return incoming ? inMac : outMac;
    }

    @Override
    public boolean isAuthenticated() {
        return authed;
    }

    @Override
    public void setAuthenticated() throws IOException {
        this.authed = true;
        sendSessionEvent(SessionListener.Event.Authenticated);
    }

    /**
     * <P>Main input point for the MINA framework.</P>
     *
     * <P>
     * This method will be called each time new data is received on
     * the socket and will append it to the input buffer before
     * calling the {@link #decode()} method.
     * </P>
     *
     * @param buffer the new buffer received
     * @throws Exception if an error occurs while decoding or handling the data
     */
    public void messageReceived(Readable buffer) throws Exception {
        synchronized (decodeLock) {
            decoderBuffer.putBuffer(buffer);
            // One of those property will be set by the constructor and the other
            // one should be set by the readIdentification method
            if (clientVersion == null || serverVersion == null) {
                if (readIdentification(decoderBuffer)) {
                    decoderBuffer.compact();
                } else {
                    return;
                }
            }
            decode();
        }
    }

    /**
     * Refresh whatever internal configuration is not {@code final}
     */
    protected void refreshConfiguration() {
        synchronized (random) {
            // re-keying configuration
            maxRekeyBytes = PropertyResolverUtils.getLongProperty(this, FactoryManager.REKEY_BYTES_LIMIT, maxRekeyBytes);
            maxRekeyInterval = PropertyResolverUtils.getLongProperty(this, FactoryManager.REKEY_TIME_LIMIT, maxRekeyInterval);
            maxRekyPackets = PropertyResolverUtils.getLongProperty(this, FactoryManager.REKEY_PACKETS_LIMIT, maxRekyPackets);

            // intermittent SSH_MSG_IGNORE stream padding
            ignorePacketDataLength = PropertyResolverUtils.getIntProperty(this, FactoryManager.IGNORE_MESSAGE_SIZE, FactoryManager.DEFAULT_IGNORE_MESSAGE_SIZE);
            ignorePacketsFrequency = PropertyResolverUtils.getLongProperty(this, FactoryManager.IGNORE_MESSAGE_FREQUENCY, FactoryManager.DEFAULT_IGNORE_MESSAGE_FREQUENCY);
            ignorePacketsVariance = PropertyResolverUtils.getIntProperty(this, FactoryManager.IGNORE_MESSAGE_VARIANCE, FactoryManager.DEFAULT_IGNORE_MESSAGE_VARIANCE);
            if (ignorePacketsVariance >= ignorePacketsFrequency) {
                ignorePacketsVariance = 0;
            }

            ignorePacketsCount.set(calculateNextIgnorePacketCount(random, ignorePacketsFrequency, ignorePacketsVariance));
        }
    }

    /**
     * Abstract method for processing incoming decoded packets.
     * The given buffer will hold the decoded packet, starting from
     * the command byte at the read position.
     *
     * @param buffer The {@link Buffer} containing the packet - it may be
     * re-used to generate the response once request has been decoded
     * @throws Exception if an exception occurs while handling this packet.
     * @see #doHandleMessage(Buffer)
     */
    protected void handleMessage(Buffer buffer) throws Exception {
        try {
            synchronized (lock) {
                doHandleMessage(buffer);
            }
        } catch (Throwable e) {
            DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
            // if have any ongoing KEX notify it about the failure
            if (kexFuture != null) {
                synchronized (kexFuture) {
                    Object value = kexFuture.getValue();
                    if (value == null) {
                        kexFuture.setValue(e);
                    }
                }
            }

            if (e instanceof Exception) {
                throw (Exception) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }
    }

    protected void doHandleMessage(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        if (log.isTraceEnabled()) {
            log.trace("doHandleMessage({}) process {}", this, SshConstants.getCommandMessageName(cmd));
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
                handleDebug(buffer);
                break;
            case SshConstants.SSH_MSG_SERVICE_REQUEST:
                handleServiceRequest(buffer);
                break;
            case SshConstants.SSH_MSG_SERVICE_ACCEPT:
                handleServiceAccept(buffer);
                break;
            case SshConstants.SSH_MSG_KEXINIT:
                handleKexInit(buffer);
                break;
            case SshConstants.SSH_MSG_NEWKEYS:
                handleNewKeys(cmd, buffer);
                break;
            default:
                if ((cmd >= SshConstants.SSH_MSG_KEX_FIRST) && (cmd <= SshConstants.SSH_MSG_KEX_LAST)) {
                    if (firstKexPacketFollows != null) {
                        try {
                            if (!handleFirstKexPacketFollows(cmd, buffer, firstKexPacketFollows.booleanValue())) {
                                break;
                            }
                        } finally {
                            firstKexPacketFollows = null;   // avoid re-checking
                        }
                    }

                    handleKexMessage(cmd, buffer);
                } else if (currentService != null) {
                    currentService.process(cmd, buffer);
                    resetIdleTimeout();
                } else {
                    throw new IllegalStateException("Unsupported command " + SshConstants.getCommandMessageName(cmd));
                }
                break;
        }
        checkRekey();
    }

    protected boolean handleFirstKexPacketFollows(int cmd, Buffer buffer, boolean followFlag) {
        if (!followFlag) {
            return true; // if 1st KEX packet does not follow then process the command
        }

        /*
         * According to RFC4253 section 7.1:
         *
         *      If the other party's guess was wrong, and this field was TRUE,
         *      the next packet MUST be silently ignored
         */
        for (KexProposalOption option : new KexProposalOption[]{KexProposalOption.ALGORITHMS, KexProposalOption.SERVERKEYS}) {
            Pair<String, String> result = comparePreferredKexProposalOption(option);
            if (result != null) {
                if (log.isDebugEnabled()) {
                    log.debug("handleFirstKexPacketFollows({})[{}] 1st follow KEX packet {} option mismatch: client={}, server={}",
                              this, SshConstants.getCommandMessageName(cmd), option, result.getFirst(), result.getSecond());
                }
                return false;
            }
        }

        return true;
    }

    protected Pair<String, String> comparePreferredKexProposalOption(KexProposalOption option) {
        String[] clientPreferences = GenericUtils.split(clientProposal.get(option), ',');
        String clientValue = clientPreferences[0];
        String[] serverPreferences = GenericUtils.split(serverProposal.get(option), ',');
        String serverValue = serverPreferences[0];
        return clientValue.equals(serverValue) ? null : new Pair<>(clientValue, serverValue);
    }

    protected void handleKexMessage(int cmd, Buffer buffer) throws Exception {
        validateKexState(cmd, KexState.RUN);

        if (kex.next(cmd, buffer)) {
            if (log.isDebugEnabled()) {
                log.debug("handleKexMessage({})[{}] KEX processing complete after cmd={}", this, kex.getName(), cmd);
            }
            checkKeys();
            sendNewKeys();
            kexState.set(KexState.KEYS);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("handleKexMessage({})[{}] more KEX packets expected after cmd={}", this, kex.getName(), cmd);
            }
        }
    }

    @Override
    public IoWriteFuture sendIgnoreMessage(byte... data) throws IOException {
        data = (data == null) ? GenericUtils.EMPTY_BYTE_ARRAY : data;
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_IGNORE, data.length + Byte.SIZE);
        buffer.putBytes(data);
        return writePacket(buffer);
    }

    protected void handleIgnore(Buffer buffer) throws Exception {
        ReservedSessionMessagesHandler handler = resolveReservedSessionMessagesHandler();
        handler.handleIgnoreMessage(this, buffer);
    }

    protected void handleUnimplemented(Buffer buffer) throws Exception {
        handleUnimplemented(buffer.getInt(), buffer);
    }

    protected void handleUnimplemented(int seqNo, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleUnimplented({}) SSH_MSG_UNIMPLEMENTED #{}", this, seqNo);
        }

        if (log.isTraceEnabled()) {
            log.trace("handleUnimplemented({}) data: {}", this, buffer.toHex());
        }
    }

    @Override
    public IoWriteFuture sendDebugMessage(boolean display, Object msg, String lang) throws IOException {
        String text = Objects.toString(msg);
        lang = (lang == null) ? "" : lang;

        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DEBUG,
                text.length() + lang.length() + Integer.SIZE /* a few extras */);
        buffer.putBoolean(display);
        buffer.putString(text);
        buffer.putString(lang);
        return writePacket(buffer);
    }

    protected void handleDebug(Buffer buffer) throws Exception {
        ReservedSessionMessagesHandler handler = resolveReservedSessionMessagesHandler();
        handler.handleDebugMessage(this, buffer);
    }

    protected ReservedSessionMessagesHandler resolveReservedSessionMessagesHandler() {
        ReservedSessionMessagesHandler handler = getReservedSessionMessagesHandler();
        return (handler == null) ? ReservedSessionMessagesHandlerAdapter.DEFAULT : handler;
    }

    protected void handleDisconnect(Buffer buffer) throws Exception  {
        handleDisconnect(buffer.getInt(), buffer.getString(), buffer.getString(), buffer);
    }

    protected void handleDisconnect(int code, String msg, String lang, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleDisconnect({}) SSH_MSG_DISCONNECT reason={}, [lang={}] msg={}",
                      this, SshConstants.getDisconnectReasonName(code), lang, msg);
        }

        close(true);
    }

    protected void handleServiceRequest(Buffer buffer) throws Exception {
        handleServiceRequest(buffer.getString(), buffer);
    }

    protected void handleServiceRequest(String serviceName, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleServiceRequest({}) SSH_MSG_SERVICE_REQUEST '{}'", this, serviceName);
        }
        validateKexState(SshConstants.SSH_MSG_SERVICE_REQUEST, KexState.DONE);
        try {
            startService(serviceName);
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("handleServiceRequest({}) Service {} rejected: {} = {}",
                          this, serviceName, e.getClass().getSimpleName(), e.getMessage());
            }

            if (log.isTraceEnabled()) {
                log.trace("handleServiceRequest(" + this + ") service=" + serviceName + " rejection details", e);
            }
            disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + serviceName);
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("handleServiceRequest({}) Accepted service {}", this, serviceName);
        }

        Buffer response = createBuffer(SshConstants.SSH_MSG_SERVICE_ACCEPT, Byte.SIZE + GenericUtils.length(serviceName));
        response.putString(serviceName);
        writePacket(response);
    }

    protected void handleServiceAccept(Buffer buffer) throws Exception {
        handleServiceAccept(buffer.getString(), buffer);
    }

    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleServiceAccept({}) SSH_MSG_SERVICE_ACCEPT service={}", this, serviceName);
        }
        validateKexState(SshConstants.SSH_MSG_SERVICE_ACCEPT, KexState.DONE);
    }

    protected void handleKexInit(Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleKexInit({}) SSH_MSG_KEXINIT", this);
        }
        receiveKexInit(buffer);
        if (kexState.compareAndSet(KexState.DONE, KexState.RUN)) {
            sendKexInit();
        } else if (!kexState.compareAndSet(KexState.INIT, KexState.RUN)) {
            throw new IllegalStateException("Received SSH_MSG_KEXINIT while key exchange is running");
        }

        Map<KexProposalOption, String> result = negotiate();
        String kexAlgorithm = result.get(KexProposalOption.ALGORITHMS);
        kex = ValidateUtils.checkNotNull(NamedFactory.Utils.create(getKeyExchangeFactories(), kexAlgorithm),
                "Unknown negotiated KEX algorithm: %s",
                kexAlgorithm);
        kex.init(this, serverVersion.getBytes(StandardCharsets.UTF_8), clientVersion.getBytes(StandardCharsets.UTF_8), i_s, i_c);
        sendSessionEvent(SessionListener.Event.KexCompleted);
    }

    protected void handleNewKeys(int cmd, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleNewKeys({}) SSH_MSG_NEWKEYS command={}", this, SshConstants.getCommandMessageName(cmd));
        }
        validateKexState(cmd, KexState.KEYS);
        receiveNewKeys();

        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
        if (kexFuture != null) {
            synchronized (kexFuture) {
                Object value = kexFuture.getValue();
                if (value == null) {
                    kexFuture.setValue(Boolean.TRUE);
                }
            }
        }

        sendSessionEvent(SessionListener.Event.KeyEstablished);
        synchronized (pendingPackets) {
            if (!pendingPackets.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("handleNewKeys({}) Dequeing {} pending packets", this, pendingPackets.size());
                }
                synchronized (encodeLock) {
                    PendingWriteFuture future;
                    while ((future = pendingPackets.poll()) != null) {
                        doWritePacket(future.getBuffer()).addListener(future);
                    }
                }
            }
            kexState.set(KexState.DONE);
        }

        synchronized (lock) {
            lock.notifyAll();
        }
    }

    protected void validateKexState(int cmd, KexState expected) {
        KexState actual = kexState.get();
        if (!expected.equals(actual)) {
            throw new IllegalStateException("Received KEX command=" + SshConstants.getCommandMessageName(cmd)
                                          + " while in state=" + actual + " instead of " + expected);
        }
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

        SessionListener listener = getSessionListenerProxy();
        try {
            listener.sessionException(this, t);
        } catch (Throwable err) {
            Throwable e = GenericUtils.peelException(err);
            if (log.isDebugEnabled()) {
                log.debug("exceptionCaught(" + this + ") signal session exception details", e);
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("exceptionCaught(" + this + ") suppressed session exception signalling", s);
                    }
                }
            }
        }

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

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .parallel(getServices())
                .close(ioSession)
                .build();
    }

    @Override
    protected void preClose() {
        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
        if (kexFuture != null) {
            // if have any pending KEX then notify it about the closing session
            synchronized (kexFuture) {
                Object value = kexFuture.getValue();
                if (value == null) {
                    kexFuture.setValue(new SshException("Session closing while KEX in progress"));
                }
            }
        }

        // if anyone waiting for global response notify them about the closing session
        synchronized (requestResult) {
            requestResult.set(GenericUtils.NULL);
            requestResult.notify();
        }

        // Fire 'close' event
        SessionListener listener = getSessionListenerProxy();
        try {
            listener.sessionClosed(this);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn("preClose({}) {} while signal session closed: {}", this, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("preClose(" + this + ") signal session closed exception details", e);
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("preClose(" + this + ") suppressed session closed signalling", s);
                    }
                }
            }
        } finally {
            // clear the listeners since we are closing the session (quicker GC)
            this.sessionListeners.clear();
            this.channelListeners.clear();
        }

        super.preClose();
    }

    protected List<Service> getServices() {
        return (currentService != null)
              ? Collections.singletonList(currentService)
              : Collections.<Service>emptyList();
    }

    @Override
    public <T extends Service> T getService(Class<T> clazz) {
        for (Service s : getServices()) {
            if (clazz.isInstance(s)) {
                return clazz.cast(s);
            }
        }
        throw new IllegalStateException("Attempted to access unknown service " + clazz.getSimpleName());
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        // While exchanging key, queue high level packets
        if (!KexState.DONE.equals(kexState.get())) {
            byte cmd = buffer.array()[buffer.rpos()];
            if (cmd > SshConstants.SSH_MSG_KEX_LAST) {
                synchronized (pendingPackets) {
                    if (!KexState.DONE.equals(kexState.get())) {
                        if (pendingPackets.isEmpty()) {
                            log.debug("writePacket({})[{}] Start flagging packets as pending until key exchange is done",
                                      this, SshConstants.getCommandMessageName(cmd & 0xFF));
                        }
                        PendingWriteFuture future = new PendingWriteFuture(buffer);
                        pendingPackets.add(future);
                        return future;
                    }
                }
            }
        }

        try {
            return doWritePacket(buffer);
        } finally {
            resetIdleTimeout();
            checkRekey();
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public IoWriteFuture writePacket(Buffer buffer, final long timeout, final TimeUnit unit) throws IOException {
        final IoWriteFuture writeFuture = writePacket(buffer);
        final DefaultSshFuture<IoWriteFuture> future = (DefaultSshFuture<IoWriteFuture>) writeFuture;
        ScheduledExecutorService executor = factoryManager.getScheduledExecutorService();
        final ScheduledFuture<?> sched = executor.schedule(new Runnable() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
                    Throwable t = new TimeoutException("Timeout writing packet: " + timeout + " " + unit);
                    if (log.isDebugEnabled()) {
                        log.debug("writePacket({}): {}", AbstractSession.this, t.getMessage());
                    }
                    future.setValue(t);
                }
            }, timeout, unit);
        future.addListener(new SshFutureListener<IoWriteFuture>() {
                @Override
                public void operationComplete(IoWriteFuture future) {
                    sched.cancel(false);
                }
            });
        return writeFuture;
    }

    protected IoWriteFuture doWritePacket(Buffer buffer) throws IOException {
        Buffer ignoreBuf = null;
        int ignoreDataLen = resolveIgnoreBufferDataLength();
        if (ignoreDataLen > 0) {
            ignoreBuf = createBuffer(SshConstants.SSH_MSG_IGNORE, ignoreDataLen + Byte.SIZE);
            ignoreBuf.putInt(ignoreDataLen);

            int wpos = ignoreBuf.wpos();
            synchronized (random) {
                random.fill(ignoreBuf.array(), wpos, ignoreDataLen);
            }
            ignoreBuf.wpos(wpos + ignoreDataLen);

            if (log.isDebugEnabled()) {
                log.debug("doWritePacket({}) append SSH_MSG_IGNORE message", this);
            }
        }

        int curPos = buffer.rpos();
        byte[] data = buffer.array();
        int cmd = data[curPos] & 0xFF;  // usually the 1st byte is the command
        buffer = validateTargetBuffer(cmd, buffer);

        // Synchronize all write requests as needed by the encoding algorithm
        // and also queue the write request in this synchronized block to ensure
        // packets are sent in the correct order
        synchronized (encodeLock) {
            if (ignoreBuf != null) {
                encode(ignoreBuf);
                ioSession.write(ignoreBuf);
            }

            encode(buffer);
            return ioSession.write(buffer);
        }
    }

    protected int resolveIgnoreBufferDataLength() {
        if ((ignorePacketDataLength <= 0) || (ignorePacketsFrequency <= 0L) || (ignorePacketsVariance < 0)) {
            return 0;
        }

        long count = ignorePacketsCount.decrementAndGet();
        if (count > 0L) {
            return 0;
        }

        synchronized (random) {
            ignorePacketsCount.set(calculateNextIgnorePacketCount(random, ignorePacketsFrequency, ignorePacketsVariance));
            return ignorePacketDataLength + random.random(ignorePacketDataLength);
        }
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

    @Override
    public Buffer request(String request, Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        ValidateUtils.checkTrue(timeout > 0L, "Non-positive timeout requested: %d", timeout);

        long maxWaitMillis = TimeUnit.MILLISECONDS.convert(timeout, unit);
        if (maxWaitMillis <= 0L) {
            throw new IllegalArgumentException("Requested timeout for " + request + " below 1 msec: " + timeout + " " + unit);
        }

        if (log.isDebugEnabled()) {
            log.debug("request({}) request={}, timeout={} {}", this, request, timeout, unit);
        }

        Object result;
        synchronized (requestLock) {
            try {
                writePacket(buffer);

                synchronized (requestResult) {
                    while (isOpen() && (maxWaitMillis > 0L) && (requestResult.get() == null)) {
                        if (log.isTraceEnabled()) {
                            log.trace("request({})[{}] remaining wait={}", this, request, maxWaitMillis);
                        }

                        long waitStart = System.nanoTime();
                        requestResult.wait(maxWaitMillis);
                        long waitEnd = System.nanoTime();
                        long waitDuration = waitEnd - waitStart;
                        long waitMillis = TimeUnit.NANOSECONDS.toMillis(waitDuration);
                        if (waitMillis > 0L) {
                            maxWaitMillis -= waitMillis;
                        } else {
                            maxWaitMillis--;
                        }
                    }

                    result = requestResult.getAndSet(null);
                }
            } catch (InterruptedException e) {
                throw (InterruptedIOException) new InterruptedIOException("Interrupted while waiting for request=" + request + " result").initCause(e);
            }
        }

        if (!isOpen()) {
            throw new IOException("Session is closed or closing while awaiting reply for request=" + request);
        }

        if (log.isDebugEnabled()) {
            log.debug("request({}) request={}, timeout={} {}, result received={}",
                      this, request, timeout, unit, result != null);
        }

        if (result == null) {
            throw new SocketTimeoutException("No response received after " + timeout + " " + unit + " for request=" + request);
        }

        if (result instanceof Buffer) {
            return (Buffer) result;
        }

        return null;
    }

    @Override
    public Buffer createBuffer(byte cmd) {
        return createBuffer(cmd, 0);
    }

    @Override
    public Buffer createBuffer(byte cmd, int len) {
        if (len <= 0) {
            return prepareBuffer(cmd, new ByteArrayBuffer());
        }

        // Since the caller claims to know how many bytes they will need
        // increase their request to account for our headers/footers if
        // they actually send exactly this amount.
        //
        int bsize = outCipherSize;
        len += SshConstants.SSH_PACKET_HEADER_LEN;
        int pad = (-len) & (bsize - 1);
        if (pad < bsize) {
            pad += bsize;
        }
        len = len + pad - 4;
        if (outMac != null) {
            len += outMac.getBlockSize();
        }

        return prepareBuffer(cmd, new ByteArrayBuffer(new byte[len + Byte.SIZE], false));
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
     * Makes sure that the buffer used for output is not {@code null} or one
     * of the session's internal ones used for decoding and uncompressing
     *
     * @param <B> The {@link Buffer} type being validated
     * @param cmd The most likely command this buffer refers to (not guaranteed to be correct)
     * @param buffer The buffer to be examined
     * @return The validated target instance - default same as input
     * @throws IllegalArgumentException if any of the conditions is violated
     */
    protected <B extends Buffer> B validateTargetBuffer(int cmd, B buffer) {
        ValidateUtils.checkNotNull(buffer, "No target buffer to examine for command=%d", cmd);
        ValidateUtils.checkTrue(buffer != decoderBuffer, "Not allowed to use the internal decoder buffer for command=%d", cmd);
        ValidateUtils.checkTrue(buffer != uncompressBuffer, "Not allowed to use the internal uncompress buffer for command=%d", cmd);
        return buffer;
    }

    /**
     * Encode a buffer into the SSH protocol.
     * This method need to be called into a synchronized block around encodeLock
     *
     * @param buffer the buffer to encode
     * @throws IOException if an exception occurs during the encoding process
     */
    protected void encode(Buffer buffer) throws IOException {
        try {
            // Check that the packet has some free space for the header
            int curPos = buffer.rpos();
            if (curPos < SshConstants.SSH_PACKET_HEADER_LEN) {
                byte[] data = buffer.array();
                int cmd = data[curPos] & 0xFF;  // usually the 1st byte is an SSH opcode
                log.warn("encode({}) command={} performance cost: available buffer packet header length ({}) below min. required ({})",
                         this, SshConstants.getCommandMessageName(cmd), curPos, SshConstants.SSH_PACKET_HEADER_LEN);
                Buffer nb = new ByteArrayBuffer(buffer.available() + Long.SIZE, false);
                nb.wpos(SshConstants.SSH_PACKET_HEADER_LEN);
                nb.putBuffer(buffer);
                buffer = nb;
                curPos = buffer.rpos();
            }

            // Grab the length of the packet (excluding the 5 header bytes)
            int len = buffer.available();
            int off = curPos - SshConstants.SSH_PACKET_HEADER_LEN;
            // Debug log the packet
            if (log.isTraceEnabled()) {
                buffer.dumpHex(getSimplifiedLogger(), "encode(" + this + ") packet #" + seqo, this);
            }

            // Compress the packet if needed
            if ((outCompression != null) && outCompression.isCompressionExecuted() && (authed || (!outCompression.isDelayed()))) {
                outCompression.compress(buffer);
                len = buffer.available();
            }

            // Compute padding length
            int bsize = outCipherSize;
            int oldLen = len;
            len += SshConstants.SSH_PACKET_HEADER_LEN;
            int pad = (-len) & (bsize - 1);
            if (pad < bsize) {
                pad += bsize;
            }
            len = len + pad - 4;
            // Write 5 header bytes
            buffer.wpos(off);
            buffer.putInt(len);
            buffer.putByte((byte) pad);
            // Fill padding
            buffer.wpos(off + oldLen + SshConstants.SSH_PACKET_HEADER_LEN + pad);
            synchronized (random) {
                random.fill(buffer.array(), buffer.wpos() - pad, pad);
            }

            // Compute mac
            if (outMac != null) {
                int macSize = outMac.getBlockSize();
                int l = buffer.wpos();
                buffer.wpos(l + macSize);
                outMac.updateUInt(seqo);
                outMac.update(buffer.array(), off, l);
                outMac.doFinal(buffer.array(), l);
            }
            // Encrypt packet, excluding mac
            if (outCipher != null) {
                outCipher.update(buffer.array(), off, len + 4);

                int blocksCount = (len + 4) / outCipher.getBlockSize();
                outBlocksCount.addAndGet(Math.max(1, blocksCount));
            }
            // Increment packet id
            seqo = (seqo + 1) & 0xffffffffL;
            // Update stats
            outPacketsCount.incrementAndGet();
            outBytesCount.addAndGet(len);
            // Make buffer ready to be read
            buffer.rpos(off);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    /**
     * Decode the incoming buffer and handle packets as needed.
     *
     * @throws Exception If failed to decode
     */
    protected void decode() throws Exception {
        // Decoding loop
        for (;;) {
            // Wait for beginning of packet
            if (decoderState == 0) {
                // The read position should always be 0 at this point because we have compacted this buffer
                assert decoderBuffer.rpos() == 0;
                // If we have received enough bytes, start processing those
                if (decoderBuffer.available() > inCipherSize) {
                    // Decrypt the first bytes
                    if (inCipher != null) {
                        inCipher.update(decoderBuffer.array(), 0, inCipherSize);

                        int blocksCount = inCipherSize / inCipher.getBlockSize();
                        inBlocksCount.addAndGet(Math.max(1, blocksCount));
                    }
                    // Read packet length
                    decoderLength = decoderBuffer.getInt();
                    // Check packet length validity
                    if ((decoderLength < SshConstants.SSH_PACKET_HEADER_LEN) || (decoderLength > (256 * 1024))) {
                        log.warn("decode({}) Error decoding packet(invalid length): {}", this, decoderLength);
                        decoderBuffer.dumpHex(getSimplifiedLogger(), "decode(" + this + ") invalid length packet", this);
                        throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                                "Invalid packet length: " + decoderLength);
                    }
                    // Ok, that's good, we can go to the next step
                    decoderState = 1;
                } else {
                    // need more data
                    break;
                }
                // We have received the beginning of the packet
            } else if (decoderState == 1) {
                // The read position should always be 4 at this point
                assert decoderBuffer.rpos() == 4;
                int macSize = inMac != null ? inMac.getBlockSize() : 0;
                // Check if the packet has been fully received
                if (decoderBuffer.available() >= (decoderLength + macSize)) {
                    byte[] data = decoderBuffer.array();
                    // Decrypt the remaining of the packet
                    if (inCipher != null) {
                        int updateLen = decoderLength + 4 - inCipherSize;
                        inCipher.update(data, inCipherSize, updateLen);

                        int blocksCount = updateLen / inCipher.getBlockSize();
                        inBlocksCount.addAndGet(Math.max(1, blocksCount));
                    }
                    // Check the mac of the packet
                    if (inMac != null) {
                        // Update mac with packet id
                        inMac.updateUInt(seqi);
                        // Update mac with packet data
                        inMac.update(data, 0, decoderLength + 4);
                        // Compute mac result
                        inMac.doFinal(inMacResult, 0);
                        // Check the computed result with the received mac (just after the packet data)
                        if (!BufferUtils.equals(inMacResult, 0, data, decoderLength + 4, macSize)) {
                            throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "MAC Error");
                        }
                    }
                    // Increment incoming packet sequence number
                    seqi = (seqi + 1) & 0xffffffffL;
                    // Get padding
                    int pad = decoderBuffer.getUByte();
                    Buffer packet;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if ((inCompression != null) && inCompression.isCompressionExecuted() && (authed || (!inCompression.isDelayed()))) {
                        if (uncompressBuffer == null) {
                            uncompressBuffer = new SessionWorkBuffer(this);
                        } else {
                            uncompressBuffer.forceClear();
                        }

                        decoderBuffer.wpos(decoderBuffer.rpos() + decoderLength - 1 - pad);
                        inCompression.uncompress(decoderBuffer, uncompressBuffer);
                        packet = uncompressBuffer;
                    } else {
                        decoderBuffer.wpos(decoderLength + 4 - pad);
                        packet = decoderBuffer;
                    }

                    if (log.isTraceEnabled()) {
                        packet.dumpHex(getSimplifiedLogger(), "decode(" + this + ") packet #" + seqi, this);
                    }

                    // Update stats
                    inPacketsCount.incrementAndGet();
                    inBytesCount.addAndGet(packet.available());
                    // Process decoded packet
                    handleMessage(packet);
                    // Set ready to handle next packet
                    decoderBuffer.rpos(decoderLength + 4 + macSize);
                    decoderBuffer.wpos(wpos);
                    decoderBuffer.compact();
                    decoderState = 0;
                } else {
                    // need more data
                    break;
                }
            }
        }
    }

    /**
     * Resolves the identification to send to the peer session by consulting
     * the associated {@link FactoryManager}. If a value is set, then it is
     * <U>appended</U> to the standard {@link #DEFAULT_SSH_VERSION_PREFIX}.
     * Otherwise a default value is returned consisting of the prefix and
     * the core artifact name + version in <U>uppercase</U> - e.g.,'
     * &quot;SSH-2.0-SSHD-CORE-1.2.3.4&quot;
     *
     * @param configPropName The property used to query the factory manager
     * @return The resolved identification value
     */
    protected String resolveIdentificationString(String configPropName) {
        FactoryManager manager = getFactoryManager();
        String ident = PropertyResolverUtils.getString(manager, configPropName);
        return DEFAULT_SSH_VERSION_PREFIX + (GenericUtils.isEmpty(ident) ? manager.getVersion() : ident);
    }

    /**
     * Send our identification.
     *
     * @param ident our identification to send
     * @return {@link IoWriteFuture} that can be used to wait for notification
     * that identification has been send
     */
    protected IoWriteFuture sendIdentification(String ident) {
        byte[] data = (ident + "\r\n").getBytes(StandardCharsets.UTF_8);
        if (log.isDebugEnabled()) {
            log.debug("sendIdentification({}): {}", this, ident.replace('\r', '|').replace('\n', '|'));
        }
        return ioSession.write(new ByteArrayBuffer(data));
    }

    /**
     * Read the other side identification.
     * This method is specific to the client or server side, but both should call
     * {@link #doReadIdentification(Buffer, boolean)} and
     * store the result in the needed property.
     *
     * @param buffer The {@link Buffer} containing the remote identification
     * @return <code>true</code> if the identification has been fully read or
     * <code>false</code> if more data is needed
     * @throws IOException if an error occurs such as a bad protocol version
     */
    protected abstract boolean readIdentification(Buffer buffer) throws IOException;

    /**
     * Read the remote identification from this buffer.
     * If more data is needed, the buffer will be reset to its original state
     * and a {@code null} value will be returned.  Else the identification
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
        for (byte[] data = new byte[MAX_VERSION_LINE_LENGTH];;) {
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
                NamedResource.Utils.getNames(
                        ValidateUtils.checkNotNullAndNotEmpty(getKeyExchangeFactories(), "No KEX factories")));
        proposal.put(KexProposalOption.SERVERKEYS, hostKeyTypes);

        String ciphers = NamedResource.Utils.getNames(
                ValidateUtils.checkNotNullAndNotEmpty(getCipherFactories(), "No cipher factories"));
        proposal.put(KexProposalOption.S2CENC, ciphers);
        proposal.put(KexProposalOption.C2SENC, ciphers);

        String macs = NamedResource.Utils.getNames(
                ValidateUtils.checkNotNullAndNotEmpty(getMacFactories(), "No MAC factories"));
        proposal.put(KexProposalOption.S2CMAC, macs);
        proposal.put(KexProposalOption.C2SMAC, macs);

        String compressions = NamedResource.Utils.getNames(
                ValidateUtils.checkNotNullAndNotEmpty(getCompressionFactories(), "No compression factories"));
        proposal.put(KexProposalOption.S2CCOMP, compressions);
        proposal.put(KexProposalOption.C2SCOMP, compressions);

        proposal.put(KexProposalOption.S2CLANG, "");    // TODO allow configuration
        proposal.put(KexProposalOption.C2SLANG, "");    // TODO allow configuration
        return proposal;
    }

    /**
     * Send the key exchange initialization packet.
     * This packet contains random data along with our proposal.
     *
     * @param proposal our proposal for key exchange negotiation
     * @return the sent packet data which must be kept for later use
     * when deriving the session keys
     * @throws IOException if an error occurred sending the packet
     */
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendKexInit({}) Send SSH_MSG_KEXINIT", this);
        }
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + SshConstants.MSG_KEX_COOKIE_SIZE);
        synchronized (random) {
            random.fill(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE);
        }
        if (log.isTraceEnabled()) {
            log.trace("sendKexInit({}) cookie={}",
                      this, BufferUtils.toHex(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            String s = proposal.get(paramType);
            if (log.isTraceEnabled()) {
                log.trace("sendKexInit(}|)[{}] {}", this, paramType.getDescription(), s);
            }
            buffer.putString(GenericUtils.trimToEmpty(s));
        }

        buffer.putBoolean(false);   // first kex packet follows
        buffer.putInt(0);   // reserved (FFU)
        byte[] data = buffer.getCompactData();
        writePacket(buffer);
        return data;
    }

    /**
     * Receive the remote key exchange init message.
     * The packet data is returned for later use.
     *
     * @param buffer   the {@link Buffer} containing the key exchange init packet
     * @param proposal the remote proposal to fill
     * @return the packet data
     */
    protected byte[] receiveKexInit(Buffer buffer, Map<KexProposalOption, String> proposal) {
        // Recreate the packet payload which will be needed at a later time
        byte[] d = buffer.array();
        byte[] data = new byte[buffer.available() + 1 /* the opcode */];
        data[0] = SshConstants.SSH_MSG_KEXINIT;

        int size = 6;
        int cookieStartPos = buffer.rpos();
        System.arraycopy(d, cookieStartPos, data, 1, data.length - 1);
        // Skip random cookie data
        buffer.rpos(cookieStartPos + SshConstants.MSG_KEX_COOKIE_SIZE);
        size += SshConstants.MSG_KEX_COOKIE_SIZE;
        if (log.isTraceEnabled()) {
            log.trace("receiveKexInit({}) cookie={}",
                      this, BufferUtils.toHex(d, cookieStartPos, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        // Read proposal
        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            int lastPos = buffer.rpos();
            String value = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("receiveKexInit({})[{}] {}", this, paramType.getDescription(), value);
            }
            int curPos = buffer.rpos();
            int readLen = curPos - lastPos;
            proposal.put(paramType, value);
            size += readLen;
        }

        firstKexPacketFollows = buffer.getBoolean();
        if (log.isTraceEnabled()) {
            log.trace("receiveKexInit({}) first kex packet follows: {}", this, firstKexPacketFollows);
        }

        long reserved = buffer.getUInt();
        if (reserved != 0) {
            if (log.isTraceEnabled()) {
                log.trace("receiveKexInit({}) non-zero reserved value: {}", this, reserved);
            }
        }

        // Return data
        byte[] dataShrinked = new byte[size];
        System.arraycopy(data, 0, dataShrinked, 0, size);
        return dataShrinked;
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

    /**
     * Put new keys into use.
     * This method will initialize the ciphers, digests, macs and compression
     * according to the negotiated server and client proposals.
     *
     * @throws Exception if an error occurs
     */
    protected void receiveNewKeys() throws Exception {
        byte[] k = kex.getK();
        byte[] h = kex.getH();
        Digest hash = kex.getHash();

        if (sessionId == null) {
            sessionId = h.clone();
            if (log.isDebugEnabled()) {
                log.debug("receiveNewKeys({}) session ID={}", this, BufferUtils.toHex(':', sessionId));
            }
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putMPInt(k);
        buffer.putRawBytes(h);
        buffer.putByte((byte) 0x41);
        buffer.putRawBytes(sessionId);

        int pos = buffer.available();
        byte[] buf = buffer.array();
        hash.update(buf, 0, pos);

        byte[] iv_c2s = hash.digest();
        int j = pos - sessionId.length - 1;

        buf[j]++;
        hash.update(buf, 0, pos);
        byte[] iv_s2c = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        byte[] e_c2s = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        byte[] e_s2c = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        byte[] mac_c2s = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        byte[] mac_s2c = hash.digest();

        String value = getNegotiatedKexParameter(KexProposalOption.S2CENC);
        Cipher s2ccipher = ValidateUtils.checkNotNull(NamedFactory.Utils.create(getCipherFactories(), value), "Unknown s2c cipher: %s", value);
        e_s2c = resizeKey(e_s2c, s2ccipher.getBlockSize(), hash, k, h);
        s2ccipher.init(isServer ? Cipher.Mode.Encrypt : Cipher.Mode.Decrypt, e_s2c, iv_s2c);

        value = getNegotiatedKexParameter(KexProposalOption.S2CMAC);
        Mac s2cmac = NamedFactory.Utils.create(getMacFactories(), value);
        if (s2cmac == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown s2c MAC: " + value);
        }
        mac_s2c = resizeKey(mac_s2c, s2cmac.getBlockSize(), hash, k, h);
        s2cmac.init(mac_s2c);

        value = getNegotiatedKexParameter(KexProposalOption.S2CCOMP);
        Compression s2ccomp = NamedFactory.Utils.create(getCompressionFactories(), value);
        if (s2ccomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown s2c compression: " + value);
        }

        value = getNegotiatedKexParameter(KexProposalOption.C2SENC);
        Cipher c2scipher = ValidateUtils.checkNotNull(NamedFactory.Utils.create(getCipherFactories(), value), "Unknown c2s cipher: %s", value);
        e_c2s = resizeKey(e_c2s, c2scipher.getBlockSize(), hash, k, h);
        c2scipher.init(isServer ? Cipher.Mode.Decrypt : Cipher.Mode.Encrypt, e_c2s, iv_c2s);

        value = getNegotiatedKexParameter(KexProposalOption.C2SMAC);
        Mac c2smac = NamedFactory.Utils.create(getMacFactories(), value);
        if (c2smac == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown c2s MAC: " + value);
        }
        mac_c2s = resizeKey(mac_c2s, c2smac.getBlockSize(), hash, k, h);
        c2smac.init(mac_c2s);

        value = getNegotiatedKexParameter(KexProposalOption.C2SCOMP);
        Compression c2scomp = NamedFactory.Utils.create(getCompressionFactories(), value);
        if (c2scomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown c2s compression: " + value);
        }

        if (isServer) {
            outCipher = s2ccipher;
            outMac = s2cmac;
            outCompression = s2ccomp;
            inCipher = c2scipher;
            inMac = c2smac;
            inCompression = c2scomp;
        } else {
            outCipher = c2scipher;
            outMac = c2smac;
            outCompression = c2scomp;
            inCipher = s2ccipher;
            inMac = s2cmac;
            inCompression = s2ccomp;
        }
        outCipherSize = outCipher.getIVSize();
        // TODO add support for configurable compression level
        outCompression.init(Compression.Type.Deflater, -1);

        inCipherSize = inCipher.getIVSize();
        inMacResult = new byte[inMac.getBlockSize()];
        // TODO add support for configurable compression level
        inCompression.init(Compression.Type.Inflater, -1);

        // see https://tools.ietf.org/html/rfc4344#section-3.2
        int inBlockSize = inCipher.getBlockSize();
        int outBlockSize = outCipher.getBlockSize();
        // select the lowest cipher size
        int avgCipherBlockSize = Math.min(inBlockSize, outBlockSize);
        long recommendedByteRekeyBlocks = 1L << Math.min((avgCipherBlockSize * Byte.SIZE) / 4, 63);    // in case (block-size / 4) > 63
        maxRekeyBlocks.set(PropertyResolverUtils.getLongProperty(this, FactoryManager.REKEY_BLOCKS_LIMIT, recommendedByteRekeyBlocks));
        if (log.isDebugEnabled()) {
            log.debug("receiveNewKeys({}) inCipher={}, outCipher={}, recommended blocks limit={}, actual={}",
                      this, inCipher, outCipher, recommendedByteRekeyBlocks, maxRekeyBlocks);
        }

        inBytesCount.set(0L);
        outBytesCount.set(0L);
        inPacketsCount.set(0L);
        outPacketsCount.set(0L);
        inBlocksCount.set(0L);
        outBlocksCount.set(0L);
        lastKeyTimeValue.set(System.currentTimeMillis());
        firstKexPacketFollows = null;
    }

    /**
     * Method used while putting new keys into use that will resize the key used to
     * initialize the cipher to the needed length.
     *
     * @param e         the key to resize
     * @param blockSize the cipher block size (in bytes)
     * @param hash      the hash algorithm
     * @param k         the key exchange k parameter
     * @param h         the key exchange h parameter
     * @return the resized key
     * @throws Exception if a problem occur while resizing the key
     */
    protected byte[] resizeKey(byte[] e, int blockSize, Digest hash, byte[] k, byte[] h) throws Exception {
        for (Buffer buffer = null; blockSize > e.length; buffer = BufferUtils.clear(buffer)) {
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

    @Override
    public void disconnect(final int reason, final String msg) throws IOException {
        log.info("Disconnecting({}): {} - {}", this, SshConstants.getDisconnectReasonName(reason), msg);
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DISCONNECT, msg.length() + Short.SIZE);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");   // TODO configure language...

        // Write the packet with a timeout to ensure a timely close of the session
        // in case the consumer does not read packets anymore.
        long disconnectTimeoutMs = PropertyResolverUtils.getLongProperty(this, FactoryManager.DISCONNECT_TIMEOUT, FactoryManager.DEFAULT_DISCONNECT_TIMEOUT);
        writePacket(buffer, disconnectTimeoutMs, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
            @Override
            @SuppressWarnings("synthetic-access")
            public void operationComplete(IoWriteFuture future) {
                Throwable t = future.getException();
                if (log.isDebugEnabled()) {
                    if (t == null) {
                        log.debug("disconnect({}) operation successfully completed for reason={} [{}]",
                                  AbstractSession.this, SshConstants.getDisconnectReasonName(reason), msg);
                    } else {
                        log.debug("disconnect({}) operation failed ({}) for reason={} [{}]: {}",
                                   AbstractSession.this, t.getClass().getSimpleName(),
                                   SshConstants.getDisconnectReasonName(reason), msg, t.getMessage());
                    }
                }

                if (t != null) {
                    if (log.isTraceEnabled()) {
                        log.trace("disconnect(" + AbstractSession.this + ") reason=" + SshConstants.getDisconnectReasonName(reason) + " failure details", t);
                    }
                }

                close(true);
            }
        });
    }

    /**
     * Send a {@code SSH_MSG_UNIMPLEMENTED} packet.  This packet should
     * contain the sequence id of the unsupported packet: this number
     * is assumed to be the last packet received.
     *
     * @return An {@link IoWriteFuture} that can be used to wait for packet write completion
     * @throws IOException if an error occurred sending the packet
     * @see #sendNotImplemented(long)
     */
    protected IoWriteFuture notImplemented() throws IOException {
        return sendNotImplemented(seqi - 1);
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

    /**
     * Compute the negotiated proposals by merging the client and
     * server proposal. The negotiated proposal will also be stored in
     * the {@link #negotiationResult} property.
     *
     * @return The negotiated options {@link Map}
     */
    protected Map<KexProposalOption, String> negotiate() {
        Map<KexProposalOption, String> guess = new EnumMap<>(KexProposalOption.class);
        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            String clientParamValue = clientProposal.get(paramType);
            String serverParamValue = serverProposal.get(paramType);
            String[] c = GenericUtils.split(clientParamValue, ',');
            String[] s = GenericUtils.split(serverParamValue, ',');
            for (String ci : c) {
                for (String si : s) {
                    if (ci.equals(si)) {
                        guess.put(paramType, ci);
                        break;
                    }
                }

                String value = guess.get(paramType);
                if (value != null) {
                    break;
                }
            }

            // check if reached an agreement
            String value = guess.get(paramType);
            if (value == null) {
                String message = "Unable to negotiate key exchange for " + paramType.getDescription()
                        + " (client: " + clientParamValue + " / server: " + serverParamValue + ")";
                // OK if could not negotiate languages
                if (KexProposalOption.S2CLANG.equals(paramType) || KexProposalOption.C2SLANG.equals(paramType)) {
                    if (log.isTraceEnabled()) {
                        log.trace("negotiate({}) {}", this, message);
                    }
                } else {
                    throw new IllegalStateException(message);
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("negotiate(" + this + ")[" + paramType.getDescription() + "] guess=" + value
                            + " (client: " + clientParamValue + " / server: " + serverParamValue + ")");
                }
            }
        }

        return setNegotiationResult(guess);
    }

    protected Map<KexProposalOption, String> setNegotiationResult(Map<KexProposalOption, String> guess) {
        synchronized (negotiationResult) {
            if (!negotiationResult.isEmpty()) {
                negotiationResult.clear(); // debug breakpoint
            }
            negotiationResult.putAll(guess);
        }

        if (log.isDebugEnabled()) {
            log.debug("setNegotiationResult({}) Kex: server->client {} {} {}", this,
                      guess.get(KexProposalOption.S2CENC),
                      guess.get(KexProposalOption.S2CMAC),
                      guess.get(KexProposalOption.S2CCOMP));
            log.debug("setNegotiationResult({}) Kex: client->server {} {} {}", this,
                      guess.get(KexProposalOption.C2SENC),
                      guess.get(KexProposalOption.C2SMAC),
                      guess.get(KexProposalOption.C2SCOMP));
        }

        return guess;
    }

    /**
     * Indicates the reception of a {@code SSH_MSG_REQUEST_SUCCESS} message
     *
     * @param buffer The {@link Buffer} containing the message data
     * @throws Exception If failed to handle the message
     */
    protected void requestSuccess(Buffer buffer) throws Exception {
        // use a copy of the original data in case it is re-used on return
        Buffer resultBuf = ByteArrayBuffer.getCompactClone(buffer.array(), buffer.rpos(), buffer.available());
        synchronized (requestResult) {
            requestResult.set(resultBuf);
            resetIdleTimeout();
            requestResult.notify();
        }
    }

    /**
     * Indicates the reception of a {@code SSH_MSG_REQUEST_FAILURE} message
     *
     * @param buffer The {@link Buffer} containing the message data
     * @throws Exception If failed to handle the message
     */
    protected void requestFailure(Buffer buffer) throws Exception {
        synchronized (requestResult) {
            requestResult.set(GenericUtils.NULL);
            resetIdleTimeout();
            requestResult.notify();
        }
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

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
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

    @Override
    public void addSessionListener(SessionListener listener) {
        ValidateUtils.checkNotNull(listener, "addSessionListener(%s) null instance", this);
        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addSessionListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.sessionListeners.add(listener)) {
            log.trace("addSessionListener({})[{}] registered", this, listener);
        } else {
            log.trace("addSessionListener({})[{}] ignored duplicate", this, listener);
        }
    }

    @Override
    public void removeSessionListener(SessionListener listener) {
        if (this.sessionListeners.remove(listener)) {
            log.trace("removeSessionListener({})[{}] removed", this, listener);
        } else {
            log.trace("removeSessionListener({})[{}] not registered", this, listener);
        }
    }

    @Override
    public SessionListener getSessionListenerProxy() {
        return sessionListenerProxy;
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ValidateUtils.checkNotNull(listener, "addChannelListener(%s) null instance", this);
        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while session is closing", this, listener);
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

    /**
     * Sends a session event to all currently registered session listeners
     *
     * @param event The event to send
     * @throws IOException If any of the registered listeners threw an exception.
     */
    protected void sendSessionEvent(SessionListener.Event event) throws IOException {
        SessionListener listener = getSessionListenerProxy();
        try {
            listener.sessionEvent(this, event);
        } catch (Throwable e) {
            Throwable t = GenericUtils.peelException(e);
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

    @Override
    public KeyExchangeFuture reExchangeKeys() throws IOException {
        requestNewKeysExchange();
        return ValidateUtils.checkNotNull(kexFutureHolder.get(), "No current KEX future on state=%s", kexState.get());
    }

    /**
     * Checks if a re-keying is required and if so initiates it
     *
     * @return A {@link KeyExchangeFuture} to wait for the initiated exchange
     * or {@code null} if no need to re-key or an exchange is already in progress
     * @throws IOException If failed to send the request
     * @see #isRekeyRequired()
     * @see #requestNewKeysExchange()
     */
    protected KeyExchangeFuture checkRekey() throws IOException {
        return isRekeyRequired() ? requestNewKeysExchange() : null;
    }

    /**
     * Initiates a new keys exchange if one not already in progress
     *
     * @return A {@link KeyExchangeFuture} to wait for the initiated exchange
     * or {@code null} if an exchange is already in progress
     * @throws IOException If failed to send the request
     */
    protected KeyExchangeFuture requestNewKeysExchange() throws IOException {
        if (!kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
            if (log.isDebugEnabled()) {
                log.debug("requestNewKeysExchange({}) KEX state not DONE: {}", this, kexState.get());
            }

            return null;
        }

        log.info("requestNewKeysExchange({}) Initiating key re-exchange", this);
        sendKexInit();

        DefaultKeyExchangeFuture newFuture = new DefaultKeyExchangeFuture(null);
        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.getAndSet(newFuture);
        if (kexFuture != null) {
            synchronized (kexFuture) {
                Object value = kexFuture.getValue();
                if (value == null) {
                    kexFuture.setValue(new SshException("New KEX started while previous one still ongoing"));
                }
            }
        }

        return newFuture;
    }

    protected boolean isRekeyRequired() {
        KexState curState = kexState.get();
        if (!KexState.DONE.equals(curState)) {
            return false;
        }

        return isRekeyTimeIntervalExceeded()
            || isRekeyPacketCountsExceeded()
            || isRekeyBlocksCountExceeded()
            || isRekeyDataSizeExceeded();
    }

    protected boolean isRekeyTimeIntervalExceeded() {
        if (maxRekeyInterval <= 0L) {
            return false;   // disabled
        }

        long now = System.currentTimeMillis();
        long rekeyDiff = now - lastKeyTimeValue.get();
        boolean rekey = rekeyDiff > maxRekeyInterval;
        if (rekey) {
            if (log.isDebugEnabled()) {
                log.debug("isRekeyTimeIntervalExceeded({}) re-keying: last={}, now={}, diff={}, max={}",
                          this, new Date(lastKeyTimeValue.get()), new Date(now),
                          rekeyDiff, maxRekeyInterval);
            }
        }

        return rekey;
    }

    protected boolean isRekeyPacketCountsExceeded() {
        if (maxRekyPackets <= 0L) {
            return false;   // disabled
        }

        boolean rekey = (inPacketsCount.get() > maxRekyPackets) || (outPacketsCount.get() > maxRekyPackets);
        if (rekey) {
            if (log.isDebugEnabled()) {
                log.debug("isRekeyPacketCountsExceeded({}) re-keying: in={}, out={}, max={}",
                          this, inPacketsCount, outPacketsCount, maxRekyPackets);
            }
        }

        return rekey;
    }

    protected boolean isRekeyDataSizeExceeded() {
        if (maxRekeyBytes <= 0L) {
            return false;
        }

        boolean rekey = (inBytesCount.get() > maxRekeyBytes) || (outBytesCount.get() > maxRekeyBytes);
        if (rekey) {
            if (log.isDebugEnabled()) {
                log.debug("isRekeyDataSizeExceeded({}) re-keying: in={}, out={}, max={}",
                          this, inBytesCount, outBytesCount, maxRekeyBytes);
            }
        }

        return rekey;
    }

    protected boolean isRekeyBlocksCountExceeded() {
        long maxBlocks = maxRekeyBlocks.get();
        if (maxBlocks <= 0L) {
            return false;
        }

        boolean rekey = (inBlocksCount.get() > maxBlocks) || (outBlocksCount.get() > maxBlocks);
        if (rekey) {
            if (log.isDebugEnabled()) {
                log.debug("isRekeyBlocksCountExceeded({}) re-keying: in={}, out={}, max={}",
                          this, inBlocksCount, outBlocksCount, maxBlocks);
            }
        }

        return rekey;
    }

    protected byte[] sendKexInit() throws IOException {
        String resolvedAlgorithms = resolveAvailableSignaturesProposal();
        if (GenericUtils.isEmpty(resolvedAlgorithms)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
                    "sendKexInit() no resolved signatures available");
        }

        Map<KexProposalOption, String> proposal = createProposal(resolvedAlgorithms);
        byte[] seed = sendKexInit(proposal);
        if (log.isTraceEnabled()) {
            log.trace("sendKexInit({}) proposal={} seed: {}", this, proposal, BufferUtils.toHex(':', seed));
        }
        setKexSeed(seed);
        return seed;
    }

    /**
     * @param seed The result of the KEXINIT handshake - required for correct
     *             session key establishment
     */
    protected abstract void setKexSeed(byte... seed);

    /**
     * @return A comma-separated list of all the signature protocols to be
     * included in the proposal - {@code null}/empty if no proposal
     * @see #getFactoryManager()
     * @see #resolveAvailableSignaturesProposal(FactoryManager)
     */
    protected String resolveAvailableSignaturesProposal() {
        return resolveAvailableSignaturesProposal(getFactoryManager());
    }

    /**
     * @param manager The {@link FactoryManager}
     * @return A comma-separated list of all the signature protocols to be
     * included in the proposal - {@code null}/empty if no proposal
     */
    protected abstract String resolveAvailableSignaturesProposal(FactoryManager manager);

    /**
     * Indicates the the key exchange is completed and the exchanged keys
     * can now be verified - e.g., client can verify the server's key
     *
     * @throws IOException If validation failed
     */
    protected abstract void checkKeys() throws IOException;

    protected void receiveKexInit(Buffer buffer) throws IOException {
        Map<KexProposalOption, String> proposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
        byte[] seed = receiveKexInit(buffer, proposal);
        receiveKexInit(proposal, seed);
    }

    protected abstract void receiveKexInit(Map<KexProposalOption, String> proposal, byte[] seed) throws IOException;

    // returns the proposal argument
    protected Map<KexProposalOption, String> mergeProposals(Map<KexProposalOption, String> current, Map<KexProposalOption, String> proposal) {
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

    /**
     * Checks whether the session has timed out (both auth and idle timeouts are checked).
     * If the session has timed out, a DISCONNECT message will be sent.
     *
     * @throws IOException If failed to check
     * @see #checkAuthenticationTimeout(long, long)
     * @see #checkIdleTimeout(long, long)
     */
    protected void checkForTimeouts() throws IOException {
        if (isClosing()) {
            log.debug("checkForTimeouts({}) session closing", this);
            return;
        }

        long now = System.currentTimeMillis();
        Pair<TimeoutStatus, String> result = checkAuthenticationTimeout(now, getAuthTimeout());
        if (result == null) {
            result = checkIdleTimeout(now, getIdleTimeout());
        }

        TimeoutStatus status = (result == null) ? TimeoutStatus.NoTimeout : result.getFirst();
        if ((status == null) || TimeoutStatus.NoTimeout.equals(status)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("checkForTimeouts({}) disconnect - reason={}", this, status);
        }

        timeoutStatus.set(status);
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, result.getSecond());
    }

    /**
     * Checks if authentication timeout expired
     *
     * @param now           The current time in millis
     * @param authTimeoutMs The configured timeout in millis - if non-positive
     *                      then no timeout
     * @return A {@link Pair} specifying the timeout status and disconnect reason
     * message if timeout expired, {@code null} or {@code NoTimeout} if no timeout
     * occurred
     * @see #getAuthTimeout()
     */
    protected Pair<TimeoutStatus, String> checkAuthenticationTimeout(long now, long authTimeoutMs) {
        long authDiff = now - authTimeoutStart;
        if ((!authed) && (authTimeoutMs > 0L) && (authDiff > authTimeoutMs)) {
            return new Pair<TimeoutStatus, String>(TimeoutStatus.AuthTimeout, "Session has timed out waiting for authentication after " + authTimeoutMs + " ms.");
        } else {
            return null;
        }
    }

    /**
     * Checks if idle timeout expired
     *
     * @param now           The current time in millis
     * @param idleTimeoutMs The configured timeout in millis - if non-positive
     *                      then no timeout
     * @return A {@link Pair} specifying the timeout status and disconnect reason
     * message if timeout expired, {@code null} or {@code NoTimeout} if no timeout
     * occurred
     * @see #getIdleTimeout()
     */
    protected Pair<TimeoutStatus, String> checkIdleTimeout(long now, long idleTimeoutMs) {
        long idleDiff = now - idleTimeoutStart;
        if ((idleTimeoutMs > 0L) && (idleDiff > idleTimeoutMs)) {
            return new Pair<TimeoutStatus, String>(TimeoutStatus.IdleTimeout, "User session has timed out idling after " + idleTimeoutMs + " ms.");
        } else {
            return null;
        }
    }

    @Override
    public void resetIdleTimeout() {
        this.idleTimeoutStart = System.currentTimeMillis();
    }

    @Override
    public TimeoutStatus getTimeoutStatus() {
        return timeoutStatus.get();
    }

    @Override
    public long getAuthTimeout() {
        return PropertyResolverUtils.getLongProperty(this, FactoryManager.AUTH_TIMEOUT, FactoryManager.DEFAULT_AUTH_TIMEOUT);
    }

    @Override
    public long getIdleTimeout() {
        return PropertyResolverUtils.getLongProperty(this, FactoryManager.IDLE_TIMEOUT, FactoryManager.DEFAULT_IDLE_TIMEOUT);
    }

    @Override
    public String toString() {
        IoSession ioSession = getIoSession();
        SocketAddress peerAddress = (ioSession == null) ? null : ioSession.getRemoteAddress();
        return getClass().getSimpleName() + "[" + getUsername() + "@" + peerAddress + "]";
    }
}
