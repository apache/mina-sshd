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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.EnumMap;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongConsumer;
import java.util.logging.Level;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
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
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.GlobalRequestFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.AvailabilityPhase;
import org.apache.sshd.common.kex.extension.KexExtensionHandler.KexPhase;
import org.apache.sshd.common.kex.extension.KexExtensions;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.mac.MacInformation;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.SessionWorkBuffer;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
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

    /*
     * Key exchange support
     */
    protected byte[] sessionId;
    protected String serverVersion;
    protected String clientVersion;
    // if empty then means not-initialized
    protected final Map<KexProposalOption, String> serverProposal = new EnumMap<>(KexProposalOption.class);
    protected final Map<KexProposalOption, String> unmodServerProposal = Collections.unmodifiableMap(serverProposal);
    protected final Map<KexProposalOption, String> clientProposal = new EnumMap<>(KexProposalOption.class);
    protected final Map<KexProposalOption, String> unmodClientProposal = Collections.unmodifiableMap(clientProposal);
    protected final Map<KexProposalOption, String> negotiationResult = new EnumMap<>(KexProposalOption.class);
    protected final Map<KexProposalOption, String> unmodNegotiationResult = Collections.unmodifiableMap(negotiationResult);

    protected KeyExchange kex;
    protected Boolean firstKexPacketFollows;
    protected boolean initialKexDone;
    /**
     * Holds the current key exchange state.
     */
    protected final AtomicReference<KexState> kexState = new AtomicReference<>(KexState.UNKNOWN);
    protected final AtomicReference<DefaultKeyExchangeFuture> kexFutureHolder = new AtomicReference<>(null);

    // The kexInitializedFuture is fulfilled when this side (client or server) has prepared its own proposal. Access is
    // synchronized on kexState.
    protected DefaultKeyExchangeFuture kexInitializedFuture;

    /*
     * SSH packets encoding / decoding support
     */
    protected Cipher outCipher;
    protected Cipher inCipher;
    protected int outCipherSize = 8;
    protected int inCipherSize = 8;
    protected Mac outMac;
    protected Mac inMac;
    protected int outMacSize;
    protected int inMacSize;
    protected byte[] inMacResult;
    protected Compression outCompression;
    protected Compression inCompression;
    /** Input packet sequence number. */
    protected long seqi;
    /** Output packet sequence number. */
    protected long seqo;
    protected SessionWorkBuffer uncompressBuffer;
    protected final SessionWorkBuffer decoderBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    protected final Object decodeLock = new Object();
    protected final Object requestLock = new Object();

    /**
     * The {@link KeyExchangeMessageHandler} instance also serves as lock protecting {@link #kexState} changes from DONE
     * to INIT or RUN, and from KEYS to DONE.
     */
    protected final KeyExchangeMessageHandler kexHandler;

    /*
     * Rekeying
     */
    protected final AtomicLong inPacketsCount = new AtomicLong(0L);
    protected final AtomicLong outPacketsCount = new AtomicLong(0L);
    protected final AtomicLong inBytesCount = new AtomicLong(0L);
    protected final AtomicLong outBytesCount = new AtomicLong(0L);
    protected final AtomicLong inBlocksCount = new AtomicLong(0L);
    protected final AtomicLong outBlocksCount = new AtomicLong(0L);
    protected final AtomicReference<Instant> lastKeyTimeValue = new AtomicReference<>(Instant.now());
    // we initialize them here in case super constructor calls some methods that use these values
    protected long maxRekyPackets;
    protected long maxRekeyBytes;
    protected Duration maxRekeyInterval;

    /**
     * Resulting message coding settings at the end of a key exchange for incoming messages.
     *
     * @see #prepareNewKeys()
     * @see #setInputEncoding()
     */
    protected MessageCodingSettings inSettings;

    /**
     * Resulting message coding settings at the end of a key exchange for outgoing messages.
     *
     * @see #prepareNewKeys()
     * @see #setOutputEncoding()
     */
    protected MessageCodingSettings outSettings;

    protected final CurrentService currentService;

    // SSH_MSG_IGNORE stream padding
    protected int ignorePacketDataLength;
    protected long ignorePacketsFrequency;
    protected int ignorePacketsVariance;

    protected final AtomicLong maxRekeyBlocks
            = new AtomicLong(CoreModuleProperties.REKEY_BYTES_LIMIT.getRequiredDefault() / 16);
    protected final AtomicLong ignorePacketsCount
            = new AtomicLong(CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.getRequiredDefault());

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
     * @see {@link #request(Buffer, String, org.apache.sshd.common.future.GlobalRequestFuture.ReplyHandler)}
     * @see {@link #requestSuccess(Buffer)}
     * @see {@link #requestFailure(Buffer)}
     * @see {@link #doInvokeUnimplementedMessageHandler(int, Buffer)}
     * @see {@link #preClose()}
     */
    private final Deque<GlobalRequestFuture> pendingGlobalRequests = new ConcurrentLinkedDeque<>();

    private final Map<Buffer, LongConsumer> globalSequenceNumbers = new ConcurrentHashMap<>();

    private byte[] clientKexData; // the payload of the client's SSH_MSG_KEXINIT
    private byte[] serverKexData; // the payload of the server's SSH_MSG_KEXINIT

    /**
     * Create a new session.
     *
     * @param serverSession  {@code true} if this is a server session, {@code false} if client one
     * @param factoryManager the factory manager
     * @param ioSession      the underlying I/O session
     */
    protected AbstractSession(boolean serverSession, FactoryManager factoryManager, IoSession ioSession) {
        super(serverSession, factoryManager, ioSession);

        this.decoderBuffer = new SessionWorkBuffer(this);

        kexHandler = Objects.requireNonNull(initializeKeyExchangeMessageHandler(),
                "No KeyExchangeMessageHandler set on the session");
        currentService = Objects.requireNonNull(initializeCurrentService(), "No CurrentService set on the session");

        attachSession(ioSession, this);

        Factory<? extends Random> factory = ValidateUtils.checkNotNull(
                factoryManager.getRandomFactory(), "No random factory for %s", ioSession);
        random = ValidateUtils.checkNotNull(
                factory.create(), "No randomizer instance for %s", ioSession);

        refreshConfiguration();

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
     * Creates a new {@link KeyExchangeMessageHandler} instance managing packet sending for this session.
     * <p>
     * This initialization method is invoked once from the {@link AbstractSession} constructor. Do not rely on subclass
     * fields being initialized.
     * </p>
     *
     * @return a new {@link KeyExchangeMessageHandler} instance for the session
     */
    protected KeyExchangeMessageHandler initializeKeyExchangeMessageHandler() {
        return new KeyExchangeMessageHandler(this, log);
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

    /**
     * @param  len       The packet payload size
     * @param  blockSize The cipher block size
     * @param  etmMode   Whether using &quot;encrypt-then-MAC&quot; mode
     * @return           The required padding length
     */
    public static int calculatePadLength(int len, int blockSize, boolean etmMode) {
        /*
         * Note: according to RFC-4253 section 6:
         *
         * The minimum size of a packet is 16 (or the cipher block size, whichever is larger) bytes (plus 'mac').
         *
         * Since all out ciphers, MAC(s), etc. have a block size > 8 then the minimum size of the packet will be at
         * least 16 due to the padding at the very least - so even packets that contain an opcode with no arguments will
         * be above this value. This avoids an un-necessary call to Math.max(len, 16) for each and every packet
         */

        len++; // the pad length
        if (!etmMode) {
            len += Integer.BYTES;
        }

        /*
         * Note: according to RFC-4253 section 6:
         *
         * Note that the length of the concatenation of 'packet_length', 'padding_length', 'payload', and 'random
         * padding' MUST be a multiple of the cipher block size or 8, whichever is larger.
         *
         * However, we currently do not have ciphers with a block size of less than 8 so we do not take this into
         * account in order to accelerate the calculation and avoiding an un-necessary call to Math.max(blockSize, 8)
         * for each and every packet.
         */
        int pad = (-len) & (blockSize - 1);
        if (pad < blockSize) {
            pad += blockSize;
        }

        return pad;
    }

    @Override
    public String getServerVersion() {
        return serverVersion;
    }

    @Override
    public Map<KexProposalOption, String> getServerKexProposals() {
        return unmodServerProposal;
    }

    @Override
    public String getClientVersion() {
        return clientVersion;
    }

    @Override
    public Map<KexProposalOption, String> getClientKexProposals() {
        return unmodClientProposal;
    }

    @Override
    public KeyExchange getKex() {
        return kex;
    }

    @Override
    public KexState getKexState() {
        return kexState.get();
    }

    @Override
    public byte[] getSessionId() {
        // return a clone to avoid anyone changing the internal value
        return NumberUtils.isEmpty(sessionId) ? sessionId : sessionId.clone();
    }

    @Override
    public Map<KexProposalOption, String> getKexNegotiationResult() {
        return unmodNegotiationResult;
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

    /**
     * <P>
     * Main input point for the MINA framework.
     * </P>
     *
     * <P>
     * This method will be called each time new data is received on the socket and will append it to the input buffer
     * before calling the {@link #decode()} method.
     * </P>
     *
     * @param  buffer    the new buffer received
     * @throws Exception if an error occurs while decoding or handling the data
     */
    public void messageReceived(Readable buffer) throws Exception {
        synchronized (decodeLock) {
            decoderBuffer.putBuffer(buffer);
            // One of those properties will be set by the constructor and the other
            // one should be set by the readIdentification method
            if ((clientVersion == null) || (serverVersion == null)) {
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
            maxRekeyBytes = CoreModuleProperties.REKEY_BYTES_LIMIT.getRequired(this);
            maxRekeyInterval = CoreModuleProperties.REKEY_TIME_LIMIT.getRequired(this);
            maxRekyPackets = CoreModuleProperties.REKEY_PACKETS_LIMIT.getRequired(this);

            // intermittent SSH_MSG_IGNORE stream padding
            ignorePacketDataLength = CoreModuleProperties.IGNORE_MESSAGE_SIZE.getRequired(this);
            ignorePacketsFrequency = CoreModuleProperties.IGNORE_MESSAGE_FREQUENCY.getRequired(this);
            ignorePacketsVariance = CoreModuleProperties.IGNORE_MESSAGE_VARIANCE.getRequired(this);
            if (ignorePacketsVariance >= ignorePacketsFrequency) {
                ignorePacketsVariance = 0;
            }

            long countValue = calculateNextIgnorePacketCount(
                    random, ignorePacketsFrequency, ignorePacketsVariance);
            ignorePacketsCount.set(countValue);
        }
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
        try {
            ThreadUtils.runAsInternal(() -> {
                doHandleMessage(buffer);
                return null;
            });
        } catch (Throwable e) {
            DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
            // if have any ongoing KEX notify it about the failure
            if (kexFuture != null) {
                kexFuture.setValue(e);
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
        if (log.isDebugEnabled()) {
            log.debug("doHandleMessage({}) process #{} {}", this, seqi - 1,
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
            case KexExtensions.SSH_MSG_EXT_INFO:
                handleKexExtension(cmd, buffer);
                break;
            case KexExtensions.SSH_MSG_NEWCOMPRESS:
                handleNewCompression(cmd, buffer);
                break;
            default:
                if ((cmd >= SshConstants.SSH_MSG_KEX_FIRST) && (cmd <= SshConstants.SSH_MSG_KEX_LAST)) {
                    if (firstKexPacketFollows != null) {
                        try {
                            if (!handleFirstKexPacketFollows(cmd, buffer, firstKexPacketFollows)) {
                                break;
                            }
                        } finally {
                            firstKexPacketFollows = null; // avoid re-checking
                        }
                    }

                    handleKexMessage(cmd, buffer);
                } else if (currentService.process(cmd, buffer)) {
                    resetIdleTimeout();
                } else {
                    /*
                     * According to https://tools.ietf.org/html/rfc4253#section-11.4
                     *
                     * An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message
                     * in the order in which the messages were received.
                     */
                    if (log.isDebugEnabled()) {
                        log.debug("process({}) Unsupported command: {}",
                                this, SshConstants.getCommandMessageName(cmd));
                    }
                    notImplemented(cmd, buffer);
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
         * If the other party's guess was wrong, and this field was TRUE, the next packet MUST be silently ignored
         */
        boolean debugEnabled = log.isDebugEnabled();
        for (KexProposalOption option : KexProposalOption.FIRST_KEX_PACKET_GUESS_MATCHES) {
            Map.Entry<String, String> result = comparePreferredKexProposalOption(option);
            if (result != null) {
                if (debugEnabled) {
                    log.debug(
                            "handleFirstKexPacketFollows({})[{}] 1st follow KEX packet {} option mismatch: client={}, server={}",
                            this, SshConstants.getCommandMessageName(cmd), option, result.getKey(), result.getValue());
                }
                return false;
            }
        }

        return true;
    }

    /**
     * Compares the specified {@link KexProposalOption} option value for client vs. server
     *
     * @param  option The option to check
     * @return        {@code null} if option is equal, otherwise a key/value pair where key=client option value and
     *                value=the server-side one
     */
    protected Map.Entry<String, String> comparePreferredKexProposalOption(KexProposalOption option) {
        String[] clientPreferences = GenericUtils.split(clientProposal.get(option), ',');
        String clientValue = GenericUtils.isEmpty(clientPreferences) ? null : clientPreferences[0];
        String[] serverPreferences = GenericUtils.split(serverProposal.get(option), ',');
        String serverValue = GenericUtils.isEmpty(serverPreferences) ? null : serverPreferences[0];
        if (GenericUtils.isEmpty(clientValue) || GenericUtils.isEmpty(serverValue)
                || (!Objects.equals(clientValue, serverValue))) {
            return new SimpleImmutableEntry<>(clientValue, serverValue);
        }

        return null;
    }

    /**
     * Send a message to put new keys into use.
     *
     * @return           An {@link IoWriteFuture} that can be used to wait and check the result of sending the packet
     * @throws Exception if an error occurs sending the message
     */
    protected IoWriteFuture sendNewKeys() throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("sendNewKeys({}) Send SSH_MSG_NEWKEYS", this);
        }

        prepareNewKeys();
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_NEWKEYS, Byte.SIZE);
        IoWriteFuture future;
        synchronized (encodeLock) {
            // writePacket() would also work since it would never try to queue the packet, and would never try to
            // initiate a new KEX, and thus would never try to get the kexLock monitor. If it did, we might get a
            // deadlock due to lock inversion. It seems safer to push this out directly, though.
            future = doWritePacket(buffer);
            // Use the new settings from now on for any outgoing packet
            setOutputEncoding();
        }
        kexHandler.updateState(() -> kexState.set(KexState.KEYS));

        resetIdleTimeout();
        /*
         * According to https://tools.ietf.org/html/rfc8308#section-2.4:
         *
         *
         * If a client sends SSH_MSG_EXT_INFO, it MUST send it as the next packet following the client's first
         * SSH_MSG_NEWKEYS message to the server.
         *
         * If a server sends SSH_MSG_EXT_INFO, it MAY send it at zero, one, or both of the following opportunities:
         *
         * + As the next packet following the server's first SSH_MSG_NEWKEYS.
         */
        KexExtensionHandler extHandler = getKexExtensionHandler();
        if ((extHandler != null) && extHandler.isKexExtensionsAvailable(this, AvailabilityPhase.NEWKEYS)) {
            extHandler.sendKexExtensions(this, KexPhase.NEWKEYS);
        }

        SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture> flushDone = kexHandler.terminateKeyExchange();

        // Flush the queue asynchronously.
        int numPending = flushDone.getKey().intValue();
        if (numPending == 0) {
            if (log.isDebugEnabled()) {
                log.debug("handleNewKeys({}) No pending packets to flush at end of KEX", this);
            }
            flushDone.getValue().setValue(Boolean.TRUE);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("handleNewKeys({}) {} pending packets to flush at end of KEX", this, numPending);
            }
            kexHandler.flushQueue(flushDone.getValue());
        }

        return future;
    }

    protected void handleKexMessage(int cmd, Buffer buffer) throws Exception {
        validateKexState(cmd, KexState.RUN);

        boolean debugEnabled = log.isDebugEnabled();
        if (kex.next(cmd, buffer)) {
            if (debugEnabled) {
                log.debug("handleKexMessage({})[{}] KEX processing complete after cmd={}",
                        this, kex.getName(), cmd);
            }
            checkKeys();
            sendNewKeys();
        } else {
            if (debugEnabled) {
                log.debug("handleKexMessage({})[{}] more KEX packets expected after cmd={}",
                        this, kex.getName(), cmd);
            }
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
        KexState state = kexState.get();
        if (!validateServiceKexState(state)) {
            throw new IllegalStateException(
                    "Received " + SshConstants.getCommandMessageName(SshConstants.SSH_MSG_SERVICE_REQUEST)
                                            + " while in KEX state=" + state);
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

    protected boolean validateServiceKexState(KexState state) {
        if (KexState.DONE.equals(state)) {
            return true;
        } else if (KexState.INIT.equals(state)) {
            // Allow service requests that were "in flight" when we sent our own KEX_INIT. We will send back the accept
            // only after KEX is done. However, we will refuse a service request before the initial KEX.
            return initialKexDone;
        }
        return false;
    }

    protected void handleServiceAccept(Buffer buffer) throws Exception {
        handleServiceAccept(buffer.getString(), buffer);
    }

    protected void handleServiceAccept(String serviceName, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleServiceAccept({}) SSH_MSG_SERVICE_ACCEPT service={}", this, serviceName);
        }
        KexState state = kexState.get();
        if (!validateServiceKexState(state)) {
            throw new IllegalStateException(
                    "Received " + SshConstants.getCommandMessageName(SshConstants.SSH_MSG_SERVICE_REQUEST)
                                            + " while in KEX state=" + state);
        }
    }

    protected void handleKexInit(Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleKexInit({}) SSH_MSG_KEXINIT", this);
        }
        receiveKexInit(buffer);
        doKexNegotiation();
    }

    private enum KexStart {
        PEER,
        BOTH,
        ONGOING
    }

    protected void doKexNegotiation() throws Exception {
        KexStart starting = kexHandler.updateState(() -> {
            if (kexState.compareAndSet(KexState.DONE, KexState.RUN)) {
                kexHandler.initNewKeyExchange();
                return KexStart.PEER;
            } else if (kexState.compareAndSet(KexState.INIT, KexState.RUN)) {
                return KexStart.BOTH;
            }
            return KexStart.ONGOING;
        });

        switch (starting) {
            case PEER:
                sendKexInit();
                break;
            case BOTH:
                DefaultKeyExchangeFuture initFuture;
                synchronized (kexState) {
                    initFuture = kexInitializedFuture;
                    if (initFuture == null) {
                        initFuture = new DefaultKeyExchangeFuture(toString(), null);
                        kexInitializedFuture = initFuture;
                    }
                }
                // requestNewKeyExchange() is running in some other thread: wait until it has set up our own proposal.
                // The timeout is a last resort only to avoid blocking indefinitely in case something goes
                // catastrophically wrong somewhere; it should never be hit. If it is, an exception will be thrown.
                //
                // See https://issues.apache.org/jira/browse/SSHD-1197
                initFuture.await(CoreModuleProperties.KEX_PROPOSAL_SETUP_TIMEOUT.getRequired(this));
                break;
            default:
                throw new IllegalStateException("Received SSH_MSG_KEXINIT while key exchange is running");
        }

        Map<KexProposalOption, String> result = negotiate();
        String kexAlgorithm = result.get(KexProposalOption.ALGORITHMS);
        Collection<? extends KeyExchangeFactory> kexFactories = getKeyExchangeFactories();
        KeyExchangeFactory kexFactory = NamedResource.findByName(
                kexAlgorithm, String.CASE_INSENSITIVE_ORDER, kexFactories);
        ValidateUtils.checkNotNull(kexFactory, "Unknown negotiated KEX algorithm: %s", kexAlgorithm);

        byte[] v_s = serverVersion.getBytes(StandardCharsets.UTF_8);
        byte[] v_c = clientVersion.getBytes(StandardCharsets.UTF_8);
        byte[] i_s;
        byte[] i_c;
        synchronized (kexState) {
            i_s = getServerKexData();
            i_c = getClientKexData();
        }

        kex = kexFactory.createKeyExchange(this);
        kex.init(v_s, v_c, i_s, i_c);

        synchronized (kexState) {
            kexInitializedFuture = null;
        }
        signalSessionEvent(SessionListener.Event.KexCompleted);
    }

    protected void handleNewKeys(int cmd, Buffer buffer) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleNewKeys({}) SSH_MSG_NEWKEYS command={}",
                    this, SshConstants.getCommandMessageName(cmd));
        }
        validateKexState(cmd, KexState.KEYS);
        // It is guaranteed that we handle the peer's SSH_MSG_NEWKEYS after having sent our own.
        // prepareNewKeys() was already called in sendNewKeys().
        //
        // From now on, use the new settings for any incoming message.
        setInputEncoding();

        synchronized (kexState) {
            kexInitializedFuture = null;
        }

        initialKexDone = true;
        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
        if (kexFuture != null) {
            kexFuture.setValue(Boolean.TRUE);
        }

        signalSessionEvent(SessionListener.Event.KeyEstablished);

        kexHandler.updateState(() -> {
            kex = null; // discard and GC since KEX is completed
            kexState.set(KexState.DONE);
        });

        synchronized (futureLock) {
            futureLock.notifyAll();
        }
    }

    protected void validateKexState(int cmd, KexState expected) {
        KexState actual = kexState.get();
        if (!expected.equals(actual)) {
            throw new IllegalStateException("Received KEX command=" + SshConstants.getCommandMessageName(cmd)
                                            + " while in state=" + actual + " instead of " + expected);
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
        DefaultKeyExchangeFuture initFuture;
        synchronized (kexState) {
            initFuture = kexInitializedFuture;
        }
        if (initFuture != null) {
            initFuture.setValue(new SshException("Session closing while KEX in progress"));
        }
        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.get();
        if (kexFuture != null) {
            // if have any pending KEX then notify it about the closing session
            kexFuture.setValue(new SshException("Session closing while KEX in progress"));
        }
        kexHandler.shutdown();

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
            future.fail("Session is closing");
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
    protected Buffer preProcessEncodeBuffer(int cmd, Buffer buffer) throws IOException {
        buffer = super.preProcessEncodeBuffer(cmd, buffer);
        // SSHD-968 - remember global request outgoing sequence number
        LongConsumer setter = globalSequenceNumbers.remove(buffer);
        if (setter != null) {
            setter.accept(seqo);
        }
        return buffer;
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        return kexHandler.writePacket(buffer, 0, null);
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        long timeoutMillis = unit.toMillis(timeout);
        IoWriteFuture writeFuture;
        try {
            long start = System.currentTimeMillis();
            writeFuture = kexHandler.writePacket(buffer, timeout, unit);
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

    // NOTE: must acquire encodeLock when calling this method
    protected Buffer resolveOutputPacket(Buffer buffer) throws IOException {
        Buffer ignoreBuf = null;
        int ignoreDataLen = resolveIgnoreBufferDataLength();
        if (ignoreDataLen > 0) {
            ignoreBuf = createBuffer(SshConstants.SSH_MSG_IGNORE, ignoreDataLen + Byte.SIZE);
            ignoreBuf.putUInt(ignoreDataLen);

            int wpos = ignoreBuf.wpos();
            synchronized (random) {
                random.fill(ignoreBuf.array(), wpos, ignoreDataLen);
            }
            ignoreBuf.wpos(wpos + ignoreDataLen);

            if (log.isDebugEnabled()) {
                log.debug("resolveOutputPacket({}) append SSH_MSG_IGNORE message", this);
            }
        }

        int curPos = buffer.rpos();
        byte[] data = buffer.array();
        int cmd = data[curPos] & 0xFF; // usually the 1st byte is the command
        buffer = validateTargetBuffer(cmd, buffer);

        if (ignoreBuf != null) {
            ignoreBuf = encode(ignoreBuf);

            IoSession networkSession = getIoSession();
            networkSession.writeBuffer(ignoreBuf);
        }

        return encode(buffer);
    }

    protected IoWriteFuture doWritePacket(Buffer buffer) throws IOException {
        // Synchronize all write requests as needed by the encoding algorithm
        // and also queue the write request in this synchronized block to ensure
        // packets are sent in the correct order
        synchronized (encodeLock) {
            Buffer packet = resolveOutputPacket(buffer);
            IoSession networkSession = getIoSession();
            IoWriteFuture future = networkSession.writeBuffer(packet);
            return future;
        }
    }

    protected int resolveIgnoreBufferDataLength() {
        if ((ignorePacketDataLength <= 0)
                || (ignorePacketsFrequency <= 0L)
                || (ignorePacketsVariance < 0)) {
            return 0;
        }

        long count = ignorePacketsCount.decrementAndGet();
        if (count > 0L) {
            return 0;
        }

        synchronized (random) {
            count = calculateNextIgnorePacketCount(
                    random, ignorePacketsFrequency, ignorePacketsVariance);
            ignorePacketsCount.set(count);
            return ignorePacketDataLength + random.random(ignorePacketDataLength);
        }
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
                    future.fail(SshConstants.getCommandMessageName(cmd));
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
            return prepareBuffer(cmd, new ByteArrayBuffer());
        }

        // Since the caller claims to know how many bytes they will need
        // increase their request to account for our headers/footers if
        // they actually send exactly this amount.
        boolean etmMode = outMac != null && outMac.isEncryptThenMac();
        int authLen = outCipher != null ? outCipher.getAuthenticationTagSize() : 0;
        boolean authMode = authLen > 0;
        int pad = calculatePadLength(len, outCipherSize, etmMode || authMode);
        len += SshConstants.SSH_PACKET_HEADER_LEN + pad + authLen;
        if (outMac != null) {
            len += outMacSize;
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
     * Makes sure that the buffer used for output is not {@code null} or one of the session's internal ones used for
     * decoding and uncompressing
     *
     * @param  <B>                      The {@link Buffer} type being validated
     * @param  cmd                      The most likely command this buffer refers to (not guaranteed to be correct)
     * @param  buffer                   The buffer to be examined
     * @return                          The validated target instance - default same as input
     * @throws IllegalArgumentException if any of the conditions is violated
     */
    protected <B extends Buffer> B validateTargetBuffer(int cmd, B buffer) {
        ValidateUtils.checkNotNull(buffer, "No target buffer to examine for command=%d", cmd);
        ValidateUtils.checkTrue(
                buffer != decoderBuffer, "Not allowed to use the internal decoder buffer for command=%d", cmd);
        ValidateUtils.checkTrue(
                buffer != uncompressBuffer, "Not allowed to use the internal uncompress buffer for command=%d", cmd);
        return buffer;
    }

    /**
     * Encode a buffer into the SSH protocol. <B>Note:</B> This method must be called inside a {@code synchronized}
     * block using {@code encodeLock}.
     *
     * @param  buffer      the buffer to encode
     * @return             The encoded buffer - may be different than original if input buffer does not have enough room
     *                     for {@link SshConstants#SSH_PACKET_HEADER_LEN}, in which case a substitute buffer will be
     *                     created and used.
     * @throws IOException if an exception occurs during the encoding process
     */
    protected Buffer encode(Buffer buffer) throws IOException {
        try {
            // Check that the packet has some free space for the header
            int curPos = buffer.rpos();
            int cmd = buffer.rawByte(curPos) & 0xFF; // usually the 1st byte is an SSH opcode
            Buffer nb = preProcessEncodeBuffer(cmd, buffer);
            if (nb != buffer) {
                buffer = nb;
                curPos = buffer.rpos();

                int newCmd = buffer.rawByte(curPos) & 0xFF;
                if (cmd != newCmd) {
                    log.warn("encode({}) - command changed from {}[{}] to {}[{}] by pre-processor",
                            this, cmd, SshConstants.getCommandMessageName(cmd),
                            newCmd, SshConstants.getCommandMessageName(newCmd));
                    cmd = newCmd;
                }
            }

            // Grab the length of the packet (excluding the 5 header bytes)
            int len = buffer.available();
            if (log.isDebugEnabled()) {
                log.debug("encode({}) packet #{} sending command={}[{}] len={}",
                        this, seqo, cmd, SshConstants.getCommandMessageName(cmd), len);
            }

            int off = curPos - SshConstants.SSH_PACKET_HEADER_LEN;
            // Debug log the packet
            boolean traceEnabled = log.isTraceEnabled();
            if (traceEnabled) {
                buffer.dumpHex(getSimplifiedLogger(), Level.FINEST,
                        "encode(" + this + ") packet #" + seqo, this);
            }

            // Compress the packet if needed
            if ((outCompression != null)
                    && outCompression.isCompressionExecuted()
                    && (isAuthenticated() || (!outCompression.isDelayed()))) {
                int oldLen = len;
                outCompression.compress(buffer);
                len = buffer.available();
                if (traceEnabled) {
                    log.trace("encode({}) packet #{} command={}[{}] compressed {} -> {}",
                            this, seqo, cmd, SshConstants.getCommandMessageName(cmd), oldLen, len);
                }
            }

            // Compute padding length
            boolean etmMode = outMac != null && outMac.isEncryptThenMac();
            int authSize = outCipher != null ? outCipher.getAuthenticationTagSize() : 0;
            boolean authMode = authSize > 0;
            int oldLen = len;

            int pad = calculatePadLength(len, outCipherSize, etmMode || authMode);

            len += Byte.BYTES + pad;

            if (traceEnabled) {
                log.trace("encode({}) packet #{} command={}[{}] len={}, pad={}, mac={}",
                        this, seqo, cmd, SshConstants.getCommandMessageName(cmd), len, pad, outMac);
            }

            // Write 5 header bytes
            buffer.wpos(off);
            buffer.putUInt(len);
            buffer.putByte((byte) pad);
            // Make sure enough room for padding and then fill it
            buffer.wpos(off + oldLen + SshConstants.SSH_PACKET_HEADER_LEN + pad);
            synchronized (random) {
                random.fill(buffer.array(), buffer.wpos() - pad, pad);
            }

            if (authMode) {
                int wpos = buffer.wpos();
                buffer.wpos(wpos + authSize);
                aeadOutgoingBuffer(buffer, off, len);
            } else if (etmMode) {
                // Do not encrypt the length field
                encryptOutgoingBuffer(buffer, off + Integer.BYTES, len);
                appendOutgoingMac(buffer, off, len);
            } else {
                appendOutgoingMac(buffer, off, len);
                encryptOutgoingBuffer(buffer, off, len + Integer.BYTES);
            }

            // Increment packet id
            seqo = (seqo + 1L) & 0x0ffffffffL;

            // Update counters used to track re-keying
            outPacketsCount.incrementAndGet();
            outBytesCount.addAndGet(len);

            // Make buffer ready to be read
            buffer.rpos(off);
            return buffer;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    protected void aeadOutgoingBuffer(Buffer buf, int offset, int len) throws Exception {
        if (outCipher == null || outCipher.getAuthenticationTagSize() == 0) {
            throw new IllegalArgumentException("AEAD mode requires an AEAD cipher");
        }
        byte[] data = buf.array();
        outCipher.updateWithAAD(data, offset, Integer.BYTES, len);
        int blocksCount = len / outCipherSize;
        outBlocksCount.addAndGet(Math.max(1, blocksCount));
    }

    protected void appendOutgoingMac(Buffer buf, int offset, int len) throws Exception {
        if (outMac == null) {
            return;
        }

        int l = buf.wpos();
        // ensure enough room for MAC in outgoing buffer
        buf.wpos(l + outMacSize);
        // Include sequence number
        outMac.updateUInt(seqo);
        // Include the length field in the MAC calculation
        outMac.update(buf.array(), offset, len + Integer.BYTES);
        // Append MAC to end of packet
        outMac.doFinal(buf.array(), l);
    }

    protected void encryptOutgoingBuffer(Buffer buf, int offset, int len) throws Exception {
        if (outCipher == null) {
            return;
        }
        outCipher.update(buf.array(), offset, len);

        int blocksCount = len / outCipherSize;
        outBlocksCount.addAndGet(Math.max(1, blocksCount));
    }

    /**
     * Decode the incoming buffer and handle packets as needed.
     *
     * @throws Exception If failed to decode
     */
    protected void decode() throws Exception {
        // Decoding loop
        for (;;) {

            int authSize = inCipher != null ? inCipher.getAuthenticationTagSize() : 0;
            boolean authMode = authSize > 0;
            int macSize = inMac != null ? inMacSize : 0;
            boolean etmMode = inMac != null && inMac.isEncryptThenMac();
            // Wait for beginning of packet
            if (decoderState == 0) {
                // The read position should always be 0 at this point because we have compacted this buffer
                assert decoderBuffer.rpos() == 0;
                /*
                 * Note: according to RFC-4253 section 6:
                 *
                 * Implementations SHOULD decrypt the length after receiving the first 8 (or cipher block size whichever
                 * is larger) bytes
                 *
                 * However, we currently do not have ciphers with a block size of less than 8 we avoid un-necessary
                 * Math.max(minBufLen, 8) for each and every packet
                 */
                int minBufLen = etmMode || authMode ? Integer.BYTES : inCipherSize;
                // If we have received enough bytes, start processing those
                if (decoderBuffer.available() > minBufLen) {
                    if (authMode) {
                        // RFC 5647: packet length encoded in additional data
                        inCipher.updateAAD(decoderBuffer.array(), 0, Integer.BYTES);
                    } else if ((inCipher != null) && (!etmMode)) {
                        // Decrypt the first bytes so we can extract the packet length
                        inCipher.update(decoderBuffer.array(), 0, inCipherSize);

                        int blocksCount = inCipherSize / inCipher.getCipherBlockSize();
                        inBlocksCount.addAndGet(Math.max(1, blocksCount));
                    }
                    // Read packet length
                    decoderLength = decoderBuffer.getInt();
                    /*
                     * Check packet length validity - we allow 8 times the minimum required packet length support in
                     * order to be aligned with some OpenSSH versions that allow up to 256k
                     */
                    if ((decoderLength < SshConstants.SSH_PACKET_HEADER_LEN)
                            || (decoderLength > (8 * SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT))) {
                        log.warn("decode({}) Error decoding packet(invalid length): {}", this, decoderLength);
                        decoderBuffer.dumpHex(getSimplifiedLogger(), Level.FINEST,
                                "decode(" + this + ") invalid length packet", this);
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
                // The read position should always be after reading the packet length at this point
                assert decoderBuffer.rpos() == Integer.BYTES;
                // Check if the packet has been fully received
                if (decoderBuffer.available() >= (decoderLength + macSize + authSize)) {
                    byte[] data = decoderBuffer.array();
                    if (authMode) {
                        inCipher.update(data, Integer.BYTES /* packet length is handled by AAD */, decoderLength);

                        int blocksCount = decoderLength / inCipherSize;
                        inBlocksCount.addAndGet(Math.max(1, blocksCount));
                    } else if (etmMode) {
                        validateIncomingMac(data, 0, decoderLength + Integer.BYTES);

                        if (inCipher != null) {
                            inCipher.update(data, Integer.BYTES /* packet length is unencrypted */, decoderLength);

                            int blocksCount = decoderLength / inCipherSize;
                            inBlocksCount.addAndGet(Math.max(1, blocksCount));
                        }
                    } else {
                        /*
                         * Decrypt the remaining of the packet - skip the block we already decoded in order to extract
                         * the packet length
                         */
                        if (inCipher != null) {
                            int updateLen = decoderLength + Integer.BYTES - inCipherSize;
                            inCipher.update(data, inCipherSize, updateLen);

                            int blocksCount = updateLen / inCipherSize;
                            inBlocksCount.addAndGet(Math.max(1, blocksCount));
                        }

                        validateIncomingMac(data, 0, decoderLength + Integer.BYTES);
                    }

                    // Increment incoming packet sequence number
                    seqi = (seqi + 1L) & 0x0ffffffffL;

                    // Get padding
                    int pad = decoderBuffer.getUByte();
                    Buffer packet;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if ((inCompression != null)
                            && inCompression.isCompressionExecuted()
                            && (isAuthenticated() || (!inCompression.isDelayed()))) {
                        if (uncompressBuffer == null) {
                            uncompressBuffer = new SessionWorkBuffer(this);
                        } else {
                            uncompressBuffer.forceClear(true);
                        }

                        decoderBuffer.wpos(decoderBuffer.rpos() + decoderLength - 1 - pad);
                        inCompression.uncompress(decoderBuffer, uncompressBuffer);
                        packet = uncompressBuffer;
                    } else {
                        decoderBuffer.wpos(decoderLength + Integer.BYTES - pad);
                        packet = decoderBuffer;
                    }

                    if (log.isTraceEnabled()) {
                        packet.dumpHex(getSimplifiedLogger(), Level.FINEST,
                                "decode(" + this + ") packet #" + seqi, this);
                    }

                    // Update counters used to track re-keying
                    inPacketsCount.incrementAndGet();
                    inBytesCount.addAndGet(packet.available());

                    // Process decoded packet
                    handleMessage(packet);

                    // Set ready to handle next packet
                    decoderBuffer.rpos(decoderLength + Integer.BYTES + macSize + authSize);
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

    protected void validateIncomingMac(byte[] data, int offset, int len) throws Exception {
        if (inMac == null) {
            return;
        }

        // Update mac with packet id
        inMac.updateUInt(seqi);
        // Update mac with packet data
        inMac.update(data, offset, len);
        // Compute mac result
        inMac.doFinal(inMacResult, 0);

        // Check the computed result with the received mac (just after the packet data)
        if (!Mac.equals(inMacResult, 0, data, offset + len, inMacSize)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "MAC Error");
        }
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
     * Send the key exchange initialization packet. This packet contains random data along with our proposal.
     *
     * @param  proposal  our proposal for key exchange negotiation
     * @return           the sent packet data which must be kept for later use when deriving the session keys
     * @throws Exception if an error occurred sending the packet
     */
    protected byte[] sendKexInit(Map<KexProposalOption, String> proposal) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("sendKexInit({}) Send SSH_MSG_KEXINIT", this);
        }

        Buffer buffer = createBuffer(SshConstants.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + SshConstants.MSG_KEX_COOKIE_SIZE);
        synchronized (random) {
            random.fill(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE);
        }

        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("sendKexInit({}) cookie={}",
                    this, BufferUtils.toHex(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            String s = proposal.get(paramType);
            if (traceEnabled) {
                log.trace("sendKexInit({})[{}] {}", this, paramType.getDescription(), s);
            }
            buffer.putString(GenericUtils.trimToEmpty(s));
        }

        buffer.putBoolean(false); // first kex packet follows
        buffer.putUInt(0L); // reserved (FFU)

        ReservedSessionMessagesHandler handler = getReservedSessionMessagesHandler();
        IoWriteFuture future = (handler == null) ? null : handler.sendKexInitRequest(this, proposal, buffer);
        byte[] data = buffer.getCompactData();
        if (future == null) {
            writePacket(buffer);
        } else {
            if (debugEnabled) {
                log.debug("sendKexInit({}) KEX handled by reserved messages handler", this);
            }
        }

        return data;
    }

    /**
     * Receive the remote key exchange init message. The packet data is returned for later use.
     *
     * @param  buffer    the {@link Buffer} containing the key exchange init packet
     * @param  proposal  the remote proposal to fill
     * @return           the packet data
     * @throws Exception If failed to handle the message
     */
    protected byte[] receiveKexInit(Buffer buffer, Map<KexProposalOption, String> proposal) throws Exception {
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

        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("receiveKexInit({}) cookie={}",
                    this, BufferUtils.toHex(d, cookieStartPos, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        // Read proposal
        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            int lastPos = buffer.rpos();
            String value = buffer.getString();
            if (traceEnabled) {
                log.trace("receiveKexInit({})[{}] {}", this, paramType.getDescription(), value);
            }
            int curPos = buffer.rpos();
            int readLen = curPos - lastPos;
            proposal.put(paramType, value);
            size += readLen;
        }

        KexExtensionHandler extHandler = getKexExtensionHandler();
        if (extHandler != null) {
            if (traceEnabled) {
                log.trace("receiveKexInit({}) options before handler: {}", this, proposal);
            }

            extHandler.handleKexInitProposal(this, false, proposal);

            if (traceEnabled) {
                log.trace("receiveKexInit({}) options after handler: {}", this, proposal);
            }
        }

        firstKexPacketFollows = buffer.getBoolean();
        if (traceEnabled) {
            log.trace("receiveKexInit({}) first kex packet follows: {}", this, firstKexPacketFollows);
        }

        long reserved = buffer.getUInt();
        if (reserved != 0L) {
            if (traceEnabled) {
                log.trace("receiveKexInit({}) non-zero reserved value: {}", this, reserved);
            }
        }

        // Return data
        byte[] dataShrinked = new byte[size];
        System.arraycopy(data, 0, dataShrinked, 0, size);
        return dataShrinked;
    }

    /**
     * Prepares the new ciphers, macs and compression algorithms according to the negotiated server and client proposals
     * and stores them in {@link #inSettings} and {@link #outSettings}. The new settings do not take effect yet; use
     * {@link #setInputEncoding()} or {@link #setOutputEncoding()} for that.
     *
     * @throws Exception if an error occurs
     */
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    protected void prepareNewKeys() throws Exception {
        byte[] k = kex.getK();
        byte[] h = kex.getH();
        Digest hash = kex.getHash();

        boolean debugEnabled = log.isDebugEnabled();
        if (sessionId == null) {
            sessionId = h.clone();
            if (debugEnabled) {
                log.debug("prepareNewKeys({}) session ID={}", this, BufferUtils.toHex(':', sessionId));
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

        boolean serverSession = isServerSession();
        String value = getNegotiatedKexParameter(KexProposalOption.S2CENC);
        Cipher s2ccipher = ValidateUtils.checkNotNull(
                NamedFactory.create(getCipherFactories(), value), "Unknown s2c cipher: %s", value);
        e_s2c = resizeKey(e_s2c, s2ccipher.getKdfSize(), hash, k, h);

        Mac s2cmac;
        if (s2ccipher.getAuthenticationTagSize() == 0) {
            value = getNegotiatedKexParameter(KexProposalOption.S2CMAC);
            s2cmac = NamedFactory.create(getMacFactories(), value);
            if (s2cmac == null) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown s2c MAC: " + value);
            }
            mac_s2c = resizeKey(mac_s2c, s2cmac.getBlockSize(), hash, k, h);
            s2cmac.init(mac_s2c);
        } else {
            s2cmac = null;
        }

        value = getNegotiatedKexParameter(KexProposalOption.S2CCOMP);
        Compression s2ccomp = NamedFactory.create(getCompressionFactories(), value);
        if (s2ccomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown s2c compression: " + value);
        }

        value = getNegotiatedKexParameter(KexProposalOption.C2SENC);
        Cipher c2scipher = ValidateUtils.checkNotNull(
                NamedFactory.create(getCipherFactories(), value), "Unknown c2s cipher: %s", value);
        e_c2s = resizeKey(e_c2s, c2scipher.getKdfSize(), hash, k, h);

        Mac c2smac;
        if (c2scipher.getAuthenticationTagSize() == 0) {
            value = getNegotiatedKexParameter(KexProposalOption.C2SMAC);
            c2smac = NamedFactory.create(getMacFactories(), value);
            if (c2smac == null) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown c2s MAC: " + value);
            }
            mac_c2s = resizeKey(mac_c2s, c2smac.getBlockSize(), hash, k, h);
            c2smac.init(mac_c2s);
        } else {
            c2smac = null;
        }

        value = getNegotiatedKexParameter(KexProposalOption.C2SCOMP);
        Compression c2scomp = NamedFactory.create(getCompressionFactories(), value);
        if (c2scomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown c2s compression: " + value);
        }

        if (serverSession) {
            outSettings = new MessageCodingSettings(s2ccipher, s2cmac, s2ccomp, Cipher.Mode.Encrypt, e_s2c, iv_s2c);
            inSettings = new MessageCodingSettings(c2scipher, c2smac, c2scomp, Cipher.Mode.Decrypt, e_c2s, iv_c2s);
        } else {
            outSettings = new MessageCodingSettings(c2scipher, c2smac, c2scomp, Cipher.Mode.Encrypt, e_c2s, iv_c2s);
            inSettings = new MessageCodingSettings(s2ccipher, s2cmac, s2ccomp, Cipher.Mode.Decrypt, e_s2c, iv_s2c);
        }
    }

    /**
     * Installs the current prepared {@link #outSettings} so that they are effective and will be applied to any future
     * outgoing packet. Clears {@link #outSettings}.
     *
     * @throws Exception on errors
     */
    protected void setOutputEncoding() throws Exception {
        outCipher = outSettings.getCipher(seqo);
        outMac = outSettings.getMac();
        outCompression = outSettings.getCompression();
        outSettings = null;
        outCipherSize = outCipher.getCipherBlockSize();
        outMacSize = outMac != null ? outMac.getBlockSize() : 0;
        // TODO add support for configurable compression level
        outCompression.init(Compression.Type.Deflater, -1);

        maxRekeyBlocks.set(determineRekeyBlockLimit(inCipherSize, outCipherSize));

        outBytesCount.set(0L);
        outPacketsCount.set(0L);
        outBlocksCount.set(0L);

        lastKeyTimeValue.set(Instant.now());
        firstKexPacketFollows = null;

        if (log.isDebugEnabled()) {
            log.debug("setOutputEncoding({}): cipher {}; mac {}; compression {}; blocks limit {}", this, outCipher, outMac,
                    outCompression, maxRekeyBlocks);
        }
    }

    /**
     * Installs the current prepared {@link #inSettings} so that they are effective and will be applied to any future
     * incoming packet. Clears {@link #inSettings}.
     *
     * @throws Exception on errors
     */
    protected void setInputEncoding() throws Exception {
        inCipher = inSettings.getCipher(seqi);
        inMac = inSettings.getMac();
        inCompression = inSettings.getCompression();
        inSettings = null;
        inCipherSize = inCipher.getCipherBlockSize();
        inMacSize = inMac != null ? inMac.getBlockSize() : 0;
        inMacResult = new byte[inMacSize];
        // TODO add support for configurable compression level
        inCompression.init(Compression.Type.Inflater, -1);

        maxRekeyBlocks.set(determineRekeyBlockLimit(inCipherSize, outCipherSize));

        inBytesCount.set(0L);
        inPacketsCount.set(0L);
        inBlocksCount.set(0L);

        lastKeyTimeValue.set(Instant.now());
        firstKexPacketFollows = null;

        if (log.isDebugEnabled()) {
            log.debug("setInputEncoding({}): cipher {}; mac {}; compression {}; blocks limit {}", this, inCipher, inMac,
                    inCompression, maxRekeyBlocks);
        }
    }

    /**
     * Compute the number of blocks after which we should re-key again. See RFC 4344.
     *
     * @param  inCipherBlockSize  block size of the input cipher
     * @param  outCipherBlockSize block size of the output cipher
     * @return                    the number of block after which re-keying occur at the latest
     * @see                       <a href= "https://tools.ietf.org/html/rfc4344#section-3.2">RFC 4344, section 3.2</a>
     */
    protected long determineRekeyBlockLimit(int inCipherBlockSize, int outCipherBlockSize) {
        // see https://tools.ietf.org/html/rfc4344#section-3.2
        // select the lowest cipher size
        long rekeyBlocksLimit = CoreModuleProperties.REKEY_BLOCKS_LIMIT.getRequired(this);
        if (rekeyBlocksLimit <= 0) {
            // Default per RFC 4344
            int minCipherBlockBytes = Math.min(inCipherSize, outCipherSize);
            if (minCipherBlockBytes >= 16) {
                rekeyBlocksLimit = 1L << Math.min(minCipherBlockBytes * 2, 63);
            } else {
                // With a block size of 8 we'd end up with 2^16. That would re-key very often.
                // RFC 4344: "If L is less than 128 [...], then, although it may be too
                // expensive to rekey every 2**(L/4) blocks, it is still advisable for SSH
                // implementations to follow the original recommendation in [RFC4253]: rekey at
                // least once for every gigabyte of transmitted data."
                //
                // Note that chacha20-poly1305 has a block size of 8. The OpenSSH recommendation
                // is: "ChaCha20 must never reuse a {key, nonce} for encryption nor may it be
                // used to encrypt more than 2^70 bytes under the same {key, nonce}. The
                // SSH Transport protocol (RFC4253) recommends a far more conservative
                // rekeying every 1GB of data sent or received. If this recommendation
                // is followed, then chacha20-poly1305@openssh.com requires no special
                // handling in this area."
                rekeyBlocksLimit = (1L << 30) / minCipherBlockBytes; // 1GB
            }
        }
        return rekeyBlocksLimit;
    }

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

        return sendNotImplemented(seqi - 1L);
    }

    /**
     * Compute the negotiated proposals by merging the client and server proposal. The negotiated proposal will also be
     * stored in the {@link #negotiationResult} property.
     *
     * @return           The negotiated options {@link Map}
     * @throws Exception If negotiation failed
     */
    protected Map<KexProposalOption, String> negotiate() throws Exception {
        Map<KexProposalOption, String> c2sOptions = getClientKexProposals();
        Map<KexProposalOption, String> s2cOptions = getServerKexProposals();
        signalNegotiationStart(c2sOptions, s2cOptions);

        Map<KexProposalOption, String> guess = new EnumMap<>(KexProposalOption.class);
        Map<KexProposalOption, String> negotiatedGuess = Collections.unmodifiableMap(guess);
        try {
            boolean debugEnabled = log.isDebugEnabled();
            boolean traceEnabled = log.isTraceEnabled();
            SessionDisconnectHandler discHandler = getSessionDisconnectHandler();
            KexExtensionHandler extHandler = getKexExtensionHandler();
            for (KexProposalOption paramType : KexProposalOption.VALUES) {
                String clientParamValue = c2sOptions.get(paramType);
                String serverParamValue = s2cOptions.get(paramType);
                String[] c = GenericUtils.split(clientParamValue, ',');
                String[] s = GenericUtils.split(serverParamValue, ',');
                /*
                 * According to https://tools.ietf.org/html/rfc8308#section-2.2:
                 *
                 * Implementations MAY disconnect if the counterpart sends an incorrect (KEX extension) indicator
                 *
                 * TODO - for now we do not enforce this
                 */
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
                if (extHandler != null) {
                    extHandler.handleKexExtensionNegotiation(
                            this, paramType, value, c2sOptions, clientParamValue, s2cOptions, serverParamValue);
                }

                if (value != null) {
                    if (traceEnabled) {
                        log.trace("negotiate({})[{}] guess={} (client={} / server={})",
                                this, paramType.getDescription(), value, clientParamValue, serverParamValue);
                    }
                    continue;
                }

                try {
                    if ((discHandler != null)
                            && discHandler.handleKexDisconnectReason(
                                    this, c2sOptions, s2cOptions, negotiatedGuess, paramType)) {
                        if (debugEnabled) {
                            log.debug("negotiate({}) ignore missing value for KEX option={}", this, paramType);
                        }
                        continue;
                    }
                } catch (IOException | RuntimeException e) {
                    // If disconnect handler throws an exception continue with the disconnect
                    debug("negotiate({}) failed ({}) to invoke disconnect handler due to mismatched KEX option={}: {}",
                            this, e.getClass().getSimpleName(), paramType, e.getMessage(), e);
                }

                String message = "Unable to negotiate key exchange for " + paramType.getDescription()
                                 + " (client: " + clientParamValue + " / server: " + serverParamValue + ")";
                // OK if could not negotiate languages
                if (KexProposalOption.S2CLANG.equals(paramType) || KexProposalOption.C2SLANG.equals(paramType)) {
                    if (traceEnabled) {
                        log.trace("negotiate({}) {}", this, message);
                    }
                } else {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, message);
                }
            }

            /*
             * According to https://tools.ietf.org/html/rfc8308#section-2.2:
             *
             * If "ext-info-c" or "ext-info-s" ends up being negotiated as a key exchange method, the parties MUST
             * disconnect.
             */
            String kexOption = guess.get(KexProposalOption.ALGORITHMS);
            if (KexExtensions.IS_KEX_EXTENSION_SIGNAL.test(kexOption)) {
                if ((discHandler != null)
                        && discHandler.handleKexDisconnectReason(
                                this, c2sOptions, s2cOptions, negotiatedGuess, KexProposalOption.ALGORITHMS)) {
                    if (debugEnabled) {
                        log.debug("negotiate({}) ignore violating {} KEX option={}", this, KexProposalOption.ALGORITHMS,
                                kexOption);
                    }
                } else {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            "Illegal KEX option negotiated: " + kexOption);
                }
            }
        } catch (IOException | RuntimeException | Error e) {
            signalNegotiationEnd(c2sOptions, s2cOptions, negotiatedGuess, e);
            throw e;
        }

        signalNegotiationEnd(c2sOptions, s2cOptions, negotiatedGuess, null);
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
            guess.forEach((option, value) -> log.debug("setNegotiationResult({}) Kex: {} = {}", this,
                    option.getDescription(), value));
        }

        return guess;
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
                request.fail(SshConstants.getCommandMessageName(SshConstants.SSH_MSG_REQUEST_FAILURE));
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
            requestNewKeysExchange();
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

        return ValidateUtils.checkNotNull(
                kexFutureHolder.get(), "No current KEX future on state=%s", kexState);
    }

    /**
     * Checks if a re-keying is required and if so initiates it
     *
     * @return           A {@link KeyExchangeFuture} to wait for the initiated exchange or {@code null} if no need to
     *                   re-key or an exchange is already in progress
     * @throws Exception If failed load/generate the keys or send the request
     * @see              #isRekeyRequired()
     * @see              #requestNewKeysExchange()
     */
    protected KeyExchangeFuture checkRekey() throws Exception {
        return isRekeyRequired() ? requestNewKeysExchange() : null;
    }

    /**
     * Initiates a new keys exchange if one not already in progress
     *
     * @return           A {@link KeyExchangeFuture} to wait for the initiated exchange or {@code null} if an exchange
     *                   is already in progress
     * @throws Exception If failed to load/generate the keys or send the request
     */
    protected KeyExchangeFuture requestNewKeysExchange() throws Exception {
        boolean kexRunning = kexHandler.updateState(() -> {
            boolean isRunning = !kexState.compareAndSet(KexState.DONE, KexState.INIT);
            if (!isRunning) {
                kexHandler.initNewKeyExchange();
            }
            return Boolean.valueOf(isRunning);
        }).booleanValue();

        if (kexRunning) {
            if (log.isDebugEnabled()) {
                log.debug("requestNewKeysExchange({}) KEX state not DONE: {}", this, kexState);
            }

            return null;
        }

        log.info("requestNewKeysExchange({}) Initiating key re-exchange", this);

        DefaultKeyExchangeFuture newFuture = new DefaultKeyExchangeFuture(toString(), null);
        DefaultKeyExchangeFuture kexFuture = kexFutureHolder.getAndSet(newFuture);
        if (kexFuture != null) {
            // Should actually never do anything. We don't reset the kexFuture at the end of KEX, and we do check for a
            // running KEX above. The old future should in all cases be fulfilled already.
            kexFuture.setValue(new SshException("New KEX started while previous one still ongoing"));
        }

        sendKexInit();
        return newFuture;
    }

    protected boolean isRekeyRequired() {
        if ((!isOpen()) || isClosing() || isClosed()) {
            return false;
        }

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
        if (GenericUtils.isNegativeOrNull(maxRekeyInterval)) {
            return false; // disabled
        }

        Instant now = Instant.now();
        Duration rekeyDiff = Duration.between(lastKeyTimeValue.get(), now);
        boolean rekey = rekeyDiff.compareTo(maxRekeyInterval) > 0;
        if (rekey) {
            if (log.isDebugEnabled()) {
                log.debug("isRekeyTimeIntervalExceeded({}) re-keying: last={}, now={}, diff={}, max={}",
                        this, lastKeyTimeValue.get(), now, rekeyDiff, maxRekeyInterval);
            }
        }

        return rekey;
    }

    protected boolean isRekeyPacketCountsExceeded() {
        if (maxRekyPackets <= 0L) {
            return false; // disabled
        }

        boolean rekey = (inPacketsCount.get() > maxRekyPackets)
                || (outPacketsCount.get() > maxRekyPackets);
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

    protected byte[] sendKexInit() throws Exception {
        Map<KexProposalOption, String> proposal = getKexProposal();

        byte[] seed;
        synchronized (kexState) {
            DefaultKeyExchangeFuture initFuture = kexInitializedFuture;
            if (initFuture == null) {
                initFuture = new DefaultKeyExchangeFuture(toString(), null);
                kexInitializedFuture = initFuture;
            }
            try {
                seed = sendKexInit(proposal);
                setKexSeed(seed);
                initFuture.setValue(Boolean.TRUE);
            } catch (Exception e) {
                initFuture.setValue(e);
                throw e;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("sendKexInit({}) proposal={} seed: {}", this, proposal, BufferUtils.toHex(':', seed));
        }
        return seed;
    }

    protected byte[] getClientKexData() {
        synchronized (kexState) {
            return (clientKexData == null) ? null : clientKexData.clone();
        }
    }

    protected void setClientKexData(byte[] data) {
        ValidateUtils.checkNotNullAndNotEmpty(data, "No client KEX seed");
        synchronized (kexState) {
            clientKexData = data.clone();
        }
    }

    protected byte[] getServerKexData() {
        synchronized (kexState) {
            return (serverKexData == null) ? null : serverKexData.clone();
        }
    }

    protected void setServerKexData(byte[] data) {
        ValidateUtils.checkNotNullAndNotEmpty(data, "No server KEX seed");
        synchronized (kexState) {
            serverKexData = data.clone();
        }
    }

    /**
     * @param seed The result of the KEXINIT handshake - required for correct session key establishment
     */
    protected abstract void setKexSeed(byte... seed);

    /**
     * Indicates the the key exchange is completed and the exchanged keys can now be verified - e.g., client can verify
     * the server's key
     *
     * @throws IOException If validation failed
     */
    protected abstract void checkKeys() throws IOException;

    protected byte[] receiveKexInit(Buffer buffer) throws Exception {
        Map<KexProposalOption, String> proposal = new EnumMap<>(KexProposalOption.class);

        byte[] seed;
        synchronized (kexState) {
            seed = receiveKexInit(buffer, proposal);
            receiveKexInit(proposal, seed);
        }

        if (log.isTraceEnabled()) {
            log.trace("receiveKexInit({}) proposal={} seed: {}",
                    this, proposal, BufferUtils.toHex(':', seed));
        }

        return seed;
    }

    protected abstract void receiveKexInit(
            Map<KexProposalOption, String> proposal, byte[] seed)
            throws IOException;

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

    /**
     * Message encoding or decoding settings as determined at the end of a key exchange.
     */
    protected static class MessageCodingSettings {

        private final Cipher cipher;

        private final Mac mac;

        private final Compression compression;

        private final Cipher.Mode mode;

        private byte[] key;

        private byte[] iv;

        public MessageCodingSettings(Cipher cipher, Mac mac, Compression compression, Cipher.Mode mode, byte[] key, byte[] iv) {
            this.cipher = cipher;
            this.mac = mac;
            this.compression = compression;
            this.mode = mode;
            this.key = key.clone();
            this.iv = iv.clone();
        }

        private void initCipher(long packetSequenceNumber) throws Exception {
            if (key != null) {
                if (cipher.getAlgorithm().startsWith("ChaCha")) {
                    BufferUtils.putLong(packetSequenceNumber, iv, 0, iv.length);
                }
                cipher.init(mode, key, iv);
                key = null;
            }
        }

        /**
         * Get the {@link Cipher}.
         *
         * @param  packetSequenceNumber SSH packet sequence number for initializing the cipher. Pass {@link #seqo} if
         *                              the cipher is to be used for output, {@link #seqi} otherwise.
         * @return                      the fully initialized cipher
         * @throws Exception            if the cipher cannot be initialized
         */
        public Cipher getCipher(long packetSequenceNumber) throws Exception {
            initCipher(packetSequenceNumber);
            return cipher;
        }

        public Mac getMac() {
            return mac;
        }

        public Compression getCompression() {
            return compression;
        }
    }
}
