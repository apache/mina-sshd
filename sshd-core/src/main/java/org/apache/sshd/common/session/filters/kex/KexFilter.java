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
package org.apache.sshd.common.session.filters.kex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntSupplier;
import java.util.stream.Collectors;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.CipherFactory;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.filter.BufferInputHandler;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.future.KeyExchangeFuture;
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
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.filters.CompressionFilter;
import org.apache.sshd.common.session.filters.CryptFilter;
import org.apache.sshd.common.session.filters.CryptFilter.Settings;
import org.apache.sshd.common.session.filters.CryptStatisticsProvider.Counters;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter implementing the KEX protocol.
 * <p>
 * While a KEX is on-going, high-level messages get queued; they will be written once we've sent our SSH_MSG_NEWKEYS. To
 * avoid that the queue grows too much, all channel RemoteWindows are closed during KEX. RemoteWindows listen to KEX
 * state changes, and they report zero during a KEX. Incoming SSH_MSG_CHANNEL_WINDOW_ADJUST before we receive the peer's
 * KEX_INIT have thus no immediate effect. Once KEX is over, the windows will trigger "adjusted" events and will thus
 * open the channels again.
 * </p>
 * <p>
 * The implementation guards against malicious peers that never send their KEX_INIT but instead keep sending SSH
 * messages that would require a reply. (The replies would get queued since this side is already in KEX, and after some
 * time we'd run out of memory.)
 * </p>
 * <p>
 * Such incoming messages are:
 * </p>
 * <ul>
 * <li>SSH_MSG_PING from the {@code ping@openssh.com} extension. This is not implemented in Apache MINA sshd (yet).
 * These messages are dropped on input. See CVE-2025-26466 linked below.</li>
 * <li>SSH_MSG_GLOBAL_REQUEST or SSH_MSG_CHANNEL_REQUEST with {@code want-reply = true}.</li>
 * <li>SSH_MSG_CHANNEL_OPEN messages. User code can guard against this by limiting the number of concurrently open
 * channels.</lI>
 * <li>SSH_MSG_SERVICE_REQUEST messages. This is somewhat unlikely to occur, since normally there are only two such
 * requests in an SSH connection: a first one for user authentication, then a second one to switch to the connection
 * service. There should be no key exchanges running at these times; they're both early on in the protocol. The request
 * for user auth is sent right after the first key exchange.</li>
 * <li>SSH_MSG_CHANNEL_DATA: these messages <em>must</em> be passed on and handled. LocalWindow needs to listen to the
 * KEX state, too, and not send back SSH_CHANNEL_WINDOW_ADJUST because those would get queued. At some point, the
 * channel window will be zero, and if the broken or malicious client keeps sending data, the channel will be closed
 * forcibly. Otherwise, the local windows will send window adjustments as appropriate once KEX is over.</li>
 * <li>SSH_MSG_CHANNEL_WINDOW_ADJUST: see above. We pass these messages on, but make the adjustment take effect in the
 * RemoteWindow only after KEX. Sending a large number of window adjustments thus does not cause excessive queueing; at
 * worst (if the peer opens its window too far) it may cause trouble at the malicious peer.</li>
 * <li>Unknown messages. We should reply with SSH_MSG_UNIMPLEMENTED except if in strict KEX. During strict KEX, we will
 * drop any unknown messages on input.</li>
 * </p>
 * <p>
 * As an additional guard against this kind of misbehavior we implement two configurable parameters:
 * </p>
 * <li>MAX_PACKETS_UNTIL_KEX_INIT: if we haven't received the peer's KEX_INIT with the next MAX_PACKETS_UNTIL_KEX_INIT
 * incoming messages after having sent our own KEX_INIT, we disconnect the session.</li>
 * <li>MAX_TIME_UNTIL_KEX_INIT: if we haven't received the peer's KEX_INIT within MAX_TIME_UNTIL_KEX_INIT after having
 * sent our own KEX_INIT, we disconnect the session.</li>
 * <p>
 * Both settings have rather high defaults (1000 messages or 10min). With these settings, we will disconnect even if a
 * peer just keeps sending SSH_MSG_IGNORE packets. If a peer doesn't send any messages, the session idle timeout will
 * disconnect the session.
 * </p>
 *
 * @see <a href="https://www.cve.org/CVERecord?id=CVE-2025-26466">CVE-2025-26466</a>
 */
@SuppressWarnings("checkstyle:MethodCount")
public class KexFilter extends IoFilter {

    private static final Logger LOG = LoggerFactory.getLogger(KexFilter.class);

    private final AtomicReference<byte[]> sessionId = new AtomicReference<>();

    private final CopyOnWriteArrayList<KexListener> listeners = new CopyOnWriteArrayList<>();

    private final AtomicReference<KexState> kexState = new AtomicReference<>(KexState.DONE);

    private final AtomicReference<DefaultKeyExchangeFuture> kexFuture = new AtomicReference<>();

    private final AtomicReference<Map<KexProposalOption, String>> negotiated = new AtomicReference<>(
            new EnumMap<>(KexProposalOption.class));

    private final AtomicReference<Map<KexProposalOption, String>> myProposal = new AtomicReference<>();

    private final AtomicReference<Map<KexProposalOption, String>> peerProposal = new AtomicReference<>();

    private final AtomicReference<byte[]> myData = new AtomicReference<>();

    private final AtomicReference<byte[]> peerData = new AtomicReference<>();

    private final AtomicReference<MessageCodingSettings> inputSettings = new AtomicReference<>();

    private final AtomicReference<MessageCodingSettings> outputSettings = new AtomicReference<>();

    // Rekeying

    private final long rekeyAfterBytes;

    private final long rekeyAfterPackets;

    private final Duration rekeyAfter;

    private final AtomicReference<Instant> lastKexEnd = new AtomicReference<>(Instant.now());

    // Input & output

    private final KexInputHandler input = new KexInputHandler();

    /**
     * Handles output going through the filter, i.e., initiated from outside.
     */
    private final KexOutputHandler output = new KexOutputHandler(this, LOG);

    /**
     * Handles sending through the next filter below this one in the filter chain. Checks for wrap-around on the
     * outgoing sequence number during initial KEX.
     */
    private final Sender forward = new Sender();

    private final AbstractSession session;

    private final Random random;

    private final SessionListener signals;

    private final CryptFilter crypt;

    private final CompressionFilter compression;

    public interface Proposer {

        Map<KexProposalOption, String> get() throws Exception;
    }

    private final Proposer proposer;

    public interface HostKeyChecker {

        void check() throws IOException;
    }

    private final HostKeyChecker hostKeyChecker;

    private enum KexStart {
        PEER,
        BOTH,
        ONGOING
    }

    private volatile String clientIdent;

    private volatile String serverIdent;

    // Set and checked on the input chain
    private boolean firstKexPacketFollows;

    // Set and checked on the input chain
    private KeyExchange kex;

    // Guarded by synchronized(KexFilter.this)
    private DefaultKeyExchangeFuture myProposalReady;

    private volatile boolean initialKexDone;

    private volatile long rekeyAfterBlocks;

    // Terrapin mitigations

    private volatile boolean strictKex;

    private volatile int initialKexInitSequenceNumber;

    public KexFilter(AbstractSession session, Random random, CryptFilter crypt, CompressionFilter compression,
                     SessionListener listener, Proposer proposer, HostKeyChecker checker) {
        this.session = Objects.requireNonNull(session);
        this.random = Objects.requireNonNull(random);
        this.crypt = Objects.requireNonNull(crypt);
        this.compression = Objects.requireNonNull(compression);
        this.signals = Objects.requireNonNull(listener);
        this.proposer = Objects.requireNonNull(proposer);
        this.hostKeyChecker = Objects.requireNonNull(checker);
        rekeyAfterBytes = CoreModuleProperties.REKEY_BYTES_LIMIT.getRequired(session);
        rekeyAfterPackets = CoreModuleProperties.REKEY_PACKETS_LIMIT.getRequired(session);
        rekeyAfterBlocks = rekeyAfterBytes / 16; // Initial setting, will be updated once we know the cipher
        Duration interval = CoreModuleProperties.REKEY_TIME_LIMIT.getRequired(session);
        if (interval.isZero() || interval.isNegative()) {
            interval = null;
        }
        rekeyAfter = interval;
    }

    AbstractSession getSession() {
        return session;
    }

    public boolean isStrictKex() {
        return strictKex;
    }

    public boolean isInitialKexDone() {
        return initialKexDone;
    }

    public AtomicReference<KexState> getKexState() {
        return kexState;
    }

    public Map<KexProposalOption, String> getNegotiated() {
        return Collections.unmodifiableMap(negotiated.get());
    }

    public Map<KexProposalOption, String> getClientProposal() {
        return session.isServerSession()
                ? Collections.unmodifiableMap(peerProposal.get())
                : Collections.unmodifiableMap(myProposal.get());
    }

    public Map<KexProposalOption, String> getServerProposal() {
        return session.isServerSession()
                ? Collections.unmodifiableMap(myProposal.get())
                : Collections.unmodifiableMap(peerProposal.get());
    }

    public void setClientIdent(String ident) {
        clientIdent = Objects.requireNonNull(ident);
    }

    public void setServerIdent(String ident) {
        serverIdent = Objects.requireNonNull(ident);
    }

    public byte[] getSessionId() {
        byte[] id = sessionId.get();
        return id == null ? null : id.clone();
    }

    public void addKexListener(KexListener listener) {
        listeners.addIfAbsent(Objects.requireNonNull(listener));
    }

    public void removeKexListener(KexListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    @Override
    public InputHandler in() {
        return input;
    }

    @Override
    public OutputHandler out() {
        return output;
    }

    public void shutdown() {
        synchronized (this) {
            DefaultKeyExchangeFuture initFuture = myProposalReady;
            if (initFuture != null) {
                initFuture.setValue(new SshException("Session closing while KEX in progress"));
            }
        }
        DefaultKeyExchangeFuture globalFuture = kexFuture.get();
        if (globalFuture != null) {
            globalFuture.setValue(new SshException("Session closing while KEX in progress"));
        }
        output.shutdown();
    }

    private void exceptionCaught(Throwable t) {
        DefaultKeyExchangeFuture globalFuture = kexFuture.get();
        if (globalFuture != null) {
            globalFuture.setValue(t);
        }
        session.exceptionCaught(t);
    }

    // Receiving

    private void receiveKexInit(Buffer message) throws Exception {
        // Update the KEX state
        KexStart starting = output.updateState(() -> {
            if (kexState.compareAndSet(KexState.DONE, KexState.RUN)) {
                output.initNewKeyExchange();
                return KexStart.PEER;
            } else if (kexState.compareAndSet(KexState.INIT, KexState.RUN)) {
                return KexStart.BOTH;
            }
            return KexStart.ONGOING;
        });
        if (starting == KexStart.ONGOING) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                    "KEX: received SSH_MSG_KEXINIT while already in KEX");
        }
        if (!initialKexDone) {
            initialKexInitSequenceNumber = crypt.getInputSequenceNumber();
        }
        parsePeerProposal(message);
        if (starting == KexStart.PEER) {
            listeners.forEach(listener -> listener.event(true));
            sendKexInit().addListener(f -> {
                if (!f.isWritten()) {
                    exceptionCaught(f.getException());
                }
            });
        }
        // Else starting == KexStart.BOTH: we are in the process of sending our own KEX_INIT. Do the negotiation once
        // that's done. See https://issues.apache.org/jira/browse/SSHD-1197
        DefaultKeyExchangeFuture initFuture;
        synchronized (this) {
            initFuture = myProposalReady;
            if (initFuture == null) {
                initFuture = new DefaultKeyExchangeFuture(session.toString(), null);
                myProposalReady = initFuture;
            }
        }
        initFuture.addListener(f -> {
            Throwable t = f.getException();
            if (t != null) {
                exceptionCaught(t);
            } else {
                try {
                    performNegotiation();
                } catch (Exception e) {
                    exceptionCaught(e);
                }
            }
        });
    }

    private void parsePeerProposal(Buffer message) throws Exception {
        byte[] data = new byte[message.available()];
        message.getRawBytes(data, 0, data.length);

        Buffer buf = new ByteArrayBuffer(data);
        buf.rpos(1 + SshConstants.MSG_KEX_COOKIE_SIZE); // Skip the cmd and the random cookie
        // Read proposal
        Map<KexProposalOption, String> proposal = new EnumMap<>(KexProposalOption.class);
        for (KexProposalOption param : KexProposalOption.VALUES) {
            proposal.put(param, buf.getString());
        }
        boolean traceEnabled = LOG.isTraceEnabled();
        if (traceEnabled) {
            LOG.trace("parsePeerProposal({}) options before handler: {}", session, proposal);
        }

        KexExtensionHandler handler = session.getKexExtensionHandler();
        if (handler != null) {
            handler.handleKexInitProposal(session, false, proposal);
            if (traceEnabled) {
                LOG.trace("parsePeerProposal({}) options after handler: {}", session, proposal);
            }
        }
        firstKexPacketFollows = buf.getBoolean();
        long reserved = buf.getUInt();
        if (reserved != 0 && traceEnabled) {
            LOG.trace("parsePeerProposal({}) non-zero reserved value: {}", session, reserved);
        }
        if (LOG.isDebugEnabled()) {
            for (KexProposalOption param : KexProposalOption.VALUES) {
                LOG.debug("parsePeerProposal({}) KEX peer: {} = {}", session, param, proposal.get(param));
            }
        }
        if (buf.available() > 0) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                    "KEX: received SSH_MSG_KEXINIT contains extra data at the end");
        }

        peerProposal.set(proposal);
        peerData.set(data);
    }

    // Sending

    private Map<KexProposalOption, String> doStrictKexProposal(Map<KexProposalOption, String> proposal) {
        String value = proposal.get(KexProposalOption.ALGORITHMS);
        boolean isServer = session.isServerSession();
        String askForStrictKex = isServer
                ? KexExtensions.STRICT_KEX_SERVER_EXTENSION
                : KexExtensions.STRICT_KEX_CLIENT_EXTENSION;
        Set<String> algorithms = new LinkedHashSet<>(Arrays.asList(value.split(",")));
        boolean changed = false;
        if (!initialKexDone) {
            // On the initial KEX, include the strict KEX flag
            changed = algorithms.add(askForStrictKex);
        } else if (!GenericUtils.isEmpty(value)) {
            // On subsequent KEXes, do not include ext-info-c/ext-info-s or the strict KEX flag in the proposal.
            String extType = isServer ? KexExtensions.SERVER_KEX_EXTENSION : KexExtensions.CLIENT_KEX_EXTENSION;
            changed = algorithms.remove(extType);
            changed |= algorithms.remove(askForStrictKex);
        }
        if (changed) {
            proposal.put(KexProposalOption.ALGORITHMS, algorithms.stream().collect(Collectors.joining(",")));
        }
        return proposal;
    }

    private IoWriteFuture sendKexInit() throws Exception {
        Map<KexProposalOption, String> proposal = doStrictKexProposal(proposer.get());

        Buffer message = session.createBuffer(SshConstants.SSH_MSG_KEXINIT);
        int wpos = message.wpos();
        message.wpos(wpos + SshConstants.MSG_KEX_COOKIE_SIZE);
        random.fill(message.array(), wpos, SshConstants.MSG_KEX_COOKIE_SIZE);

        boolean isDebugEnabled = LOG.isDebugEnabled();
        for (KexProposalOption param : KexProposalOption.VALUES) {
            String value = GenericUtils.trimToEmpty(proposal.get(param));
            if (isDebugEnabled) {
                LOG.debug("sendKexInit({}) KEX this: {} = {}", session, param, value);
            }
            message.putString(value);
        }

        message.putBoolean(false); // No first KEX packet following
        message.putUInt(0); // reserved

        DefaultKeyExchangeFuture initFuture = null;
        try {
            ReservedSessionMessagesHandler handler = session.getReservedSessionMessagesHandler();
            IoWriteFuture future = (handler == null) ? null : handler.sendKexInitRequest(session, proposal, message);
            byte[] data = message.getCompactData();

            myProposal.set(proposal);
            myData.set(data);

            synchronized (this) {
                initFuture = myProposalReady;
                if (initFuture == null) {
                    initFuture = new DefaultKeyExchangeFuture(session.toString(), null);
                    myProposalReady = initFuture;
                }
            }

            if (future != null) {
                if (isDebugEnabled) {
                    LOG.debug("sendKexInit({}) : SSH_MSG_KEXINIT sent by reserved messages handler", session);
                }
            } else {
                future = forward.send(message);
            }
            initFuture.setValue(Boolean.TRUE);
            return future;
        } catch (Exception e) {
            if (initFuture != null) {
                initFuture.setValue(e);
            }
            throw e;
        }
    }

    public KeyExchangeFuture startKex() throws Exception {
        boolean start = output.updateState(() -> {
            if (kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
                output.initNewKeyExchange();
                return true;
            }
            return false;
        });
        DefaultKeyExchangeFuture result = new DefaultKeyExchangeFuture(session.toString(), session.getFutureLock());
        if (start) {
            listeners.forEach(listener -> listener.event(true));
            kexFuture.set(result);
            sendKexInit().addListener(f -> {
                if (!f.isWritten()) {
                    exceptionCaught(f.getException());
                }
            });
        } else {
            result.setValue(new SshException("KEX already ongoing"));
        }
        return result;
    }

    // Negotiation

    /**
     * Given a KEX proposal and a {@link KexProposalOption}, removes all occurrences of a value from a comma-separated
     * value list.
     *
     * @param  options  {@link Map} holding the Kex proposal
     * @param  option   {@link KexProposalOption} to modify
     * @param  toRemove value to remove
     * @return          {@code true} if the option contained the value (and it was removed); {@code false} otherwise
     */
    private boolean removeValue(Map<KexProposalOption, String> options, KexProposalOption option, String toRemove) {
        String val = options.get(option);
        Set<String> algorithms = new LinkedHashSet<>(Arrays.asList(val.split(",")));
        boolean result = algorithms.remove(toRemove);
        if (result) {
            options.put(option, algorithms.stream().collect(Collectors.joining(",")));
        }
        return result;
    }

    private String firstCommon(String[] client, String[] server) {
        for (String c : client) {
            for (String s : server) {
                if (c.equals(s)) {
                    return c;
                }
            }
        }
        return null;
    }

    private boolean isAead(String encryption) {
        NamedFactory<Cipher> factory = NamedResource.findByName(encryption, String::compareTo, session.getCipherFactories());
        if (factory != null) {
            if (factory instanceof CipherFactory) {
                return ((CipherFactory) factory).getAuthenticationTagSize() > 0;
            }
            Cipher cipher = factory.create();
            return cipher != null && cipher.getAuthenticationTagSize() > 0;
        }
        return false;
    }

    private Map<KexProposalOption, String> negotiateProposal() throws Exception {
        boolean isServer = session.isServerSession();
        Map<KexProposalOption, String> client = isServer ? peerProposal.get() : myProposal.get();
        Map<KexProposalOption, String> server = isServer ? myProposal.get() : peerProposal.get();
        Map<KexProposalOption, String> result = new EnumMap<>(KexProposalOption.class);

        // Ensure external code cannot modify the proposals
        Map<KexProposalOption, String> cView = Collections.unmodifiableMap(client);
        Map<KexProposalOption, String> sView = Collections.unmodifiableMap(server);
        Map<KexProposalOption, String> rView = Collections.unmodifiableMap(result);

        signals.sessionNegotiationStart(session, cView, sView);

        boolean strictKexClient = removeValue(client, KexProposalOption.ALGORITHMS, KexExtensions.STRICT_KEX_CLIENT_EXTENSION);
        boolean strictKexServer = removeValue(server, KexProposalOption.ALGORITHMS, KexExtensions.STRICT_KEX_SERVER_EXTENSION);
        if (removeValue(client, KexProposalOption.ALGORITHMS, KexExtensions.STRICT_KEX_SERVER_EXTENSION) && !initialKexDone) {
            LOG.warn("negotiate({}) client proposal contains server flag {}; will be ignored", session,
                    KexExtensions.STRICT_KEX_SERVER_EXTENSION);
        }
        if (removeValue(server, KexProposalOption.ALGORITHMS, KexExtensions.STRICT_KEX_CLIENT_EXTENSION) && !initialKexDone) {
            LOG.warn("negotiate({}) server proposal contains client flag {}; will be ignored", session,
                    KexExtensions.STRICT_KEX_CLIENT_EXTENSION);
        }

        try {
            boolean debugEnabled = LOG.isDebugEnabled();
            if (!initialKexDone) {
                strictKex = strictKexClient && strictKexServer;
                if (debugEnabled) {
                    LOG.debug("negotiate({}) strict KEX={} client={} server={}", session, strictKex, strictKexClient,
                            strictKexServer);
                }
                if (strictKex && initialKexInitSequenceNumber != 1) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            MessageFormat.format(
                                    "KEX: strict KEX negotiated but there were {0} messages before the first SSH_MSG_KEXINIT",
                                    initialKexInitSequenceNumber - 1));
                }
            }
            KexExtensionHandler extHandler = session.getKexExtensionHandler();
            for (KexProposalOption param : KexProposalOption.VALUES) {
                if (param == KexProposalOption.C2SMAC && isAead(result.get(KexProposalOption.C2SENC))
                        || param == KexProposalOption.S2CMAC && isAead(result.get(KexProposalOption.S2CENC))) {
                    // No need to negotiate a MAC for an AEAD cipher
                    result.put(param, "aead");
                    continue;
                }
                String clientParamValue = client.get(param);
                String serverParamValue = server.get(param);
                String[] c = GenericUtils.split(clientParamValue, ',');
                String[] s = GenericUtils.split(serverParamValue, ',');
                String value = firstCommon(c, s);
                if (extHandler != null) {
                    extHandler.handleKexExtensionNegotiation(session, param, value, cView, clientParamValue, sView,
                            serverParamValue);
                }
                if (value != null) {
                    if (isInvalid(param, value) && !acceptFailedNegotiation(cView, sView, rView, param, value)) {
                        throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                                MessageFormat.format("Negotiated value for KEX {0}={1} is invalid: client={2} server={3}",
                                        param, value, clientParamValue, serverParamValue));
                    }
                    result.put(param, value);
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("negotiate({}) {}={} (client={} / server={})", session, param.getDescription(), value,
                                clientParamValue, serverParamValue);
                    }
                } else if (param != KexProposalOption.C2SLANG && param != KexProposalOption.S2CLANG
                        && !acceptFailedNegotiation(cView, sView, rView, param, value)) {
                    // Not being able to negotiate a language is OK: RFC 4253 allows both parties to ignore the field
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            MessageFormat.format("No negotiated value for KEX {0}: client={1} server={2}", param,
                                    clientParamValue, serverParamValue));
                }
            }
        } catch (Exception e) {
            signals.sessionNegotiationEnd(session, cView, sView, rView, e);
            throw e;
        }
        negotiated.set(result);
        signals.sessionNegotiationEnd(session, cView, sView, rView, null);
        return result;
    }

    private boolean isInvalid(KexProposalOption param, String value) {
        switch (param) {
            case ALGORITHMS:
                // RFC 8303, section 2.2: disconnect if ext-info-c or ext-info-s end up being negotiated.
                return KexExtensions.IS_KEX_EXTENSION_SIGNAL.test(value);
            case C2SENC:
            case S2CENC:
                // The 'none' cipher should be set only once the session is authenticated.
                return value.equals(BuiltinCiphers.none.getName()) && !session.isAuthenticated();
            default:
                return false;
        }
    }

    private boolean acceptFailedNegotiation(
            Map<KexProposalOption, String> client, Map<KexProposalOption, String> server,
            Map<KexProposalOption, String> result, KexProposalOption param, String value) {
        SessionDisconnectHandler disconnectHandler = session.getSessionDisconnectHandler();
        try {
            if (disconnectHandler != null
                    && disconnectHandler.handleKexDisconnectReason(session, client, server, result, param)) {
                if (LOG.isDebugEnabled()) {
                    if (GenericUtils.isEmpty(value)) {
                        LOG.debug("negotiate({}) KEX: ignoring missing value for {}", session, param);
                    } else {
                        LOG.debug("negotiate({}) KEX: ignoring invalid {}={}", session, param, value);
                    }
                }
                return true;
            }
        } catch (IOException | RuntimeException e) {
            // If disconnect handler throws an exception continue with the disconnect
            LoggingUtils.debug(LOG, "negotiate({}) disconnect handler for {}={} failed: {}", session, param, value,
                    e.toString(), e);
        }
        return false;
    }

    private void performNegotiation() throws Exception {
        Map<KexProposalOption, String> options = negotiateProposal();

        String kexAlgorithm = options.get(KexProposalOption.ALGORITHMS);
        Collection<? extends KeyExchangeFactory> kexFactories = session.getKeyExchangeFactories();
        KeyExchangeFactory kexFactory = NamedResource.findByName(kexAlgorithm, String.CASE_INSENSITIVE_ORDER, kexFactories);
        ValidateUtils.checkNotNull(kexFactory, "Unknown negotiated KEX algorithm: %s", kexAlgorithm);

        boolean isServer = session.isServerSession();
        byte[] vS = serverIdent.getBytes(StandardCharsets.UTF_8);
        byte[] vC = clientIdent.getBytes(StandardCharsets.UTF_8);
        byte[] iS = isServer ? myData.get() : peerData.get();
        byte[] iC = isServer ? peerData.get() : myData.get();

        kex = kexFactory.createKeyExchange(session);
        kex.init(vS, vC, iS, iC);

        synchronized (this) {
            myProposalReady = null;
        }
        signals.sessionEvent(session, SessionListener.Event.KexCompleted);
    }

    // End of KEX

    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    private void prepareNewSettings() throws Exception {
        byte[] k = kex.getK();
        byte[] h = kex.getH();
        Digest hash = kex.getHash();

        byte[] sessionIdValue = sessionId.get();
        if (sessionIdValue == null) {
            sessionIdValue = h.clone();
            sessionId.set(sessionIdValue);
            if (LOG.isDebugEnabled()) {
                LOG.debug("prepareNewSeetings({}) session ID={}", session, BufferUtils.toHex(':', sessionIdValue));
            }
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putBytes(k);
        buffer.putRawBytes(h);
        buffer.putByte((byte) 0x41);
        buffer.putRawBytes(sessionIdValue);

        int pos = buffer.available();
        byte[] buf = buffer.array();
        hash.update(buf, 0, pos);

        byte[] iv_c2s = hash.digest();
        int j = pos - sessionIdValue.length - 1;

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

        boolean serverSession = session.isServerSession();
        Map<KexProposalOption, String> options = negotiated.get();
        String value = options.get(KexProposalOption.S2CENC);
        Cipher s2ccipher = ValidateUtils.checkNotNull(NamedFactory.create(session.getCipherFactories(), value),
                "Unknown s2c cipher: %s", value);
        e_s2c = resizeKey(e_s2c, s2ccipher.getKdfSize(), hash, k, h);

        Mac s2cmac;
        if (s2ccipher.getAuthenticationTagSize() == 0) {
            value = options.get(KexProposalOption.S2CMAC);
            s2cmac = NamedFactory.create(session.getMacFactories(), value);
            if (s2cmac == null) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown s2c MAC: " + value);
            }
            mac_s2c = resizeKey(mac_s2c, s2cmac.getBlockSize(), hash, k, h);
            s2cmac.init(mac_s2c);
        } else {
            s2cmac = null;
        }

        value = options.get(KexProposalOption.S2CCOMP);
        Compression s2ccomp = NamedFactory.create(session.getCompressionFactories(), value);
        if (s2ccomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown s2c compression: " + value);
        }

        value = options.get(KexProposalOption.C2SENC);
        Cipher c2scipher = ValidateUtils.checkNotNull(NamedFactory.create(session.getCipherFactories(), value),
                "Unknown c2s cipher: %s", value);
        e_c2s = resizeKey(e_c2s, c2scipher.getKdfSize(), hash, k, h);

        Mac c2smac;
        if (c2scipher.getAuthenticationTagSize() == 0) {
            value = options.get(KexProposalOption.C2SMAC);
            c2smac = NamedFactory.create(session.getMacFactories(), value);
            if (c2smac == null) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "Unknown c2s MAC: " + value);
            }
            mac_c2s = resizeKey(mac_c2s, c2smac.getBlockSize(), hash, k, h);
            c2smac.init(mac_c2s);
        } else {
            c2smac = null;
        }

        value = options.get(KexProposalOption.C2SCOMP);
        Compression c2scomp = NamedFactory.create(session.getCompressionFactories(), value);
        if (c2scomp == null) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_COMPRESSION_ERROR, "Unknown c2s compression: " + value);
        }

        if (serverSession) {
            outputSettings.set(new MessageCodingSettings(s2ccipher, s2cmac, s2ccomp, Cipher.Mode.Encrypt, e_s2c, iv_s2c));
            inputSettings.set(new MessageCodingSettings(c2scipher, c2smac, c2scomp, Cipher.Mode.Decrypt, e_c2s, iv_c2s));
        } else {
            outputSettings.set(new MessageCodingSettings(c2scipher, c2smac, c2scomp, Cipher.Mode.Encrypt, e_c2s, iv_c2s));
            inputSettings.set(new MessageCodingSettings(s2ccipher, s2cmac, s2ccomp, Cipher.Mode.Decrypt, e_s2c, iv_s2c));
        }
    }

    private static byte[] resizeKey(byte[] e, int kdfSize, Digest hash, byte[] k, byte[] h) throws Exception {
        Buffer buffer = null;
        while (kdfSize > e.length) {
            if (buffer == null) {
                buffer = new ByteArrayBuffer();
            } else {
                buffer.clear();
            }

            buffer.putBytes(k);
            buffer.putRawBytes(h);
            buffer.putRawBytes(e);
            hash.update(buffer.array(), 0, buffer.available());

            byte[] foo = hash.digest();
            byte[] bar = new byte[e.length + foo.length];
            System.arraycopy(e, 0, bar, 0, e.length);
            System.arraycopy(foo, 0, bar, e.length, foo.length);
            e = bar;
        }
        BufferUtils.clear(buffer);
        return e;
    }

    private IoWriteFuture sendNewKeys() throws Exception {
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_NEWKEYS, 1);
        IoWriteFuture future = forward.send(buffer);
        // Use the new settings from now on for any outgoing packet
        setOutputEncoding();
        output.updateState(() -> kexState.set(KexState.KEYS));

        session.resetIdleTimeout();
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
        KexExtensionHandler extHandler = session.getKexExtensionHandler();
        if ((extHandler != null) && extHandler.isKexExtensionsAvailable(session, AvailabilityPhase.NEWKEYS)) {
            extHandler.sendKexExtensions(session, KexPhase.NEWKEYS);
        }

        SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture> flushDone = output.terminateKeyExchange();

        // Flush the queue asynchronously.
        int numPending = flushDone.getKey().intValue();
        if (numPending == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("handleNewKeys({}) No pending packets to flush at end of KEX", session);
            }
            flushDone.getValue().setValue(Boolean.TRUE);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("handleNewKeys({}) {} pending packets to flush at end of KEX", session, numPending);
            }
            output.flushQueue(flushDone.getValue());
        }

        future.addListener(f -> {
            if (!f.isWritten()) {
                exceptionCaught(f.getException());
            }
        });
        return future;
    }

    /**
     * Installs the current prepared {@link #outSettings} so that they are effective and will be applied to any future
     * outgoing packet. Clears {@link #outSettings}.
     *
     * @throws Exception on errors
     */
    private void setOutputEncoding() throws Exception {
        MessageCodingSettings out = outputSettings.get();
        Compression comp = out.getCompression();
        // TODO add support for configurable compression level
        comp.init(Compression.Type.Deflater, -1);
        compression.setOutputCompression(comp);
        Cipher cipher = out.getCipher(strictKex ? 0 : crypt.getOutputSequenceNumber());
        Mac mac = out.getMac();
        crypt.setOutput(new Settings(cipher, mac), strictKex);
        crypt.resetOutputCounters();
        outputSettings.set(null);

        Cipher inCipher = crypt.getInputSettings().getCipher();
        int inBlockSize = inCipher == null ? 8 : inCipher.getCipherBlockSize();
        long maxRekeyBlocks = determineRekeyBlockLimit(inBlockSize, cipher.getCipherBlockSize());
        rekeyAfterBlocks = maxRekeyBlocks;

        lastKexEnd.set(Instant.now());

        forward.sequenceNumberCheckEnabled = false;

        if (LOG.isDebugEnabled()) {
            LOG.debug("setOutputEncoding({}): cipher {}; mac {}; compression {}; blocks limit {}", session, cipher, mac,
                    comp, maxRekeyBlocks);
        }
    }

    private void receiveNewKeys(KexState currentState) throws Exception {
        boolean debugEnabled = LOG.isDebugEnabled();
        if (debugEnabled) {
            LOG.debug("receiveNewKeys({}) SSH_MSG_NEWKEYS", session);
        }
        if (currentState != KexState.KEYS) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                    "KEX: received SSH_MSG_NEWKEYS in state " + currentState);
        }
        // It is guaranteed that we handle the peer's SSH_MSG_NEWKEYS after having sent our own.
        // prepareNewKeys() was already called in sendNewKeys().
        //
        // From now on, use the new settings for any incoming message.
        setInputEncoding();

        synchronized (this) {
            myProposalReady = null;
        }

        initialKexDone = true;

        signals.sessionEvent(session, SessionListener.Event.KeyEstablished);

        listeners.forEach(listener -> listener.event(false));

        output.updateState(() -> {
            kex = null; // discard and GC since KEX is completed
            kexState.set(KexState.DONE);
        });

        DefaultKeyExchangeFuture globalFuture = kexFuture.getAndSet(null);
        if (globalFuture != null) {
            globalFuture.setValue(Boolean.TRUE);
        }

    }

    /**
     * Installs the current prepared {@link #inSettings} so that they are effective and will be applied to any future
     * incoming packet. Clears {@link #inSettings}.
     *
     * @throws Exception on errors
     */
    private void setInputEncoding() throws Exception {
        MessageCodingSettings in = inputSettings.get();
        Compression comp = in.getCompression();
        // TODO add support for configurable compression level
        comp.init(Compression.Type.Inflater, -1);
        compression.setInputCompression(comp);
        Cipher cipher = in.getCipher(strictKex ? 0 : crypt.getInputSequenceNumber());
        Mac mac = in.getMac();
        crypt.setInput(new Settings(cipher, mac), strictKex);
        crypt.resetInputCounters();
        inputSettings.set(null);

        Cipher outCipher = crypt.getOutputSettings().getCipher();
        int outBlockSize = outCipher == null ? 8 : outCipher.getCipherBlockSize();
        long maxRekeyBlocks = determineRekeyBlockLimit(cipher.getCipherBlockSize(), outBlockSize);

        lastKexEnd.set(Instant.now());

        if (LOG.isDebugEnabled()) {
            LOG.debug("setInputEncoding({}): cipher {}; mac {}; compression {}; blocks limit {}", session, cipher, mac,
                    comp, maxRekeyBlocks);
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
    private long determineRekeyBlockLimit(int inCipherBlockSize, int outCipherBlockSize) {
        // see https://tools.ietf.org/html/rfc4344#section-3.2
        // select the lowest cipher size
        long rekeyBlocksLimit = CoreModuleProperties.REKEY_BLOCKS_LIMIT.getRequired(session);
        if (rekeyBlocksLimit <= 0) {
            // Default per RFC 4344
            int minCipherBlockBytes = Math.min(inCipherBlockSize, outCipherBlockSize);
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

    // Starting a KEX

    private boolean isKexNeeded(boolean input) {
        if (!initialKexDone || !session.isOpen()) {
            return false;
        }
        if (rekeyAfter != null && Duration.between(lastKexEnd.get(), Instant.now()).compareTo(rekeyAfter) >= 0) {
            return true; // Time interval expired
        }
        // Check either direction.
        Counters counts = crypt.getInputCounters();
        if (rekeyAfterBlocks > 0 && rekeyAfterBlocks <= counts.getBlocks() //
                || rekeyAfterBytes > 0 && rekeyAfterBytes <= counts.getBytes() //
                || rekeyAfterPackets > 0 && rekeyAfterPackets <= counts.getPackets()) {
            return true;
        }
        counts = crypt.getOutputCounters();
        return rekeyAfterBlocks > 0 && rekeyAfterBlocks <= counts.getBlocks() //
                || rekeyAfterBytes > 0 && rekeyAfterBytes <= counts.getBytes() //
                || rekeyAfterPackets > 0 && rekeyAfterPackets <= counts.getPackets();
    }

    // Entry points for the KexOutputHandler
    IoWriteFuture write(Buffer buffer, boolean checkForKex) throws IOException {
        IoWriteFuture result = forward.send(buffer);
        if (checkForKex) {
            startKexIfNeeded();
        }
        return result;
    }

    void startKexIfNeeded() throws IOException {
        KexState state = kexState.get();
        if (state == KexState.DONE && isKexNeeded(true)) {
            try {
                startKex();
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException(e.getMessage(), e);
            }
        }
    }

    private abstract class WithSequenceNumber {

        private int initialSequenceNumber;

        private boolean first = true;

        WithSequenceNumber() {
            super();
        }

        protected void checkSequence(String message, IntSupplier sequence) throws SshException {
            if (first) {
                first = false;
                initialSequenceNumber = sequence.getAsInt();
            } else if (!initialKexDone && initialSequenceNumber == sequence.getAsInt()) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                        message + " sequence number wraps around during initial KEX");
            }
        }
    }

    private class KexInputHandler extends WithSequenceNumber implements BufferInputHandler {

        KexInputHandler() {
            super();
        }

        @Override
        public void handleMessage(Buffer message) throws Exception {
            checkSequence("Incoming", crypt::getInputSequenceNumber);
            int cmd = message.rawByte(message.rpos()) & 0xFF;
            if (LOG.isDebugEnabled()) {
                LOG.debug("KexFilter.handleMessage({}) {} with packet size {}", getSession(),
                        SshConstants.getCommandMessageName(cmd), message.available());
            }
            KexState state = kexState.get();
            if (state == KexState.DONE) {
                // We are not in KEX.
                if (cmd == SshConstants.SSH_MSG_KEXINIT) {
                    receiveKexInit(message);
                } else {
                    if (isKexNeeded(false)) {
                        startKex();
                    }
                    owner().passOn(message);
                }
                return;
            }

            if (isKexMessage(cmd)) {
                if (cmd == SshConstants.SSH_MSG_KEXINIT) {
                    receiveKexInit(message);
                } else if (cmd == SshConstants.SSH_MSG_NEWKEYS) {
                    if (message.available() != 1) {
                        throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                                "KEX: SSH_MSG_NEWKEYS has extra data");
                    }
                    receiveNewKeys(state);
                } else {
                    handleKexMessage(state, message.getUByte(), message);
                }
            } else {
                if (state == KexState.INIT) {
                    // The peer's KEX_INIT hasn't been received yet
                    passOnBeforeKexInit(cmd, message);
                    return;
                }
                if (strictKex && !initialKexDone && cmd != SshConstants.SSH_MSG_DISCONNECT) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                            MessageFormat.format("{0} not allowed during initial key exchange in strict KEX",
                                    SshConstants.getCommandMessageName(cmd)));
                }
                // The only allowed ones are DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG.
                if (cmd > SshConstants.SSH_MSG_DEBUG) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, MessageFormat
                            .format("{0} not allowed during key exchange", SshConstants.getCommandMessageName(cmd)));
                }
                owner().passOn(message);
            }
        }

        private boolean isKexMessage(int cmd) {
            return cmd >= SshConstants.SSH_MSG_KEXINIT && cmd <= SshConstants.SSH_MSG_KEX_LAST;
        }

        private void passOnBeforeKexInit(int cmd, Buffer message) throws Exception {
            // TODO: message handling per the class javadoc.
            owner().passOn(message);
        }

        private void handleKexMessage(KexState state, int cmd, Buffer message) throws Exception {
            if (state != KexState.RUN) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, MessageFormat
                        .format("KEX message {0} received while not in running KEX", SshConstants.getCommandMessageName(cmd)));
            }
            if (firstKexPacketFollows) {
                firstKexPacketFollows = false;
                // Accept it only if the chosen KEX algorithm and server-key signature algorithm is the first in both
                // client and server proposals.
                // Otherwise just silently drop it.
                for (KexProposalOption param : KexProposalOption.FIRST_KEX_PACKET_GUESS_MATCHES) {
                    String common = negotiated.get().get(param);
                    String my = myProposal.get().get(param).split(",", 1)[0];
                    String peer = peerProposal.get().get(param).split(",", 1)[0];
                    if (!common.equals(my) || !common.equals(peer)) {
                        return;
                    }
                }
            }
            if (kex.next(cmd, message)) {
                // We're done
                hostKeyChecker.check();
                prepareNewSettings();
                lastKexEnd.set(Instant.now());
                sendNewKeys();
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("handleKexMessage({})[{}] more KEX packets expected after cmd={}", session, kex.getName(), cmd);
            }
        }
    }

    private class Sender extends WithSequenceNumber implements OutputHandler {

        volatile boolean sequenceNumberCheckEnabled = true;

        Sender() {
            super();
        }

        @Override
        public IoWriteFuture send(Buffer message) throws IOException {
            if (sequenceNumberCheckEnabled) {
                checkSequence("Outgoing", crypt::getOutputSequenceNumber);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("KexFilter.send({}) {} with packet size {}", getSession(),
                        SshConstants.getCommandMessageName(message.rawByte(message.rpos()) & 0xFF), message.available());
            }
            return owner().send(message);
        }
    }
}
