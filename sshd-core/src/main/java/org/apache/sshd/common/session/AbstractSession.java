/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.session;

import static org.apache.sshd.common.SshConstants.SSH_MSG_DEBUG;
import static org.apache.sshd.common.SshConstants.SSH_MSG_DISCONNECT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_IGNORE;
import static org.apache.sshd.common.SshConstants.SSH_MSG_KEXINIT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_NEWKEYS;
import static org.apache.sshd.common.SshConstants.SSH_MSG_SERVICE_ACCEPT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_SERVICE_REQUEST;
import static org.apache.sshd.common.SshConstants.SSH_MSG_UNIMPLEMENTED;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * The AbstractSession handles all the basic SSH protocol such as key exchange, authentication,
 * encoding and decoding. Both server side and client side sessions should inherit from this
 * abstract class. Some basic packet processing methods are defined but the actual call to these
 * methods should be done from the {@link #handleMessage(org.apache.sshd.common.util.buffer.Buffer)}
 * method, which is dependant on the state and side of this session.
 *
 * TODO: if there is any very big packet, decoderBuffer and uncompressBuffer will get quite big
 *        and they won't be resized down at any time. Though the packet size is really limited
 *        by the channel max packet size
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSession extends CloseableUtils.AbstractInnerCloseable implements Session {
    public static final String  DEFAULT_SSH_VERSION_PREFIX="SSH-2.0-";

    /**
     * Name of the property where this session is stored in the attributes of the
     * underlying MINA session. See {@link #getSession(IoSession, boolean)}
     * and {@link #attachSession(IoSession, AbstractSession)}.
     */
    public static final String SESSION = "org.apache.sshd.session";

    /** Client or server side */
    protected final boolean isServer;
    /** The factory manager used to retrieve factories of Ciphers, Macs and other objects */
    protected final FactoryManager factoryManager;
    /** The underlying MINA session */
    protected final IoSession ioSession;
    /** The pseudo random generator */
    protected final Random random;
    /** Boolean indicating if this session has been authenticated or not */
    protected boolean authed;
    /** The name of the authenticated user */
    protected String username;

    /** Session listeners container */
    protected final List<SessionListener> listeners = new CopyOnWriteArrayList<SessionListener>();
    protected final SessionListener sessionListenerProxy;
    //
    // Key exchange support
    //
    protected byte[] sessionId;
    protected String serverVersion;
    protected String clientVersion;
    // if empty then means not-initialized
    protected final Map<KexProposalOption,String> serverProposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
    protected final Map<KexProposalOption,String> clientProposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
    private final Map<KexProposalOption,String> negotiationResult  = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
    protected byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
    protected byte[] I_S; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected KeyExchange kex;
    protected final AtomicReference<KexState> kexState = new AtomicReference<KexState>(KexState.UNKNOWN);
    @SuppressWarnings("rawtypes")
    protected DefaultSshFuture reexchangeFuture;

    //
    // SSH packets encoding / decoding support
    //
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
    protected Buffer decoderBuffer = new ByteArrayBuffer();
    protected Buffer uncompressBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    protected final Object decodeLock = new Object();
    protected final Object requestLock = new Object();
    protected final AtomicReference<Buffer> requestResult = new AtomicReference<Buffer>();
    protected final Map<AttributeKey<?>, Object> attributes = new ConcurrentHashMap<AttributeKey<?>, Object>();

    // Session timeout
    protected long authTimeoutTimestamp = 0L;
    protected long idleTimeoutTimestamp = 0L;
    protected long authTimeoutMs = TimeUnit.MINUTES.toMillis(2);          // 2 minutes in milliseconds
    protected long idleTimeoutMs = TimeUnit.MINUTES.toMillis(10);         // 10 minutes in milliseconds
    protected long disconnectTimeoutMs = TimeUnit.SECONDS.toMillis(10);   // 10 seconds in milliseconds
    protected final AtomicReference<TimeoutStatus> timeoutStatus = new AtomicReference<TimeoutStatus>(TimeoutStatus.NoTimeout);

    //
    // Rekeying
    //
    protected final AtomicLong inPacketsCount = new AtomicLong(0L);
    protected final AtomicLong outPacketsCount = new AtomicLong(0L);
    protected final AtomicLong inBytesCount = new AtomicLong(0L);
    protected final AtomicLong outBytesCount = new AtomicLong(0L);
    protected final AtomicLong lastKeyTimeValue = new AtomicLong(0L);
    protected final Queue<PendingWriteFuture> pendingPackets = new LinkedList<PendingWriteFuture>();

    protected Service currentService;

    /**
     * Create a new session.
     *
     * @param factoryManager the factory manager
     * @param ioSession the underlying MINA session
     */
    public AbstractSession(boolean isServer, FactoryManager factoryManager, IoSession ioSession) {
        this.isServer = isServer;
        this.factoryManager = factoryManager;
        this.ioSession = ioSession;
        sessionListenerProxy = EventListenerUtils.proxyWrapper(SessionListener.class, getClass().getClassLoader(), listeners);
        random = factoryManager.getRandomFactory().create();
        authTimeoutMs = getLongProperty(FactoryManager.AUTH_TIMEOUT, authTimeoutMs);
        authTimeoutTimestamp = System.currentTimeMillis() + authTimeoutMs;
        idleTimeoutMs = getLongProperty(FactoryManager.IDLE_TIMEOUT, idleTimeoutMs);
        disconnectTimeoutMs = getLongProperty(FactoryManager.DISCONNECT_TIMEOUT, disconnectTimeoutMs);
    }

    /**
     * Retrieve the session from the MINA session.
     * If the session has not been attached, an IllegalStateException
     * will be thrown
     *
     * @param ioSession the MINA session
     * @return the session attached to the MINA session
     */
    public static AbstractSession getSession(IoSession ioSession) {
        return getSession(ioSession, false);
    }

    /**
     * Retrieve the session from the MINA session.
     * If the session has not been attached and allowNull is <code>false</code>,
     * an IllegalStateException will be thrown, else a {@code null} will
     * be returned
     *
     * @param ioSession the MINA session
     * @param allowNull if <code>true</code>, a {@code null} value may be
     *        returned if no session is attached
     * @return the session attached to the MINA session or {@code null}
     */
    public static AbstractSession getSession(IoSession ioSession, boolean allowNull) {
        AbstractSession session = (AbstractSession) ioSession.getAttribute(SESSION);
        if (!allowNull && session == null) {
            throw new IllegalStateException("No session available");
        }
        return session;
    }

    /**
     * Attach a session to the MINA session
     *
     * @param ioSession the MINA session
     * @param session the session to attach
     */
    public static void attachSession(IoSession ioSession, AbstractSession session) {
        ioSession.setAttribute(SESSION, session);
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
        return GenericUtils.isEmpty(sessionId) ? sessionId : sessionId.clone();
    }

    @Override
    public IoSession getIoSession() {
        return ioSession;
    }

    @Override
    public FactoryManager getFactoryManager() {
        return factoryManager;
    }

    @Override
    public String getNegotiatedKexParameter(KexProposalOption paramType) {
    	if (paramType == null) {
    		return null;
    	}

    	synchronized(negotiationResult) {
    		return negotiationResult.get(paramType);
    	}
    }

    @Override
    public boolean isAuthenticated() {
        return authed;
    }

    @Override
    public void setAuthenticated() throws IOException {
        this.authed = true;
        sendEvent(SessionListener.Event.Authenticated);
    }

    /**
     * Main input point for the MINA framework.
     *
     * This method will be called each time new data is received on
     * the socket and will append it to the input buffer before
     * calling the {@link #decode()} method.
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
     * Abstract method for processing incoming decoded packets.
     * The given buffer will hold the decoded packet, starting from
     * the command byte at the read position.
     * Packets must be processed within this call or be copied because
     * the given buffer is meant to be changed and updated when this
     * method returns.
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an exeption occurs while handling this packet.
     */
    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            doHandleMessage(buffer);
        }
    }

    protected void doHandleMessage(Buffer buffer) throws Exception {
        int cmd = buffer.getUByte();
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                if (log.isDebugEnabled()) {
                    log.debug("Received SSH_MSG_DISCONNECT (reason={}, msg={})", Integer.valueOf(code), msg);
                }
                close(true);
                break;
            }
            case SSH_MSG_IGNORE: {
                log.debug("Received SSH_MSG_IGNORE");
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                if (log.isDebugEnabled()) {
                    log.debug("Received SSH_MSG_UNIMPLEMENTED #{}", Integer.valueOf(code));
                }
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                if (log.isDebugEnabled()) {
                    log.debug("Received SSH_MSG_DEBUG (display={}) '{}'", Boolean.valueOf(display), msg);
                }
                break;
            }
            case SSH_MSG_SERVICE_REQUEST:
                String service = buffer.getString();
                log.debug("Received SSH_MSG_SERVICE_REQUEST '{}'", service);
                validateKexState(cmd, KexState.DONE);
                try {
                    startService(service);
                } catch (Exception e) {
                    log.debug("Service " + service + " rejected", e);
                    disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + service);
                    break;
                }
                log.debug("Accepted service {}", service);
                Buffer response = createBuffer(SshConstants.SSH_MSG_SERVICE_ACCEPT);
                response.putString(service);
                writePacket(response);
                break;
            case SSH_MSG_SERVICE_ACCEPT:
                log.debug("Received SSH_MSG_SERVICE_ACCEPT");
                validateKexState(cmd, KexState.DONE);
                serviceAccept();
                break;
            case SSH_MSG_KEXINIT:
                log.debug("Received SSH_MSG_KEXINIT");
                receiveKexInit(buffer);
                if (kexState.compareAndSet(KexState.DONE, KexState.RUN)) {
                    sendKexInit();
                } else if (!kexState.compareAndSet(KexState.INIT, KexState.RUN)) {
                    throw new IllegalStateException("Received SSH_MSG_KEXINIT while key exchange is running");
                }

                {
                    Map<KexProposalOption,String> result = negotiate();
                    String kexAlgorithm = result.get(KexProposalOption.ALGORITHMS);
                    kex = ValidateUtils.checkNotNull(NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), kexAlgorithm),
                                                     "Unknown negotiated KEX algorithm: %s",
                                                     kexAlgorithm);
                    kex.init(this, serverVersion.getBytes(StandardCharsets.UTF_8), clientVersion.getBytes(StandardCharsets.UTF_8), I_S, I_C);
                }

                sendEvent(SessionListener.Event.KexCompleted);
                break;
            case SSH_MSG_NEWKEYS:
                log.debug("Received SSH_MSG_NEWKEYS");
                validateKexState(cmd, KexState.KEYS);
                receiveNewKeys();
                if (reexchangeFuture != null) {
                    reexchangeFuture.setValue(Boolean.TRUE);
                }
                sendEvent(SessionListener.Event.KeyEstablished);
                synchronized (pendingPackets) {
                    if (!pendingPackets.isEmpty()) {
                        log.debug("Dequeing pending packets");
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
                break;
            default:
                if ((cmd >= SshConstants.SSH_MSG_KEX_FIRST) && (cmd <= SshConstants.SSH_MSG_KEX_LAST)) {
                    validateKexState(cmd, KexState.RUN);
                    buffer.rpos(buffer.rpos() - 1);
                    if (kex.next(buffer)) {
                        checkKeys();
                        sendNewKeys();
                        kexState.set(KexState.KEYS);
                    }
                } else if (currentService != null) {
                    currentService.process(cmd, buffer);
                    resetIdleTimeout();
                } else {
                    throw new IllegalStateException("Unsupported command " + cmd);
                }
                break;
        }
        checkRekey();
    }

    protected void validateKexState(int cmd, KexState expected) {
        KexState actual = kexState.get();
        if (!expected.equals(actual)) {
            throw new IllegalStateException("Received KEX command=" + cmd + " while in state=" + actual + " instead of " + expected);
        }
    }

    /**
     * Handle any exceptions that occurred on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an
     * {@link org.apache.sshd.common.SshException}.
     * 
     * @param t the exception to process
     */
    @Override
    public void exceptionCaught(Throwable t) {
        // Ignore exceptions that happen while closing
        synchronized (lock) {
            if (isClosing()) {
                return;
            }
        }
        log.warn("Exception caught", t);
        if (t instanceof SshException) {
            int code = ((SshException) t).getDisconnectCode();
            if (code > 0) {
                try {
                    disconnect(code, t.getMessage());
                } catch (Throwable t2) {
                    if (log.isDebugEnabled()) {
                        log.debug("Exception while disconnect with code=" + code, t2);
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
    protected void doCloseImmediately() {
        super.doCloseImmediately();
        // Fire 'close' event
        sessionListenerProxy.sessionClosed(this);
    }

    protected Service[] getServices() {
        return currentService != null ? new Service[] { currentService } : new Service[0];
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

    /**
     * Encode and send the given buffer.
     * The buffer has to have 5 bytes free at the beginning to allow the encoding to take place.
     * Also, the write position of the buffer has to be set to the position of the last byte to write.
     *
     * @param buffer the buffer to encode and send
     * @return a future that can be used to check when the packet has actually been sent
     * @throws java.io.IOException if an error occured when encoding sending the packet
     */
    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        // While exchanging key, queue high level packets
        if (!KexState.DONE.equals(kexState.get())) {
            byte cmd = buffer.array()[buffer.rpos()];
            if (cmd > SshConstants.SSH_MSG_KEX_LAST) {
                synchronized (pendingPackets) {
                    if (!KexState.DONE.equals(kexState.get())) {
                        if (pendingPackets.isEmpty()) {
                            log.debug("Start flagging packets as pending until key exchange is done");
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
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        final IoWriteFuture writeFuture = writePacket(buffer);
        final DefaultSshFuture<IoWriteFuture> future = (DefaultSshFuture<IoWriteFuture>) writeFuture;
        final ScheduledFuture<?> sched = factoryManager.getScheduledExecutorService().schedule(new Runnable() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void run() {
                log.info("Timeout writing packet.");
                future.setValue(new TimeoutException());
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
        // Synchronize all write requests as needed by the encoding algorithm
        // and also queue the write request in this synchronized block to ensure
        // packets are sent in the correct order
        synchronized (encodeLock) {
            encode(buffer);
            return ioSession.write(buffer);
        }
    }

    /**
     * Send a global request and wait for the response.
     * This must only be used when sending a SSH_MSG_GLOBAL_REQUEST with a result expected,
     * else it will wait forever.
     *
     * @param buffer the buffer containing the global request
     * @return <code>true</code> if the request was successful, <code>false</code> otherwise.
     * @throws java.io.IOException if an error occured when encoding sending the packet
     */
    @Override
    public Buffer request(Buffer buffer) throws IOException {
        synchronized (requestLock) {
            try {
                synchronized (requestResult) {
                    writePacket(buffer);
                    requestResult.wait();
                    return requestResult.get();
                }
            } catch (InterruptedException e) {
                throw (InterruptedIOException) new InterruptedIOException("Interrupted while waiting for request result").initCause(e);
            }
        }
    }

    @Override
    public Buffer createBuffer(byte cmd) {
        return createBuffer(cmd, 0);
    }

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd the SSH command
     * @param len estimated number of bytes the buffer will hold, 0 if unknown.
     * @return a new buffer ready for write
     */
    @Override
    public Buffer createBuffer(byte cmd, int len) {
        Buffer buffer;
        if (len <= 0) {
            buffer = new ByteArrayBuffer();
        } else {
            // Since the caller claims to know how many bytes they will need
            // increase their request to account for our headers/footers if
            // they actually send exactly this amount.
            //
            int bsize = outCipherSize;
            len += 5;
            int pad = (-len) & (bsize - 1);
            if (pad < bsize) {
                pad += bsize;
            }
            len = len + pad - 4;
            if (outMac != null) {
                len += outMac.getBlockSize();
            }
            buffer = new ByteArrayBuffer(new byte[Math.max(len, ByteArrayBuffer.DEFAULT_SIZE)], false);
        }
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd);
        return buffer;
    }

    /**
     * Encode a buffer into the SSH protocol.
     * This method need to be called into a synchronized block around encodeLock
     *
     * @param buffer the buffer to encode
     * @throws IOException if an exception occurs during the encoding process
     */
    private void encode(Buffer buffer) throws IOException {
        try {
            // Check that the packet has some free space for the header
            if (buffer.rpos() < 5) {
                log.warn("Performance cost: when sending a packet, ensure that "
                           + "5 bytes are available in front of the buffer");
                Buffer nb = new ByteArrayBuffer();
                nb.wpos(5);
                nb.putBuffer(buffer);
                buffer = nb;
            }
            // Grab the length of the packet (excluding the 5 header bytes)
            int len = buffer.available();
            int off = buffer.rpos() - 5;
            // Debug log the packet
            if (log.isTraceEnabled()) {
                log.trace("Sending packet #{}: {}", Long.valueOf(seqo), buffer.printHex());
            }
            // Compress the packet if needed
            if (outCompression != null && (authed || !outCompression.isDelayed())) {
                outCompression.compress(buffer);
                len = buffer.available();
            }
            // Compute padding length
            int bsize = outCipherSize;
            int oldLen = len;
            len += 5;
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
            buffer.wpos(off + oldLen + 5 + pad);
            random.fill(buffer.array(), buffer.wpos() - pad, pad);
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
            }
            // Increment packet id
            seqo = (seqo + 1) & 0xffffffffL;
            // Update stats
            outPacketsCount.incrementAndGet();
            outBytesCount.addAndGet(len);
            // Make buffer ready to be read
            buffer.rpos(off);
        } catch (SshException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    /**
     * Decode the incoming buffer and handle packets as needed.
     *
     * @throws Exception
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
                    }
                    // Read packet length
                    decoderLength = decoderBuffer.getInt();
                    // Check packet length validity
                    if (decoderLength < 5 || decoderLength > (256 * 1024)) {
                        log.warn("Error decoding packet (invalid length) {}", decoderBuffer.printHex());
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
                if (decoderBuffer.available() >= decoderLength + macSize) {
                    byte[] data = decoderBuffer.array();
                    // Decrypt the remaining of the packet
                    if (inCipher != null){
                        inCipher.update(data, inCipherSize, decoderLength + 4 - inCipherSize);
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
                    Buffer buf;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if (inCompression != null && (authed || !inCompression.isDelayed())) {
                        if (uncompressBuffer == null) {
                            uncompressBuffer = new ByteArrayBuffer();
                        } else {
                            uncompressBuffer.clear();
                        }
                        decoderBuffer.wpos(decoderBuffer.rpos() + decoderLength - 1 - pad);
                        inCompression.uncompress(decoderBuffer, uncompressBuffer);
                        buf = uncompressBuffer;
                    } else {
                        decoderBuffer.wpos(decoderLength + 4 - pad);
                        buf = decoderBuffer;
                    }
                    if (log.isTraceEnabled()) {
                        log.trace("Received packet #{}: {}", Long.valueOf(seqi), buf.printHex());
                    }
                    // Update stats
                    inPacketsCount.incrementAndGet();
                    inBytesCount.addAndGet(buf.available());
                    // Process decoded packet
                    handleMessage(buf);
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
     * Send our identification.
     *
     * @param ident our identification to send
     */
    protected void sendIdentification(String ident) {
        log.debug("Send identification: {}", ident);
        byte[] data = (ident + "\r\n").getBytes(StandardCharsets.UTF_8);
        ioSession.write(new ByteArrayBuffer(data));
    }

    /**
     * Read the other side identification.
     * This method is specific to the client or server side, but both should call
     * {@link #doReadIdentification(org.apache.sshd.common.util.buffer.Buffer,boolean)} and
     * store the result in the needed property.
     *
     * @param buffer the buffer containing the remote identification
     * @return <code>true</code> if the identification has been fully read or
     *         <code>false</code> if more data is needed
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
     * @return the remote identification or {@code null} if more data is needed
     */
    protected String doReadIdentification(Buffer buffer, boolean server) {
        byte[] data = new byte[256];
        for (;;) {
            int rpos = buffer.rpos();
            int pos = 0;
            boolean needLf = false;
            for (;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r') {
                    needLf = true;
                    continue;
                }
                if (b == '\n') {
                    break;
                }
                if (needLf) {
                    throw new IllegalStateException("Incorrect identification: bad line ending");
                }
                if (pos >= data.length) {
                    throw new IllegalStateException("Incorrect identification: line too long");
                }
                data[pos++] = b;
            }
            String str = new String(data, 0, pos);
            if (server || str.startsWith("SSH-")) {
                return str;
            }
            if (buffer.rpos() > (16 * 1024)) {
                throw new IllegalStateException("Incorrect identification: too many header lines");
            }
        }
    }

    /**
     * Create our proposal for SSH negotiation
     *
     * @param hostKeyTypes the list of supported host key types
     * @return The proposal {@link Map>
     */
    protected Map<KexProposalOption,String> createProposal(String hostKeyTypes) {
        Map<KexProposalOption,String> proposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
        proposal.put(KexProposalOption.ALGORITHMS, NamedResource.Utils.getNames(factoryManager.getKeyExchangeFactories()));
        proposal.put(KexProposalOption.SERVERKEYS, hostKeyTypes);
        
        {
            String value = NamedResource.Utils.getNames(factoryManager.getCipherFactories());
            proposal.put(KexProposalOption.S2CENC, value);
            proposal.put(KexProposalOption.C2SENC, value);
        }

        {
            String value = NamedResource.Utils.getNames(factoryManager.getMacFactories());
            proposal.put(KexProposalOption.S2CMAC, value);
            proposal.put(KexProposalOption.C2SMAC, value);
        }
        
        {
            String value = NamedResource.Utils.getNames(factoryManager.getCompressionFactories());
            proposal.put(KexProposalOption.S2CCOMP, value);
            proposal.put(KexProposalOption.C2SCOMP, value);
        }
        
        proposal.put(KexProposalOption.S2CLANG, "");
        proposal.put(KexProposalOption.C2SLANG, "");
        return proposal;
    }

    /**
     * Send the key exchange initialization packet.
     * This packet contains random data along with our proposal.
     *
     * @param proposal our proposal for key exchange negotiation
     * @return the sent packet which must be kept for later use
     * @throws IOException if an error occurred sending the packet
     */
    protected byte[] sendKexInit(Map<KexProposalOption,String> proposal) throws IOException {
        log.debug("Send SSH_MSG_KEXINIT");
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + SshConstants.MSG_KEX_COOKIE_SIZE);
        random.fill(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE);
        if (log.isTraceEnabled()) {
            log.trace("sendKexInit(" + toString() + ") cookie=" + BufferUtils.printHex(buffer.array(), p, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            String s = proposal.get(paramType);
            if (log.isTraceEnabled()) {
                log.trace("sendKexInit(" + toString() + ")[" + paramType.getDescription() + "] " + s);
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
     * @param buffer the buffer containing the key exchange init packet
     * @param proposal the remote proposal to fill
     * @return the packet data
     */
    protected byte[] receiveKexInit(Buffer buffer, Map<KexProposalOption,String> proposal) {
        // Recreate the packet payload which will be needed at a later time
        byte[] d = buffer.array();
        byte[] data = new byte[buffer.available() + 1 /* the opcode */];
        data[0] = SshConstants.SSH_MSG_KEXINIT;
        
        int size = 6, cookieStartPos = buffer.rpos();
        System.arraycopy(d, cookieStartPos, data, 1, data.length - 1);
        // Skip random cookie data
        buffer.rpos(cookieStartPos + SshConstants.MSG_KEX_COOKIE_SIZE);
        size += SshConstants.MSG_KEX_COOKIE_SIZE;
        if (log.isTraceEnabled()) {
            log.trace("receiveKexInit(" + toString() + ") cookie=" + BufferUtils.printHex(d, cookieStartPos, SshConstants.MSG_KEX_COOKIE_SIZE, ':'));
        }

        // Read proposal
        for (KexProposalOption paramType : KexProposalOption.VALUES) {
            int lastPos = buffer.rpos();
            String value = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("receiveKexInit(" + toString() + ")[" + paramType.getDescription() + "] " + value);
            }
            int curPos = buffer.rpos(), readLen = curPos - lastPos;
            proposal.put(paramType, value);
            size += readLen;
        }
        
        boolean firstKexPacketFollows = buffer.getBoolean();
        if (log.isTraceEnabled()) {
            log.trace("receiveKexInit(" + toString() + ") first kex packet follows: " + firstKexPacketFollows);
        }

        long reserved = buffer.getUInt();
        if (reserved != 0) {
            if (log.isTraceEnabled()) {
                log.trace("receiveKexInit(" + toString() + ") non-zero reserved value: " + reserved);
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
     * @throws IOException if an error occurs sending the message
     */
    protected void sendNewKeys() throws IOException {
        log.debug("Send SSH_MSG_NEWKEYS");
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_NEWKEYS);
        writePacket(buffer);
    }

    /**
     * Put new keys into use.
     * This method will initialize the ciphers, digests, macs and compression
     * according to the negotiated server and client proposals.
     *
     * @throws Exception if an error occurs
     */
    protected void receiveNewKeys() throws Exception {
        byte[] IVc2s;
        byte[] IVs2c;
        byte[] Ec2s;
        byte[] Es2c;
        byte[] MACc2s;
        byte[] MACs2c;
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        Digest hash = kex.getHash();
        Cipher s2ccipher;
        Cipher c2scipher;
        Mac s2cmac;
        Mac c2smac;
        Compression s2ccomp;
        Compression c2scomp;

        if (sessionId == null) {
            sessionId = new byte[H.length];
            System.arraycopy(H, 0, sessionId, 0, H.length);
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putMPInt(K);
        buffer.putRawBytes(H);
        buffer.putByte((byte) 0x41);
        buffer.putRawBytes(sessionId);
        int pos = buffer.available();
        byte[] buf = buffer.array();
        hash.update(buf, 0, pos);
        IVc2s = hash.digest();

        int j = pos - sessionId.length - 1;

        buf[j]++;
        hash.update(buf, 0, pos);
        IVs2c = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        Ec2s = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        Es2c = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        MACc2s = hash.digest();

        buf[j]++;
        hash.update(buf, 0, pos);
        MACs2c = hash.digest();

        {
            String value = getNegotiatedKexParameter(KexProposalOption.S2CENC);
            s2ccipher = ValidateUtils.checkNotNull(NamedFactory.Utils.create(factoryManager.getCipherFactories(), value), "Unknown s2c cipher: %s", value);
            Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
            s2ccipher.init(isServer ? Cipher.Mode.Encrypt : Cipher.Mode.Decrypt, Es2c, IVs2c);
        }

        {
            String value = getNegotiatedKexParameter(KexProposalOption.S2CMAC);
            s2cmac = ValidateUtils.checkNotNull(NamedFactory.Utils.create(factoryManager.getMacFactories(), value), "Unknown s2c mac: %s", value);
            MACs2c = resizeKey(MACs2c, s2cmac.getBlockSize(), hash, K, H);
            s2cmac.init(MACs2c);
        }

        {
            String value = getNegotiatedKexParameter(KexProposalOption.S2CCOMP);
            s2ccomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), value);
        }

        {
            String value = getNegotiatedKexParameter(KexProposalOption.C2SENC);
            c2scipher = ValidateUtils.checkNotNull(NamedFactory.Utils.create(factoryManager.getCipherFactories(), value), "Unknown c2s cipher: %s", value);
            Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
            c2scipher.init(isServer ? Cipher.Mode.Decrypt : Cipher.Mode.Encrypt, Ec2s, IVc2s);
        }

        {
            String value = getNegotiatedKexParameter(KexProposalOption.C2SMAC);
            c2smac = ValidateUtils.checkNotNull(NamedFactory.Utils.create(factoryManager.getMacFactories(), value), "Unknown c2s mac: %s", value);
            MACc2s = resizeKey(MACc2s, c2smac.getBlockSize(), hash, K, H);
            c2smac.init(MACc2s);
        }

        {
            String value = getNegotiatedKexParameter(KexProposalOption.C2SCOMP);
            c2scomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), value);
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
        if (outCompression != null) {
            outCompression.init(Compression.Type.Deflater, -1);
        }
        inCipherSize = inCipher.getIVSize();
        inMacResult = new byte[inMac.getBlockSize()];
        if (inCompression != null) {
            inCompression.init(Compression.Type.Inflater, -1);
        }
        inBytesCount.set(0L);
        outBytesCount.set(0L);
        inPacketsCount.set(0L);
        outPacketsCount.set(0L);
        lastKeyTimeValue.set(System.currentTimeMillis());
    }

    /**
     * Private method used while putting new keys into use that will resize the key used to
     * initialize the cipher to the needed length.
     *
     * @param E the key to resize
     * @param blockSize the cipher block size
     * @param hash the hash algorithm
     * @param K the key exchange K parameter
     * @param H the key exchange H parameter
     * @return the resize key
     * @throws Exception if a problem occur while resizing the key
     */
    private byte[] resizeKey(byte[] E, int blockSize, Digest hash, byte[] K, byte[] H) throws Exception {
        while (blockSize > E.length) {
            Buffer buffer = new ByteArrayBuffer();
            buffer.putMPInt(K);
            buffer.putRawBytes(H);
            buffer.putRawBytes(E);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[E.length + foo.length];
            System.arraycopy(E, 0, bar, 0, E.length);
            System.arraycopy(foo, 0, bar, E.length, foo.length);
            E = bar;
        }
        return E;
    }

    @Override
    public void disconnect(int reason, String msg) throws IOException {
        log.info("Disconnecting: {} - {}", Integer.valueOf(reason), msg);
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DISCONNECT);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");   // language...
        // Write the packet with a timeout to ensure a timely close of the session
        // in case the consumer does not read packets anymore.
        writePacket(buffer, disconnectTimeoutMs, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
            @Override
            public void operationComplete(IoWriteFuture future) {
                close(true);
            }
        });
    }

    /**
     * Send an unimplemented packet.  This packet should contain the
     * sequence id of the unsupported packet: this number is assumed to
     * be the last packet received.
     *
     * @throws IOException if an error occurred sending the packet
     */
    protected void notImplemented() throws IOException {
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_UNIMPLEMENTED);
        buffer.putInt(seqi - 1);
        writePacket(buffer);
    }

    /**
     * Compute the negotiated proposals by merging the client and
     * server proposal. The negotiated proposal will also be stored in
     * the {@link #negotiationResult} property.
     * @return The negotiated options {@link Map}
     */
    protected Map<KexProposalOption,String> negotiate() {
        Map<KexProposalOption,String> guess = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
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
            	String	message="Unable to negotiate key exchange for " + paramType.getDescription()
            				  + " (client: " + clientParamValue + " / server: " + serverParamValue + ")";
                // OK if could not negotiate languages
            	if (KexProposalOption.S2CLANG.equals(paramType) || KexProposalOption.C2SLANG.equals(paramType)) {
                    if (log.isTraceEnabled()) {
                        log.trace(message);
                    }
            	} else {
            		throw new IllegalStateException(message);
            	}
            } else {
            	if (log.isTraceEnabled()) {
            		log.trace("Kex: negotiate(" +  paramType.getDescription() + ") guess=" + value
            				+ " (client: " + clientParamValue + " / server: " + serverParamValue + ")");
            	}
            }
        }
        
        return setNegotiationResult(guess);
    }

    protected Map<KexProposalOption,String> setNegotiationResult(Map<KexProposalOption,String> guess) {
        synchronized(negotiationResult) {
            if (!negotiationResult.isEmpty()) {
                negotiationResult.clear(); // debug breakpoint
            }
            negotiationResult.putAll(guess);
        }

        if (log.isDebugEnabled()) {
            log.debug("Kex: server->client {} {} {}",
                      guess.get(KexProposalOption.S2CENC),
                      guess.get(KexProposalOption.S2CMAC),
                      guess.get(KexProposalOption.S2CCOMP));
            log.debug("Kex: client->server {} {} {}",
                      guess.get(KexProposalOption.C2SENC),
                      guess.get(KexProposalOption.C2SMAC),
                      guess.get(KexProposalOption.C2SCOMP));
        }
        
        return guess;
    }

    protected void requestSuccess(Buffer buffer) throws Exception{
        synchronized (requestResult) {
            requestResult.set(new ByteArrayBuffer(buffer.getCompactData()));
            resetIdleTimeout();
            requestResult.notify();
        }
    }

    protected void requestFailure(Buffer buffer) throws Exception{
        synchronized (requestResult) {
            requestResult.set(null);
            resetIdleTimeout();
            requestResult.notify();
        }
    }

    /**
     * Retrieve a configuration property as an integer
     *
     * @param name the name of the property
     * @param defaultValue the default value
     * @return the value of the configuration property or the default value if not found
     */
    @Override
    public int getIntProperty(String name, int defaultValue) {
        try {
            return FactoryManagerUtils.getIntProperty(factoryManager, name, defaultValue);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("getIntProperty(" + name + ") failed (" + e.getClass().getSimpleName() + ") to retrieve: " + e.getMessage());
            }
            return defaultValue;
        }
    }

    public long getLongProperty(String name, long defaultValue) {
        try {
            return FactoryManagerUtils.getLongProperty(factoryManager, name, defaultValue);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("getLongProperty(" + name + ") failed (" + e.getClass().getSimpleName() + ") to retrieve: " + e.getMessage());
            }
            return defaultValue;
        }
    }

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param key the key of the attribute; must not be null.
     * @return <tt>null</tt> if there is no attribute with the specified key
     */
    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeKey<T> key) {
        return (T)attributes.get(key);
    }

    /**
     * Sets a user-defined attribute.
     *
     * @param key   the key of the attribute; must not be null.
     * @param value the value of the attribute; must not be null.
     * @return The old value of the attribute.  <tt>null</tt> if it is new.
     */
    @Override
    @SuppressWarnings("unchecked")
    public <T, E extends T> T setAttribute(AttributeKey<T> key, E value) {
        return (T)attributes.put(key, value);
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
    public void addListener(SessionListener listener) {
        ValidateUtils.checkNotNull(listener, "addListener(%s) null instance", this);
        this.listeners.add(listener);
    }

    @Override
    public void removeListener(SessionListener listener) {
        this.listeners.remove(listener);
    }

    protected void sendEvent(SessionListener.Event event) throws IOException {
    	sessionListenerProxy.sessionEvent(this, event);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public SshFuture reExchangeKeys() throws IOException {
        if (kexState.compareAndSet(KexState.DONE, KexState.INIT)) {
            log.info("Initiating key re-exchange");
            sendKexInit();
            reexchangeFuture = new DefaultSshFuture(null);
        }
        return reexchangeFuture;
    }

    protected void checkRekey() throws IOException {
        // nothing
    }

    protected byte[] sendKexInit() throws IOException {
        String resolvedAlgorithms = resolveAvailableSignaturesProposal();
        if (GenericUtils.isEmpty(resolvedAlgorithms)) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
                                   "sendKexInit() no resolved signatures available");
        }

        Map<KexProposalOption,String> proposal = createProposal(resolvedAlgorithms); 
        byte[] seed = sendKexInit(proposal);
        if (log.isDebugEnabled()) {
            log.debug("sendKexInit(" + proposal + ") seed: " + BufferUtils.printHex(':', seed));
        }
        setKexSeed(seed);
        return seed;
    }

    /**
     * @param seed The result of the KEXINIT handshake - required for correct
     * session key establishment
     */
    protected abstract void setKexSeed(byte ... seed);

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

    protected abstract void checkKeys() throws IOException;

    protected void receiveKexInit(Buffer buffer) throws IOException {
        Map<KexProposalOption,String> proposal = new EnumMap<KexProposalOption, String>(KexProposalOption.class);
        byte[] seed = receiveKexInit(buffer, proposal);
        receiveKexInit(proposal, seed);
    }
    
    protected abstract void receiveKexInit(Map<KexProposalOption,String> proposal, byte[] seed) throws IOException;

    // returns the proposal argument
    protected Map<KexProposalOption,String> mergeProposals(Map<KexProposalOption,String> current, Map<KexProposalOption,String> proposal) {
        if (current == proposal) {
            return proposal; // debug breakpoint
        }

        synchronized(current) {
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

    protected void serviceAccept() throws IOException {
        // nothing
    }

    /**
     * Checks whether the session has timed out (both auth and idle timeouts are checked). If the session has
     * timed out, a DISCONNECT message will be sent.
     *
     * @throws IOException
     */
    protected void checkForTimeouts() throws IOException {
        if (!isClosing()) {
            long now = System.currentTimeMillis();
            if (!authed && authTimeoutMs > 0 && now > authTimeoutTimestamp) {
                timeoutStatus.set(TimeoutStatus.AuthTimeout);
                disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Session has timed out waiting for authentication after " + authTimeoutMs + " ms.");
            }
            if (idleTimeoutMs > 0 && idleTimeoutTimestamp > 0 && now > idleTimeoutTimestamp) {
                timeoutStatus.set(TimeoutStatus.AuthTimeout);
                disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "User session has timed out idling after " + idleTimeoutMs + " ms.");
            }
        }
    }

    @Override
    public void resetIdleTimeout() {
        this.idleTimeoutTimestamp = System.currentTimeMillis() + idleTimeoutMs;
    }

    /**
     * Check if timeout has occurred.
     * @return
     */
    @Override
    public TimeoutStatus getTimeoutStatus() {
        return timeoutStatus.get();
    }

    /**
     * What is timeout value in milliseconds for authentication stage
     * @return
     */
    @Override
    public long getAuthTimeout() {
        return authTimeoutMs;
    }

    /**
     * What is timeout value in milliseconds for communication
     * @return
     */
    @Override
    public long getIdleTimeout() {
        return idleTimeoutMs;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getUsername() + "@" + getIoSession().getRemoteAddress() + "]";
    }

}
