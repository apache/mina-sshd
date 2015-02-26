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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Digest;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.Readable;

import static org.apache.sshd.common.SshConstants.SSH_MSG_DEBUG;
import static org.apache.sshd.common.SshConstants.SSH_MSG_DISCONNECT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_IGNORE;
import static org.apache.sshd.common.SshConstants.SSH_MSG_KEXINIT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_NEWKEYS;
import static org.apache.sshd.common.SshConstants.SSH_MSG_SERVICE_ACCEPT;
import static org.apache.sshd.common.SshConstants.SSH_MSG_SERVICE_REQUEST;
import static org.apache.sshd.common.SshConstants.SSH_MSG_UNIMPLEMENTED;

/**
 * The AbstractSession handles all the basic SSH protocol such as key exchange, authentication,
 * encoding and decoding. Both server side and client side sessions should inherit from this
 * abstract class. Some basic packet processing methods are defined but the actual call to these
 * methods should be done from the {@link #handleMessage(org.apache.sshd.common.util.Buffer)}
 * method, which is dependant on the state and side of this session.
 *
 * TODO: if there is any very big packet, decoderBuffer and uncompressBuffer will get quite big
 *        and they won't be resized down at any time. Though the packet size is really limited
 *        by the channel max packet size
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSession extends CloseableUtils.AbstractInnerCloseable implements Session {

    /**
     * Name of the property where this session is stored in the attributes of the
     * underlying MINA session. See {@link #getSession(IoSession, boolean)}
     * and {@link #attachSession(IoSession, AbstractSession)}.
     */
    public static final String SESSION = "org.apache.sshd.session";

    protected static final int KEX_STATE_INIT = 1;
    protected static final int KEX_STATE_RUN =  2;
    protected static final int KEX_STATE_KEYS = 3;
    protected static final int KEX_STATE_DONE = 4;

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
    protected String[] serverProposal;
    protected String[] clientProposal;
    protected String[] negotiated;
    protected byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
    protected byte[] I_S; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected KeyExchange kex;
    protected final AtomicInteger kexState = new AtomicInteger();
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
    protected Buffer decoderBuffer = new Buffer();
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
    protected volatile long inPackets;
    protected volatile long outPackets;
    protected volatile long inBytes;
    protected volatile long outBytes;
    protected volatile long lastKeyTime;
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
     * an IllegalStateException will be thrown, else a <code>null</code> will
     * be returned
     *
     * @param ioSession the MINA session
     * @param allowNull if <code>true</code>, a <code>null</code> value may be
     *        returned if no session is attached
     * @return the session attached to the MINA session or <code>null</code>
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

    public String getServerVersion() {
        return serverVersion;
    }

    public String getClientVersion() {
        return clientVersion;
    }

    public KeyExchange getKex() {
        return kex;
    }

    public byte [] getSessionId() {
        return sessionId;
    }


    /**
     * Retrieve the mina session
     *  
     * @return the mina session
     */
    public IoSession getIoSession() {
        return ioSession;
    }

    /**
     * Retrieve the factory manager
     *
     * @return the factory manager for this session
     */
    public FactoryManager getFactoryManager() {
        return factoryManager;
    }

    public String getNegotiatedKexParameter(int paramType) {
    	if ((paramType < 0) || (negotiated == null) || (paramType >= negotiated.length)) {
    		return null;
    	} else {
    		return negotiated[paramType];
    	}
    }

    public boolean isAuthenticated() {
        return authed;
    }

    public void setUsername(String username) {
        this.username = username;
    }

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
        byte cmd = buffer.getByte();
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.debug("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close(true);
                break;
            }
            case SSH_MSG_IGNORE: {
                log.debug("Received SSH_MSG_IGNORE");
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                log.debug("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.debug("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_SERVICE_REQUEST:
                String service = buffer.getString();
                log.debug("Received SSH_MSG_SERVICE_REQUEST '{}'", service);
                if (kexState.get() != KEX_STATE_DONE) {
                    throw new IllegalStateException("Received command " + cmd + " before key exchange is finished");
                }
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
                if (kexState.get() != KEX_STATE_DONE) {
                    throw new IllegalStateException("Received command " + cmd + " before key exchange is finished");
                }
                serviceAccept();
                break;
            case SSH_MSG_KEXINIT:
                log.debug("Received SSH_MSG_KEXINIT");
                receiveKexInit(buffer);
                if (kexState.compareAndSet(KEX_STATE_DONE, KEX_STATE_RUN)) {
                    sendKexInit();
                } else if (!kexState.compareAndSet(KEX_STATE_INIT, KEX_STATE_RUN)) {
                    throw new IllegalStateException("Received SSH_MSG_KEXINIT while key exchange is running");
                }
                negotiate();
                kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negotiated[SshConstants.PROPOSAL_KEX_ALGS]);
                kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                sendEvent(SessionListener.Event.KexCompleted);
                break;
            case SSH_MSG_NEWKEYS:
                log.debug("Received SSH_MSG_NEWKEYS");
                if (kexState.get() != KEX_STATE_KEYS) {
                    throw new IllegalStateException("Received command " + cmd + " before key exchange is finished");
                }
                receiveNewKeys();
                if (reexchangeFuture != null) {
                    reexchangeFuture.setValue(true);
                }
                sendEvent(SessionListener.Event.KeyEstablished);
                synchronized (pendingPackets) {
                    if (!pendingPackets.isEmpty()) {
                        log.info("Dequeing pending packets");
                        synchronized (encodeLock) {
                            PendingWriteFuture future;
                            while ((future = pendingPackets.poll()) != null) {
                                doWritePacket(future.getBuffer()).addListener(future);
                            }
                        }
                    }
                    kexState.set(KEX_STATE_DONE);
                }
                synchronized (lock) {
                    lock.notifyAll();
                }
                break;
            default:
                if (cmd >= SshConstants.SSH_MSG_KEX_FIRST && cmd <= SshConstants.SSH_MSG_KEX_LAST) {
                    if (kexState.get() != KEX_STATE_RUN) {
                        throw new IllegalStateException("Received kex command " + cmd + " while not in key exchange");
                    }
                    buffer.rpos(buffer.rpos() - 1);
                    if (kex.next(buffer)) {
                        checkKeys();
                        sendNewKeys();
                        kexState.set(KEX_STATE_KEYS);
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

    /**
     * Handle any exceptions that occured on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an
     * {@link org.apache.sshd.common.SshException}.
     * 
     * @param t the exception to process
     */
    public void exceptionCaught(Throwable t) {
        // Ignore exceptions that happen while closing
        synchronized (lock) {
            if (isClosing()) {
                return;
            }
        }
        log.warn("Exception caught", t);
        try {
            if (t instanceof SshException) {
                int code = ((SshException) t).getDisconnectCode();
                if (code > 0) {
                    disconnect(code, t.getMessage());
                    return;
                }
            }
        } catch (Throwable t2) {
            // Ignore
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
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        // While exchanging key, queue high level packets
        if (kexState.get() != KEX_STATE_DONE) {
            byte cmd = buffer.array()[buffer.rpos()];
            if (cmd > SshConstants.SSH_MSG_KEX_LAST) {
                synchronized (pendingPackets) {
                    if (kexState.get() != KEX_STATE_DONE) {
                        if (pendingPackets.isEmpty()) {
                            log.info("Start flagging packets as pending until key exchange is done");
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
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        final IoWriteFuture writeFuture = writePacket(buffer);
        final DefaultSshFuture<IoWriteFuture> future = (DefaultSshFuture<IoWriteFuture>) writeFuture;
        final ScheduledFuture<?> sched = factoryManager.getScheduledExecutorService().schedule(new Runnable() {
            public void run() {
                log.info("Timeout writing packet.");
                future.setValue(new TimeoutException());
            }
        }, timeout, unit);
        future.addListener(new SshFutureListener<IoWriteFuture>() {
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
    public Buffer request(Buffer buffer) throws IOException {
        synchronized (requestLock) {
            try {
                synchronized (requestResult) {
                    writePacket(buffer);
                    requestResult.wait();
                    return requestResult.get();
                }
            } catch (InterruptedException e) {
                throw (InterruptedIOException) new InterruptedIOException().initCause(e);
            }
        }
    }

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
    public Buffer createBuffer(byte cmd, int len) {
        Buffer buffer;
        if (len <= 0) {
            buffer = new Buffer();
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
            buffer = new Buffer(new byte[Math.max(len, Buffer.DEFAULT_SIZE)], false);
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
                Buffer nb = new Buffer();
                nb.wpos(5);
                nb.putBuffer(buffer);
                buffer = nb;
            }
            // Grab the length of the packet (excluding the 5 header bytes)
            int len = buffer.available();
            int off = buffer.rpos() - 5;
            // Debug log the packet
            if (log.isTraceEnabled()) {
                log.trace("Sending packet #{}: {}", seqo, buffer.printHex());
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
            outPackets ++;
            outBytes += len;
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
                        log.info("Error decoding packet (invalid length) {}", decoderBuffer.printHex());
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
                    byte pad = decoderBuffer.getByte();
                    Buffer buf;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if (inCompression != null && (authed || !inCompression.isDelayed())) {
                        if (uncompressBuffer == null) {
                            uncompressBuffer = new Buffer();
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
                        log.trace("Received packet #{}: {}", seqi, buf.printHex());
                    }
                    // Update stats
                    inPackets ++;
                    inBytes += buf.available();
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
        byte[] data = (ident + "\r\n").getBytes();
        ioSession.write(new Buffer(data));
    }

    /**
     * Read the other side identification.
     * This method is specific to the client or server side, but both should call
     * {@link #doReadIdentification(org.apache.sshd.common.util.Buffer,boolean)} and
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
     * and a <code>null</code> value will be returned.  Else the identification
     * string will be returned and the data read will be consumed from the buffer.
     *
     * @param buffer the buffer containing the identification string
     * @return the remote identification or <code>null</code> if more data is needed
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
            if (buffer.rpos() > 16 * 1024) {
                throw new IllegalStateException("Incorrect identification: too many header lines");
            }
        }
    }

    /**
     * Create our proposal for SSH negotiation
     *
     * @param hostKeyTypes the list of supported host key types
     * @return an array of 10 strings holding this proposal
     */
    protected String[] createProposal(String hostKeyTypes) {
        return new String[] {
                NamedFactory.Utils.getNames(factoryManager.getKeyExchangeFactories()),
                hostKeyTypes,
                NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                NamedFactory.Utils.getNames(factoryManager.getMacFactories()),
                NamedFactory.Utils.getNames(factoryManager.getMacFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()),
                "",
                ""
        };
    }

    /**
     * Send the key exchange initialization packet.
     * This packet contains random data along with our proposal.
     *
     * @param proposal our proposal for key exchange negotiation
     * @return the sent packet which must be kept for later use
     * @throws IOException if an error occurred sending the packet
     */
    protected byte[] sendKexInit(String[] proposal) throws IOException {
        log.debug("Send SSH_MSG_KEXINIT");
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + 16);
        random.fill(buffer.array(), p, 16);
        for (String s : proposal) {
            buffer.putString(s);
        }
        buffer.putByte((byte) 0);
        buffer.putInt(0);
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
    protected byte[] receiveKexInit(Buffer buffer, String[] proposal) {
        // Recreate the packet payload which will be needed at a later time
        int size = 22;
        byte[] d = buffer.array();
        byte[] data = new byte[buffer.available() + 1];
        data[0] = SshConstants.SSH_MSG_KEXINIT;
        System.arraycopy(d, buffer.rpos(), data, 1, data.length - 1);
        // Skip 16 bytes of random data
        buffer.rpos(buffer.rpos() + 16);
        // Read proposal
        for (int i = 0; i < proposal.length; i++) {
            size += 4;
            proposal[i] = buffer.getString();
            size += proposal[i].length();
        }
        // Skip 5 bytes
        buffer.getByte();
        buffer.getInt();
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

        Buffer buffer = new Buffer();
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

        s2ccipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(), negotiated[SshConstants.PROPOSAL_ENC_ALGS_STOC]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(isServer ? Cipher.Mode.Encrypt : Cipher.Mode.Decrypt, Es2c, IVs2c);

        s2cmac = NamedFactory.Utils.create(factoryManager.getMacFactories(), negotiated[SshConstants.PROPOSAL_MAC_ALGS_STOC]);
        MACs2c = resizeKey(MACs2c, s2cmac.getBlockSize(), hash, K, H);
        s2cmac.init(MACs2c);

        c2scipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(), negotiated[SshConstants.PROPOSAL_ENC_ALGS_CTOS]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(isServer ? Cipher.Mode.Decrypt : Cipher.Mode.Encrypt, Ec2s, IVc2s);

        c2smac = NamedFactory.Utils.create(factoryManager.getMacFactories(), negotiated[SshConstants.PROPOSAL_MAC_ALGS_CTOS]);
        MACc2s = resizeKey(MACc2s, c2smac.getBlockSize(), hash, K, H);
        c2smac.init(MACc2s);

        s2ccomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), negotiated[SshConstants.PROPOSAL_COMP_ALGS_STOC]);
        c2scomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), negotiated[SshConstants.PROPOSAL_COMP_ALGS_CTOS]);

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
        inBytes = 0;
        outBytes = 0;
        inPackets = 0;
        outPackets = 0;
        lastKeyTime = System.currentTimeMillis();
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
            Buffer buffer = new Buffer();
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

    /**
     * Send a disconnect packet with the given reason and message.
     * Once the packet has been sent, the session will be closed
     * asynchronously.
     *
     * @param reason the reason code for this disconnect
     * @param msg the text message
     * @throws IOException if an error occured sending the packet
     */
    public void disconnect(int reason, String msg) throws IOException {
        log.info("Disconnecting: {}", msg);
        Buffer buffer = createBuffer(SshConstants.SSH_MSG_DISCONNECT);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");
        // Write the packet with a timeout to ensure a timely close of the session
        // in case the consumer does not read packets anymore.
        writePacket(buffer, disconnectTimeoutMs, TimeUnit.MILLISECONDS).addListener(new SshFutureListener<IoWriteFuture>() {
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
     * server proposal.  The negotiated proposal will be stored in
     * the {@link #negotiated} property.
     */
    protected void negotiate() {
        String[] guess = new String[SshConstants.PROPOSAL_MAX];
        for (int i = 0; i < SshConstants.PROPOSAL_MAX; i++) {
        	String paramName = SshConstants.PROPOSAL_KEX_NAMES[i];
        	String clientParamValue = clientProposal[i];
        	String serverParamValue = serverProposal[i];
            String[] c = clientParamValue.split(",");
            String[] s = serverParamValue.split(",");
            for (String ci : c) {
                for (String si : s) {
                    if (ci.equals(si)) {
                        guess[i] = ci;
                        break;
                    }
                }
                if (guess[i] != null) {
                    break;
                }
            }
            
            // check if reached an agreement
            if (guess[i] == null) {
            	String	message="Unable to negotiate key exchange for " + paramName
            				  + " (client: " + clientParamValue + " / server: " + serverParamValue + ")";
                // OK if could not negotiate languages
            	if ((i != SshConstants.PROPOSAL_LANG_CTOS) && (i != SshConstants.PROPOSAL_LANG_STOC)) {
            		throw new IllegalStateException(message);
            	} else {
            		if (log.isTraceEnabled()) {
            			log.trace(message);
            		}
            	}
            } else {
            	if (log.isTraceEnabled()) {
            		log.trace("Kex: negotiate(" + paramName + ") guess=" + guess[i]
            				+ " (client: " + clientParamValue + " / server: " + serverParamValue);
            	}
            }
        }
        negotiated = guess;

        log.debug("Kex: server->client {} {} {}",
                new Object[]{negotiated[SshConstants.PROPOSAL_ENC_ALGS_STOC],
                        negotiated[SshConstants.PROPOSAL_MAC_ALGS_STOC],
                        negotiated[SshConstants.PROPOSAL_COMP_ALGS_STOC]});
        log.debug("Kex: client->server {} {} {}",
                new Object[]{negotiated[SshConstants.PROPOSAL_ENC_ALGS_CTOS],
                        negotiated[SshConstants.PROPOSAL_MAC_ALGS_CTOS],
                        negotiated[SshConstants.PROPOSAL_COMP_ALGS_CTOS]});
    }

    protected void requestSuccess(Buffer buffer) throws Exception{
        synchronized (requestResult) {
            requestResult.set(new Buffer(buffer.getCompactData()));
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
    public int getIntProperty(String name, int defaultValue) {
        try {
            String v = factoryManager.getProperties().get(name);
            if (v != null) {
                return Integer.parseInt(v);
            }
        } catch (Exception e) {
            // Ignore
        }
        return defaultValue;
    }

    public long getLongProperty(String name, long defaultValue) {
        try {
            String v = factoryManager.getProperties().get(name);
            if (v != null) {
                return Long.parseLong(v);
            }
        } catch (Exception e) {
            // Ignore
        }
        return defaultValue;
    }

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param key the key of the attribute; must not be null.
     * @return <tt>null</tt> if there is no attribute with the specified key
     */
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
    @SuppressWarnings("unchecked")
    public <T, E extends T> T setAttribute(AttributeKey<T> key, E value) {
        return (T)attributes.put(key, value);
    }

    public String getUsername() {
        return username;
    }

    public Object getLock() {
        return lock;
    }

    /**
     * {@inheritDoc}
     */
    public void addListener(SessionListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException();
        }
        this.listeners.add(listener);
    }

    /**
     * {@inheritDoc}
     */
    public void removeListener(SessionListener listener) {
        this.listeners.remove(listener);
    }

    protected void sendEvent(SessionListener.Event event) throws IOException {
    	sessionListenerProxy.sessionEvent(this, event);
    }

    /**
     * {@inheritDoc}
     */
    public SshFuture reExchangeKeys() throws IOException {
        if (kexState.compareAndSet(KEX_STATE_DONE, KEX_STATE_INIT)) {
            log.info("Initiating key re-exchange");
            sendKexInit();
            reexchangeFuture = new DefaultSshFuture(null);
        }
        return reexchangeFuture;
    }

    protected void checkRekey() throws IOException {
    }

    protected abstract void sendKexInit() throws IOException;

    protected abstract void checkKeys() throws IOException;

    protected abstract void receiveKexInit(Buffer buffer) throws IOException;

    protected void serviceAccept() throws IOException {
    }

    public abstract void startService(String name) throws Exception;

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

    public void resetIdleTimeout() {
        this.idleTimeoutTimestamp = System.currentTimeMillis() + idleTimeoutMs;
    }

    /**
     * Check if timeout has occurred.
     * @return
     */
    public TimeoutStatus getTimeoutStatus() {
        return timeoutStatus.get();
    }

    /**
     * What is timeout value in milliseconds for authentication stage
     * @return
     */
    public long getAuthTimeout() {
        return authTimeoutMs;
    }

    /**
     * What is timeout value in milliseconds for communication
     * @return
     */
    public long getIdleTimeout() {
        return idleTimeoutMs;
    }

    /**
     * Future holding a packet pending key exchange termination.
     */
    protected static class PendingWriteFuture extends DefaultSshFuture<IoWriteFuture>
            implements IoWriteFuture, SshFutureListener<IoWriteFuture> {

        private final Buffer buffer;

        protected PendingWriteFuture(Buffer buffer) {
            super(null);
            this.buffer = buffer;
        }

        public Buffer getBuffer() {
            return buffer;
        }

        public void verify() throws SshException {
            try {
                await();
            }
            catch (InterruptedException e) {
                throw new SshException("Interrupted", e);
            }
            if (!isWritten()) {
                throw new SshException("Write failed", getException());
            }
        }

        public boolean isWritten() {
            return getValue() instanceof Boolean;
        }

        public Throwable getException() {
            Object v = getValue();
            return v instanceof Throwable ? (Throwable) v : null;
        }

        public void setWritten() {
            setValue(Boolean.TRUE);
        }

        public void setException(Throwable cause) {
            if (cause == null) {
                throw new IllegalArgumentException();
            }
            setValue(cause);
        }

        public void operationComplete(IoWriteFuture future) {
            if (future.isWritten()) {
                setWritten();
            } else {
                setException(future.getException());
            }
        }
    }

    public String toString() {
        return getClass().getSimpleName() + "[" + getUsername() + "@" + getIoSession().getRemoteAddress() + "]";
    }

}
