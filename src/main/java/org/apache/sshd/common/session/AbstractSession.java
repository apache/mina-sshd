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
import java.io.Closeable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.Digest;
import org.apache.sshd.common.SshException;
import org.apache.mina.common.ByteBuffer;
import org.apache.mina.common.IoSession;
import org.apache.mina.common.WriteFuture;
import org.apache.mina.common.CloseFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * @version $Rev$, $Date$
 */
public abstract class AbstractSession implements Closeable {

    /**
     * Name of the property where this session is stored in the attributes of the
     * underlying MINA session. See {@link #getSession(org.apache.mina.common.IoSession, boolean)}
     * and {@link #attachSession(org.apache.mina.common.IoSession, AbstractSession)}.
     */
    public static final String SESSION = "com.google.code.sshd.session";
    /** Our logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());
    /** The factory manager used to retrieve factories of Ciphers, Macs and other objects */
    protected final FactoryManager factoryManager;
    /** The underlying MINA session */
    protected final IoSession ioSession;
    /** The pseudo random generator */
    protected final Random random;
    /** Lock object for this session state */
    protected final Object lock = new Object();
    /** Boolean indicating if this session has been closed or not */
    protected boolean closed;
    /** Boolean indicating if this session has been authenticated or not */
    protected boolean authed;
    /** Map of channels keyed by the identifier */
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    /** Next channel identifier */
    protected int nextChannelId;

    //
    // Key exchange support
    //
    protected byte[] sessionId;
    protected String serverVersion;
    protected String clientVersion;
    protected String[] serverProposal;
    protected String[] clientProposal;
    protected String[] negociated;
    protected byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
    protected byte[] I_S; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected KeyExchange kex;

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
    protected int seqi;
    protected int seqo;
    protected Buffer decoderBuffer = new Buffer();
    protected Buffer uncompressBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    protected final Object decodeLock = new Object();

    /**
     * Create a new session.
     *
     * @param factoryManager the factory manager
     * @param ioSession the underlying MINA session
     */
    public AbstractSession(FactoryManager factoryManager, IoSession ioSession) {
        this.factoryManager = factoryManager;
        this.ioSession = ioSession;
        this.random = factoryManager.getRandomFactory().create();
    }

    /**
     * Retrieve the session from the MINA session.
     * If the session has not been attached, an IllegalStateException
     * will be thrown
     *
     * @param ioSession the MINA session
     * @return the session attached to the MINA session
     */
    public static final AbstractSession getSession(IoSession ioSession) {
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
    public static final AbstractSession getSession(IoSession ioSession, boolean allowNull) {
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
    public static final void attachSession(IoSession ioSession, AbstractSession session) {
        ioSession.setAttribute(SESSION, session);
    }

    /**
     * Retrieve the factory manager
     *
     * @return the factory manager for this session
     */
    public FactoryManager getFactoryManager() {
        return factoryManager;
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
    public void messageReceived(ByteBuffer buffer) throws Exception {
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
    protected abstract void handleMessage(Buffer buffer) throws Exception;

    /**
     * Handle any exceptions that occured on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an
     * {@link org.apache.sshd.common.SshException}.
     * 
     * @param t the exception to process
     * @throws IOException
     */
    public void exceptionCaught(Throwable t) {
        log.warn("Exception caught", t);
        try {
            if (t instanceof SshException) {
                int code = ((SshException) t).getDisconnectCode();
                if (code > 0) {
                    disconnect(code, t.getMessage());
                }
            }
        } catch (Throwable t2) {
            // Ignore
        }
        close();
    }

    /**
     * Close this session.
     * This method will close all channels, then close the underlying MINA session.
     * The call will block until the mina session is actually closed.
     */
    public void close() {
        if (!closed) {
            synchronized (lock) {
                if (!closed) {
                    try {
                        log.info("Closing session");
                        Channel[] channelToClose = channels.values().toArray(new Channel[0]);
                        for (Channel channel : channelToClose) {
                            log.debug("Closing channel {}", channel.getId());
                            IoUtils.closeQuietly(channel);
                        }
                        log.debug("Closing IoSession");
                        CloseFuture future = ioSession.close();
                        log.debug("Waiting for IoSession to be closed");
                        future.join();
                        log.debug("IoSession closed");
                    } catch (Throwable t) {
                        log.warn("Error closing session", t);
                    }
                    closed = true;
                    lock.notifyAll();
                }
            }
        }
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
    public WriteFuture writePacket(Buffer buffer) throws IOException {
        // Synchronize all write requests as needed by the encoding algorithm
        // and also queue the write request in this synchronized block to ensure
        // packets are sent in the correct order
        synchronized (encodeLock) {
            encode(buffer);
            ByteBuffer bb = ByteBuffer.wrap(buffer.array(), buffer.rpos(), buffer.available());
            return ioSession.write(bb);
        }
    }

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd the SSH command
     * @return a new buffer ready for write
     */
    public Buffer createBuffer(SshConstants.Message cmd) {
        Buffer buffer = new Buffer();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd.toByte());
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
            if (log.isDebugEnabled()) {
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
                int macSize = outMac != null ? outMac.getBlockSize() : 0;
                int l = buffer.wpos();
                buffer.wpos(l + macSize);
                outMac.update(seqo);
                outMac.update(buffer.array(), off, l);
                outMac.doFinal(buffer.array(), l);
            }
            // Encrypt packet, excluding mac
            if (outCipher != null) {
                outCipher.update(buffer.array(), off, len + 4);
            }
            // Increment packet id
            seqo++;
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
                    if (decoderLength < 5 || decoderLength > 32768 - 4) {
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
            // We have received the beinning of the packet
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
                        inMac.update(seqi);
                        // Update mac with packet data
                        inMac.update(data, 0, decoderLength + 4);
                        // Compute mac result
                        inMac.doFinal(inMacResult, 0);
                        // Check the computed result with the received mac (just after the packet data)
                        if (!BufferUtils.equals(inMacResult, 0, data, decoderLength + 4, macSize)) {
                            throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR,
                                                   "MAC Error");
                        }
                    }
                    // Increment incoming packet sequence number
                    seqi++;
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
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.setAutoExpand(true);
        buffer.put((ident + "\r\n").getBytes());
        buffer.flip();
        ioSession.write(buffer);
    }

    /**
     * Read the other side identification.
     * This method is specific to the client or server side, but both should call
     * {@link #doReadIdentification(org.apache.sshd.common.util.Buffer)} and
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
    protected String doReadIdentification(Buffer buffer) {
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
            if (str.startsWith("SSH-")) {
                return str;
            }
            if (buffer.rpos() > 16 * 1024) {
                throw new IllegalStateException("Incorrect identification: too many header lines");
            }
        }
    }

    /**
     * Create our proposal for SSH negociation
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
     * @param proposal our proposal for key exchange negociation
     * @return the sent packet which must be kept for later use
     * @throws IOException if an error occured sending the packet
     */
    protected byte[] sendKexInit(String[] proposal) throws IOException {
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_KEXINIT);
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
        byte[] d = buffer.array();
        byte[] data = new byte[buffer.available() + 1];
        data[0] = SshConstants.Message.SSH_MSG_KEXINIT.toByte();
        System.arraycopy(d, buffer.rpos(), data, 1, data.length - 1);
        // Skip 16 bytes of random data
        buffer.rpos(buffer.rpos() + 16);
        // Read proposal
        for (int i = 0; i < proposal.length; i++) {
            proposal[i] = buffer.getString();
        }
        // Skip 5 bytes
        buffer.getByte();
        buffer.getInt();
        // Return data
        return data;
    }

    /**
     * Send a message to put new keys into use.
     *
     * @throws IOException if an error occurs sending the message
     */
    protected void sendNewKeys() throws IOException {
        log.info("Send SSH_MSG_NEWKEYS");
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_NEWKEYS);
        writePacket(buffer);
    }

    /**
     * Put new keys into use.
     * This method will intialize the ciphers, digests, macs and compression
     * according to the negociated server and client proposals.
     *
     * @param isServer boolean indicating if this session is on the server or the client side
     * @throws Exception if an error occurs
     */
    protected void receiveNewKeys(boolean isServer) throws Exception {
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

        s2ccipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(), negociated[SshConstants.PROPOSAL_ENC_ALGS_STOC]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(isServer ? Cipher.Mode.Encrypt : Cipher.Mode.Decrypt, Es2c, IVs2c);

        s2cmac = NamedFactory.Utils.create(factoryManager.getMacFactories(), negociated[SshConstants.PROPOSAL_MAC_ALGS_STOC]);
        s2cmac.init(MACs2c);

        c2scipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(), negociated[SshConstants.PROPOSAL_ENC_ALGS_CTOS]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(isServer ? Cipher.Mode.Decrypt : Cipher.Mode.Encrypt, Ec2s, IVc2s);

        c2smac = NamedFactory.Utils.create(factoryManager.getMacFactories(), negociated[SshConstants.PROPOSAL_MAC_ALGS_CTOS]);
        c2smac.init(MACc2s);

        s2ccomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), negociated[SshConstants.PROPOSAL_COMP_ALGS_STOC]);
        c2scomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(), negociated[SshConstants.PROPOSAL_COMP_ALGS_CTOS]);

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
     * Send a disconnect packet with the given reason and message
     *
     * @param reason the reason code for this disconnect
     * @param msg the text message
     * @throws IOException if an error occured sending the packet
     */
    public void disconnect(int reason, String msg) throws IOException {
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_DISCONNECT);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");
        WriteFuture f = writePacket(buffer);
        f.join();
        close();
    }

    /**
     * Send an unimplemented packet.  This packet should contain the
     * sequence id of the usupported packet: this number is assumed to
     * be the last packet received.
     *
     * @throws IOException if an error occured sending the packet
     */
    protected void notImplemented() throws IOException {
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_UNIMPLEMENTED);
        buffer.putInt(seqi - 1);
        writePacket(buffer);
    }

    /**
     * Compute the negociated proposals by merging the client and
     * server proposal.  The negocatiated proposal will be stored in
     * the {@link #negociated} property.
     */
    protected void negociate() {
        String[] guess = new String[SshConstants.PROPOSAL_MAX];
        for (int i = 0; i < SshConstants.PROPOSAL_MAX; i++) {
            String[] c = clientProposal[i].split(",");
            String[] s = serverProposal[i].split(",");
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
            if (guess[i] == null) {
                throw new IllegalStateException("Unable to negociate");
            }
        }
        negociated = guess;
    }

    /**
     * Process incoming data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws Exception if an error occurs
     */
    protected void channelData(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleData(buffer);
    }

    /**
     * Process incoming extended data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws Exception if an error occurs
     */
    protected void channelExtendedData(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleExtendedData(buffer);
    }

    /**
     * Process a window adjust packet on a channel
     *
     * @param buffer the buffer containing the window adjustement parameters
     * @throws Exception if an error occurs
     */
    protected void channelWindowAdjust(Buffer buffer) throws Exception {
        try {
            Channel channel = getChannel(buffer);
            channel.handleWindowAdjust(buffer);
        } catch (SshException e) {
            log.info(e.getMessage());
        }
    }

    /**
     * Process end of file on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelEof(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleEof();
    }

    /**
     * Close a channel due to a close packet received
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelClose(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.close();
        channels.remove(channel.getId());
    }

    /**
     * Service a request on a channel
     *
     * @param buffer the buffer containing the request
     * @throws Exception if an error occurs
     */
    protected void channelRequest(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleRequest(buffer);
    }

    /**
     * Process a failure on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelFailure(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleFailure();
    }

    /**
     * Retrieve the channel designated by the given packet
     *
     * @param buffer the incoming packet
     * @return the target channel
     * @throws IOException if the channel does not exists
     */
    protected Channel getChannel(Buffer buffer) throws IOException {
        int recipient = buffer.getInt();
        Channel channel = channels.get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            SshConstants.Message cmd = buffer.getCommand();
            throw new SshException("Received " + cmd + " on unknown channel " + recipient);
        }
        return channel;
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

}
