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
package org.apache.sshd.sftp.client.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.NullOutputStream;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.ParserUtils;
import org.apache.sshd.sftp.common.extensions.VersionsParser.Versions;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSftpClient extends AbstractSftpClient {
    private final ClientSession clientSession;
    private final ChannelSubsystem channel;
    private final Map<Integer, Buffer> messages = new HashMap<>();
    private final AtomicInteger cmdId = new AtomicInteger(100);
    private final Buffer receiveBuffer = new ByteArrayBuffer();
    private final AtomicInteger versionHolder = new AtomicInteger(0);
    private final AtomicBoolean closing = new AtomicBoolean(false);
    private final NavigableMap<String, byte[]> extensions = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final NavigableMap<String, byte[]> exposedExtensions = Collections.unmodifiableNavigableMap(extensions);
    private Charset nameDecodingCharset;

    /**
     * @param  clientSession          The {@link ClientSession}
     * @param  initialVersionSelector The initial {@link SftpVersionSelector} - if {@code null} then version 6 is
     *                                assumed.
     * @throws IOException            If failed to initialize
     */
    public DefaultSftpClient(ClientSession clientSession, SftpVersionSelector initialVersionSelector) throws IOException {
        this.nameDecodingCharset = SftpModuleProperties.NAME_DECODING_CHARSET.getRequired(clientSession);
        this.clientSession = Objects.requireNonNull(clientSession, "No client session");
        this.channel = createSftpChannelSubsystem(clientSession);
        clientSession.getService(ConnectionService.class).registerChannel(channel);

        Duration initializationTimeout = SftpModuleProperties.SFTP_CHANNEL_OPEN_TIMEOUT.getRequired(clientSession);
        this.channel.open().verify(initializationTimeout);
        this.channel.onClose(() -> {
            synchronized (messages) {
                closing.set(true);
                messages.notifyAll();
            }

            if (versionHolder.get() <= 0) {
                log.warn("onClose({}) closed before version negotiated", channel);
            }
        });

        try {
            init(clientSession, initialVersionSelector, initializationTimeout);
        } catch (IOException | RuntimeException | Error e) {
            this.channel.close(true);
            throw e;
        }
    }

    @Override
    public int getVersion() {
        return versionHolder.get();
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public ClientChannel getClientChannel() {
        return channel;
    }

    @Override
    public NavigableMap<String, byte[]> getServerExtensions() {
        return exposedExtensions;
    }

    @Override
    public Charset getNameDecodingCharset() {
        return nameDecodingCharset;
    }

    @Override
    public void setNameDecodingCharset(Charset nameDecodingCharset) {
        this.nameDecodingCharset = Objects.requireNonNull(nameDecodingCharset, "No charset provided");
    }

    @Override
    public boolean isClosing() {
        return closing.get();
    }

    @Override
    public boolean isOpen() {
        return this.channel.isOpen();
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            this.channel.close(false);
        }
    }

    /**
     * Receive binary data
     *
     * @param  buf         The buffer for the incoming data
     * @param  start       Offset in buffer to place the data
     * @param  len         Available space in buffer for the data
     * @return             Actual size of received data
     * @throws IOException If failed to receive incoming data
     */
    protected int data(byte[] buf, int start, int len) throws IOException {
        Buffer incoming = new ByteArrayBuffer(buf, start, len);
        // If we already have partial data, we need to append it to the buffer and use it
        if (receiveBuffer.available() > 0) {
            receiveBuffer.putBuffer(incoming);
            incoming = receiveBuffer;
        }

        // Process commands
        int rpos = incoming.rpos();
        boolean traceEnabled = log.isTraceEnabled();
        for (int count = 1; receive(incoming); count++) {
            if (traceEnabled) {
                log.trace("data({}) Processed {} data messages", getClientChannel(), count);
            }
        }

        int read = incoming.rpos() - rpos;
        // Compact and add remaining data
        receiveBuffer.compact();
        if ((receiveBuffer != incoming) && (incoming.available() > 0)) {
            receiveBuffer.putBuffer(incoming);
        }

        return read;
    }

    /**
     * Read SFTP packets from buffer
     *
     * @param  incoming    The received {@link Buffer}
     * @return             {@code true} if data from incoming buffer was processed
     * @throws IOException if failed to process the buffer
     * @see                #process(Buffer)
     */
    protected boolean receive(Buffer incoming) throws IOException {
        int rpos = incoming.rpos();
        int wpos = incoming.wpos();
        ClientSession session = getClientSession();
        session.resetIdleTimeout();

        if ((wpos - rpos) > 4) {
            int length = incoming.getInt();
            if (length < 5) {
                throw new IOException("Illegal sftp packet length: " + length);
            }
            if (length > (8 * SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                throw new StreamCorruptedException("Illogical sftp packet length: " + length);
            }
            if ((wpos - rpos) >= (length + 4)) {
                incoming.rpos(rpos);
                incoming.wpos(rpos + 4 + length);
                process(incoming);
                incoming.rpos(rpos + 4 + length);
                incoming.wpos(wpos);
                return true;
            }
        }
        incoming.rpos(rpos);
        return false;
    }

    /**
     * Process an SFTP packet
     *
     * @param  incoming    The received {@link Buffer}
     * @throws IOException if failed to process the buffer
     */
    protected void process(Buffer incoming) throws IOException {
        // create a copy of the buffer in case it is being re-used
        Buffer buffer = new ByteArrayBuffer(incoming.available() + Long.SIZE, false);
        buffer.putBuffer(incoming);

        int rpos = buffer.rpos();
        int length = buffer.getInt();
        int type = buffer.getUByte();
        Integer id = buffer.getInt();
        buffer.rpos(rpos);

        if (log.isTraceEnabled()) {
            log.trace("process({}) id={}, type={}, len={}",
                    getClientChannel(), id, SftpConstants.getCommandMessageName(type), length);
        }

        synchronized (messages) {
            messages.put(id, buffer);
            messages.notifyAll();
        }
    }

    @Override
    public int send(int cmd, Buffer buffer) throws IOException {
        int id = cmdId.incrementAndGet();
        int len = buffer.available();
        if (log.isTraceEnabled()) {
            log.trace("send({}) cmd={}, len={}, id={}",
                    getClientChannel(), SftpConstants.getCommandMessageName(cmd), len, id);
        }

        Buffer buf;
        int hdr = Integer.BYTES /* length */ + 1 /* cmd */ + Integer.BYTES /* id */;
        if (buffer.rpos() >= hdr) {
            int wpos = buffer.wpos();
            int s = buffer.rpos() - hdr;
            buffer.rpos(s);
            buffer.wpos(s);
            buffer.putInt(1 /* cmd */ + Integer.BYTES /* id */ + len); // length
            buffer.putByte((byte) (cmd & 0xFF)); // cmd
            buffer.putInt(id); // id
            buffer.wpos(wpos);
            buf = buffer;
        } else {
            buf = new ByteArrayBuffer(hdr + len);
            buf.putInt(1 /* cmd */ + Integer.BYTES /* id */ + len);
            buf.putByte((byte) (cmd & 0xFF));
            buf.putInt(id);
            buf.putBuffer(buffer);
        }

        IoOutputStream asyncIn = channel.getAsyncIn();
        IoWriteFuture writeFuture = asyncIn.writeBuffer(buf);
        writeFuture.verify();
        return id;
    }

    @Override
    public Buffer receive(int id) throws IOException {
        Session session = getClientSession();
        Duration idleTimeout = CoreModuleProperties.IDLE_TIMEOUT.getRequired(session);
        if (GenericUtils.isNegativeOrNull(idleTimeout)) {
            idleTimeout = CoreModuleProperties.IDLE_TIMEOUT.getRequiredDefault();
        }

        Instant now = Instant.now();
        Instant waitEnd = now.plus(idleTimeout);
        boolean traceEnabled = log.isTraceEnabled();
        for (int count = 1;; count++) {
            if (isClosing() || (!isOpen())) {
                throw new SshException("Channel is being closed");
            }
            if (now.compareTo(waitEnd) > 0) {
                throw new SshException("Timeout expired while waiting for id=" + id);
            }

            Buffer buffer = receive(id, Duration.between(now, waitEnd));
            if (buffer != null) {
                return buffer;
            }

            now = Instant.now();
            if (traceEnabled) {
                log.trace("receive({}) check iteration #{} for id={} remain time={}", this, count, id, idleTimeout);
            }
        }
    }

    @Override
    public Buffer receive(int id, long idleTimeout) throws IOException {
        return receive(id, Duration.ofMillis(idleTimeout));
    }

    @Override
    public Buffer receive(int id, Duration idleTimeout) throws IOException {
        synchronized (messages) {
            Buffer buffer = messages.remove(id);
            if (buffer != null) {
                return buffer;
            }
            if (GenericUtils.isPositive(idleTimeout)) {
                try {
                    messages.wait(idleTimeout.toMillis(), idleTimeout.getNano() % 1_000_000);
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException("Interrupted while waiting for messages").initCause(e);
                }
            }
        }
        return null;
    }

    protected void init(ClientSession session, SftpVersionSelector initialVersionSelector, Duration initializationTimeout)
            throws IOException {
        int initialVersion = (initialVersionSelector == null)
                ? SftpConstants.SFTP_V6
                : initialVersionSelector.selectVersion(
                        session, true, SftpConstants.SFTP_V6, SftpSubsystemEnvironment.SUPPORTED_SFTP_VERSIONS);
        ValidateUtils.checkState(SftpSubsystemEnvironment.SUPPORTED_SFTP_VERSIONS.contains(initialVersion),
                "Unsupported initial version selected: %d", initialVersion);

        // Send init packet
        Buffer buf = new ByteArrayBuffer(INIT_COMMAND_SIZE + SshConstants.SSH_PACKET_HEADER_LEN);
        buf.putInt(INIT_COMMAND_SIZE);
        buf.putByte((byte) SftpConstants.SSH_FXP_INIT);
        buf.putInt(initialVersion);

        boolean traceEnabled = log.isTraceEnabled();
        IoOutputStream asyncIn = channel.getAsyncIn();
        ClientChannel clientChannel = getClientChannel();
        if (traceEnabled) {
            log.trace("init({}) send SSH_FXP_INIT - initial version={}", clientChannel, initialVersion);
        }
        IoWriteFuture writeFuture = asyncIn.writeBuffer(buf);
        writeFuture.verify();

        if (traceEnabled) {
            log.trace("init({}) wait for SSH_FXP_INIT respose (timeout={})", clientChannel, initializationTimeout);
        }
        Buffer buffer = waitForInitResponse(initializationTimeout);
        handleInitResponse(buffer);
    }

    protected void handleInitResponse(Buffer buffer) throws IOException {
        boolean traceEnabled = log.isTraceEnabled();
        ClientChannel clientChannel = getClientChannel();
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (traceEnabled) {
            log.trace("handleInitResponse({}) id={} type={} len={}",
                    clientChannel, id, SftpConstants.getCommandMessageName(type), length);
        }

        if (type == SftpConstants.SSH_FXP_VERSION) {
            if ((id < SftpConstants.SFTP_V3) || (id > SftpConstants.SFTP_V6)) {
                throw new SshException("Unsupported sftp version " + id);
            }
            versionHolder.set(id);

            if (traceEnabled) {
                log.trace("handleInitResponse({}) version={}", clientChannel, versionHolder);
            }

            while (buffer.available() > 0) {
                String name = buffer.getString();
                byte[] data = buffer.getBytes();
                if (traceEnabled) {
                    log.trace("handleInitResponse({}) added extension={}", clientChannel, name);
                }
                extensions.put(name, data);
            }
        } else if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (traceEnabled) {
                log.trace("handleInitResponse({})[id={}] - status: {} [{}] {}",
                        clientChannel, id, SftpConstants.getStatusName(substatus), lang, msg);
            }

            throwStatusException(SftpConstants.SSH_FXP_INIT, id, substatus, msg, lang);
        } else {
            IOException err = handleUnexpectedPacket(
                    SftpConstants.SSH_FXP_INIT, SftpConstants.SSH_FXP_VERSION, id, type, length, buffer);
            if (err != null) {
                throw err;
            }

        }
    }

    protected Buffer waitForInitResponse(Duration initializationTimeout) throws IOException {
        ValidateUtils.checkTrue(GenericUtils.isPositive(initializationTimeout), "Invalid initialization timeout: %d",
                initializationTimeout);

        synchronized (messages) {
            /*
             * We need to use a timeout since if the remote server does not support SFTP, we will not know it
             * immediately. This is due to the fact that the request for the subsystem does not contain a reply as to
             * its success or failure. Thus, the SFTP channel is created by the client, but there is no one on the other
             * side to reply - thus the need for the timeout
             */
            Instant now = Instant.now();
            Instant max = now.plus(initializationTimeout);
            while ((now.compareTo(max) < 0) && messages.isEmpty() && (!isClosing()) && isOpen()) {
                try {
                    Duration rem = Duration.between(now, max);
                    messages.wait(rem.toMillis(), rem.getNano() % 1_000_000);
                    now = Instant.now();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException(
                            "Interrupted init() while " + Duration.between(now, max) + " remaining").initCause(e);
                }
            }

            if (isClosing() || (!isOpen())) {
                throw new EOFException("Closing while await init message");
            }

            if (messages.isEmpty()) {
                throw new SocketTimeoutException(
                        "No incoming initialization response received within " + initializationTimeout + " msec.");
            }

            Collection<Integer> ids = messages.keySet();
            Iterator<Integer> iter = ids.iterator();
            Integer reqId = iter.next();
            return messages.remove(reqId);
        }
    }

    /**
     * @param  selector    The {@link SftpVersionSelector} to use - ignored if {@code null}
     * @return             The selected version (may be same as current)
     * @throws IOException If failed to negotiate
     */
    public int negotiateVersion(SftpVersionSelector selector) throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        ClientChannel clientChannel = getClientChannel();
        int current = getVersion();
        if (selector == null) {
            if (debugEnabled) {
                log.debug("negotiateVersion({}) no selector to override current={}", clientChannel, current);
            }
            return current;
        }

        Map<String, ?> parsed = getParsedServerExtensions();
        Collection<String> extensions = ParserUtils.supportedExtensions(parsed);
        List<Integer> availableVersions = Collections.emptyList();
        if ((GenericUtils.size(extensions) > 0)
                && extensions.contains(SftpConstants.EXT_VERSION_SELECT)) {
            Versions vers = GenericUtils.isEmpty(parsed)
                    ? null
                    : (Versions) parsed.get(SftpConstants.EXT_VERSIONS);
            availableVersions = (vers == null)
                    ? Collections.singletonList(current)
                    : vers.resolveAvailableVersions(current);
        } else {
            availableVersions = Collections.singletonList(current);
        }

        ClientSession session = getClientSession();
        int selected = selector.selectVersion(session, false, current, availableVersions);
        if (debugEnabled) {
            log.debug("negotiateVersion({}) current={} {} -> {}",
                    clientChannel, current, availableVersions, selected);
        }

        if (selected == current) {
            return current;
        }

        if (!availableVersions.contains(selected)) {
            throw new StreamCorruptedException(
                    "Selected version (" + selected + ") not part of available: " + availableVersions);
        }

        String verVal = String.valueOf(selected);
        Buffer buffer = new ByteArrayBuffer(
                Integer.BYTES + SftpConstants.EXT_VERSION_SELECT.length() // extension name
                                            + Integer.BYTES + verVal.length() + Byte.SIZE,
                false);
        buffer.putString(SftpConstants.EXT_VERSION_SELECT);
        buffer.putString(verVal);
        checkCommandStatus(SftpConstants.SSH_FXP_EXTENDED, buffer);
        versionHolder.set(selected);
        return selected;
    }

    protected ChannelSubsystem createSftpChannelSubsystem(ClientSession clientSession) {
        return new SftpChannelSubsystem();
    }

    protected class SftpChannelSubsystem extends ChannelSubsystem {
        protected SftpChannelSubsystem() {
            super(SftpConstants.SFTP_SUBSYSTEM_NAME);
        }

        @Override
        protected void doOpen() throws IOException {
            String systemName = getSubsystem();
            Session session = getSession();
            boolean wantReply = CoreModuleProperties.REQUEST_SUBSYSTEM_REPLY.getRequired(this);
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST,
                    Channel.CHANNEL_SUBSYSTEM.length() + systemName.length() + Integer.SIZE);
            buffer.putInt(getRecipient());
            buffer.putString(Channel.CHANNEL_SUBSYSTEM);
            buffer.putBoolean(wantReply);
            buffer.putString(systemName);
            addPendingRequest(Channel.CHANNEL_SUBSYSTEM, wantReply);
            writePacket(buffer);

            asyncIn = createAsyncInput(session);
            setOut(createStdOutputStream(session));
            setErr(createErrOutputStream(session));
        }

        protected ChannelAsyncOutputStream createAsyncInput(Session session) {
            return new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA) {
                @SuppressWarnings("synthetic-access")
                @Override
                protected CloseFuture doCloseGracefully() {
                    try {
                        sendEof();
                    } catch (IOException e) {
                        session.exceptionCaught(e);
                    }
                    return super.doCloseGracefully();
                }
            };
        }

        protected OutputStream createStdOutputStream(Session session) {
            return new OutputStream() {
                private final byte[] singleByte = new byte[1];

                @Override
                public void write(int b) throws IOException {
                    synchronized (singleByte) {
                        singleByte[0] = (byte) b;
                        write(singleByte);
                    }
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    data(b, off, len);
                }
            };
        }

        protected OutputStream createErrOutputStream(Session session) {
            /*
             * The protocol does not specify how to handle such data but we are lenient and ignore it - similar to
             * /dev/null
             */
            return new NullOutputStream();
        }
    }
}
