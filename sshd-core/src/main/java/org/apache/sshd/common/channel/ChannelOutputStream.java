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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.exception.SshChannelClosedException;
import org.apache.sshd.common.io.PacketWriter;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelOutputStream extends OutputStream implements java.nio.channels.Channel, ChannelHolder {

    private final AbstractChannel channelInstance;
    private final PacketWriter packetWriter;
    private final Window remoteWindow;
    private final Duration maxWaitTimeout;
    private final Logger log;
    private final byte cmd;
    private final boolean eofOnClose;
    private final byte[] b = new byte[1];
    private final AtomicBoolean closedState = new AtomicBoolean(false);
    private Buffer buffer;
    private int bufferLength;
    private int lastSize;
    private boolean noDelay;

    public ChannelOutputStream(
                               AbstractChannel channel, Window remoteWindow, Logger log, byte cmd, boolean eofOnClose) {
        this(channel, remoteWindow,
             CoreModuleProperties.WAIT_FOR_SPACE_TIMEOUT.getRequired(channel),
             log, cmd, eofOnClose);
    }

    public ChannelOutputStream(
                               AbstractChannel channel, Window remoteWindow, long maxWaitTimeout, Logger log, byte cmd,
                               boolean eofOnClose) {
        this(channel, remoteWindow,
             Duration.ofMillis(maxWaitTimeout),
             log, cmd, eofOnClose);
    }

    public ChannelOutputStream(
                               AbstractChannel channel, Window remoteWindow, Duration maxWaitTimeout, Logger log, byte cmd,
                               boolean eofOnClose) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.packetWriter = channelInstance.resolveChannelStreamPacketWriter(channel, cmd);
        this.remoteWindow = Objects.requireNonNull(remoteWindow, "No remote window");
        Objects.requireNonNull(maxWaitTimeout, "No maxWaitTimeout");
        ValidateUtils.checkTrue(GenericUtils.isPositive(maxWaitTimeout), "Non-positive max. wait time: %s",
                maxWaitTimeout.toString());
        this.maxWaitTimeout = maxWaitTimeout;
        this.log = Objects.requireNonNull(log, "No logger");
        this.cmd = cmd;
        this.eofOnClose = eofOnClose;
        newBuffer(0);
    }

    @Override // co-variant return
    public AbstractChannel getChannel() {
        return channelInstance;
    }

    public boolean isEofOnClose() {
        return eofOnClose;
    }

    public void setNoDelay(boolean noDelay) {
        this.noDelay = noDelay;
    }

    public boolean isNoDelay() {
        return noDelay;
    }

    @Override
    public boolean isOpen() {
        return !closedState.get();
    }

    @Override
    public void write(int w) throws IOException {
        try {
            Channel channel = getChannel();
            Session session = channel.getSession();
            ((AbstractSession) session).executeUnderPendingPacketsLock(
                    getExtraPendingPacketLockWaitTime(1), () -> {
                        b[0] = (byte) w;
                        lockedWrite(session, channel, b, 0, 1);
                        return null;
                    });
        } catch (Exception e) {
            log.error("write(" + this + ") value=0x" + Integer.toHexString(w) + " failed to write", e);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }
    }

    @Override
    public void write(byte[] buf, int startOffset, int dataLen) throws IOException {
        try {
            Channel channel = getChannel();
            Session session = channel.getSession();
            ((AbstractSession) session).executeUnderPendingPacketsLock(
                    getExtraPendingPacketLockWaitTime(dataLen), () -> {
                        lockedWrite(session, channel, buf, startOffset, dataLen);
                        return null;
                    });
        } catch (Exception e) {
            log.error("write(" + this + ") len=" + dataLen + " failed to write", e);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }
    }

    protected void lockedWrite(
            Session session, Channel channel, byte[] buf, int startOffset, int dataLen)
            throws Exception {
        if (!isOpen()) {
            throw new SshChannelClosedException(
                    channel.getId(),
                    "lockedWrite(" + this + ") len=" + dataLen + " - channel already closed");
        }

        boolean debugEnabled = log.isDebugEnabled();
        boolean traceEnabled = log.isTraceEnabled();
        while (dataLen > 0) {
            // The maximum amount we should admit without flushing again
            // is enough to make up one full packet within our allowed
            // window size. We give ourselves a credit equal to the last
            // packet we sent to allow the producer to race ahead and fill
            // out the next packet before we block and wait for space to
            // become available again.
            long minReqLen = Math.min(remoteWindow.getSize() + lastSize, remoteWindow.getPacketSize());
            long l2 = Math.min(dataLen, minReqLen - bufferLength);
            if (l2 <= 0) {
                if (bufferLength > 0) {
                    lockedFlush(session, channel);
                } else {
                    session.resetIdleTimeout();
                    try {
                        long available = remoteWindow.waitForSpace(maxWaitTimeout);
                        if (traceEnabled) {
                            log.trace("lockedWrite({}) len={} - available={}", this, dataLen, available);
                        }
                    } catch (IOException e) {
                        log.error("lockedWrite({}) failed ({}) to wait for space of len={}: {}",
                                this, e.getClass().getSimpleName(), dataLen, e.getMessage());

                        if ((e instanceof WindowClosedException) && (!closedState.getAndSet(true))) {
                            if (debugEnabled) {
                                log.debug("lockedWrite({})[len={}] closing due to window closed", this, dataLen);
                            }
                        }

                        throw e;
                    } catch (InterruptedException e) {
                        throw (IOException) new InterruptedIOException(
                                "Interrupted while waiting for remote space on write len=" + dataLen + " to " + this)
                                        .initCause(e);
                    }
                }
                session.resetIdleTimeout();
                continue;
            }

            ValidateUtils.checkTrue(l2 <= Integer.MAX_VALUE,
                    "Accumulated bytes length exceeds int boundary: %d", l2);
            buffer.putRawBytes(buf, startOffset, (int) l2);
            bufferLength += l2;
            startOffset += l2;
            dataLen -= l2;
        }

        if (isNoDelay()) {
            lockedFlush(session, channel);
        } else {
            session.resetIdleTimeout();
        }
    }

    @Override
    public void flush() throws IOException {
        Channel channel = getChannel();
        Session session = channel.getSession();
        try {
            ((AbstractSession) session).executeUnderPendingPacketsLock(
                    getExtraPendingPacketLockWaitTime(bufferLength),
                    () -> {
                        lockedFlush(session, channel);
                        return null;
                    });
        } catch (WindowClosedException e) {
            if (!closedState.getAndSet(true)) {
                if (log.isDebugEnabled()) {
                    log.debug("flush({}) closing due to window closed", this);
                }
            }
            throw e;
        } catch (Exception e) {
            log.error("flush(" + this + ") failed", e);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else if (e instanceof InterruptedException) {
                throw (IOException) new InterruptedIOException(
                        "Interrupted while waiting for remote space flush len=" + bufferLength + " to " + this)
                                .initCause(e);
            } else {
                throw new SshException(e);
            }
        }
    }

    protected void lockedFlush(Session session, Channel channel) throws Exception {
        boolean traceEnabled = log.isTraceEnabled();
        if (!isOpen()) {
            if (bufferLength > 0) {
                throw new SshChannelClosedException(
                        channel.getId(),
                        "lockedFlush(" + this + ") length=" + bufferLength + " - stream is already closed");
            }

            if (traceEnabled) {
                log.trace("lockedFlush({}) nothing to flush", this);
            }
            return;
        }

        while (bufferLength > 0) {
            session.resetIdleTimeout();

            Buffer buf = buffer;
            long total = bufferLength;
            long available;
            try {
                available = remoteWindow.waitForSpace(maxWaitTimeout);
                if (traceEnabled) {
                    log.trace("lockedFlush({}) len={}, available={}", this, total, available);
                }
            } catch (IOException e) {
                log.error("lockedFlush({}) failed ({}) to wait for space of len={}: {}",
                        this, e.getClass().getSimpleName(), total, e.getMessage());
                if (log.isDebugEnabled()) {
                    log.error("lockedFlush(" + this + ") wait for space len=" + total + " exception details", e);
                }
                throw e;
            }

            long lenToSend = Math.min(available, total);
            long length = Math.min(lenToSend, remoteWindow.getPacketSize());
            if (length > Integer.MAX_VALUE) {
                throw new StreamCorruptedException(
                        "Accumulated " + SshConstants.getCommandMessageName(cmd)
                                                   + " command bytes size (" + length
                                                   + ") exceeds int boundaries");
            }

            int pos = buf.wpos();
            buf.wpos((cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) ? 14 : 10);
            buf.putInt(length);
            buf.wpos(buf.wpos() + (int) length);
            if (total == length) {
                newBuffer((int) length);
            } else {
                long leftover = total - length;
                newBuffer((int) Math.max(leftover, length));
                buffer.putRawBytes(buf.array(), pos - (int) leftover, (int) leftover);
                bufferLength = (int) leftover;
            }
            lastSize = (int) length;

            session.resetIdleTimeout();
            remoteWindow.waitAndConsume(length, maxWaitTimeout);
            if (traceEnabled) {
                log.trace("lockedFlush({}) send len={}", this, length);
            }
            packetWriter.writePacket(buf);
        }
    }

    // TODO see if can do anything better
    protected long getExtraPendingPacketLockWaitTime(int dataSize) {
        Duration minTimeout = CoreModuleProperties.NIO2_MIN_WRITE_TIMEOUT.get(getChannel()).orElse(null);
        long minValue = (minTimeout == null) ? dataSize : minTimeout.toMillis();
        return Math.min(dataSize, minValue) + maxWaitTimeout.toMillis();
    }

    protected void lockedClose(Session session, AbstractChannel channel) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace("lockedClose({}) closing", this);
        }

        try {
            lockedFlush(session, channel);

            if (isEofOnClose()) {
                channel.sendEof();
            }
        } finally {
            try {
                if (!(packetWriter instanceof Channel)) {
                    packetWriter.close();
                }
            } finally {
                closedState.set(true);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!isOpen()) {
            return;
        }

        AbstractChannel channel = getChannel();
        Session session = channel.getSession();
        try {
            ((AbstractSession) session).executeUnderPendingPacketsLock(
                    getExtraPendingPacketLockWaitTime(bufferLength),
                    () -> {
                        lockedClose(session, channel);
                        return null;
                    });
        } catch (Exception e) {
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeSshException(e);
            }
        }
    }

    protected void newBuffer(int size) {
        Channel channel = getChannel();
        Session session = channel.getSession();
        buffer = session.createBuffer(cmd, size <= 0 ? 12 : 12 + size);
        buffer.putInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buffer.putInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
        }
        buffer.putInt(0);
        bufferLength = 0;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] " + SshConstants.getCommandMessageName(cmd & 0xFF);
    }
}
