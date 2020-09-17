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

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.exception.SshChannelClosedException;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelOutputStream extends OutputStream implements java.nio.channels.Channel, ChannelHolder {

    private final AbstractChannel channelInstance;
    private final ChannelStreamWriter packetWriter;
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
        this.packetWriter = channelInstance.resolveChannelStreamWriter(channel, cmd);
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
    public synchronized void write(int w) throws IOException {
        b[0] = (byte) w;
        write(b, 0, 1);
    }

    @Override
    public synchronized void write(byte[] buf, int s, int l) throws IOException {
        Channel channel = getChannel();
        if (!isOpen()) {
            throw new SshChannelClosedException(
                    channel.getId(),
                    "write(" + this + ") len=" + l + " - channel already closed");
        }

        Session session = channel.getSession();
        boolean debugEnabled = log.isDebugEnabled();
        boolean traceEnabled = log.isTraceEnabled();
        while (l > 0) {
            // The maximum amount we should admit without flushing again
            // is enough to make up one full packet within our allowed
            // window size. We give ourselves a credit equal to the last
            // packet we sent to allow the producer to race ahead and fill
            // out the next packet before we block and wait for space to
            // become available again.
            long minReqLen = Math.min(remoteWindow.getSize() + lastSize, remoteWindow.getPacketSize());
            long l2 = Math.min(l, minReqLen - bufferLength);
            if (l2 <= 0) {
                if (bufferLength > 0) {
                    flush();
                } else {
                    session.resetIdleTimeout();
                    try {
                        long available = remoteWindow.waitForSpace(maxWaitTimeout);
                        if (traceEnabled) {
                            log.trace("write({}) len={} - available={}", this, l, available);
                        }
                    } catch (IOException e) {
                        LoggingUtils.debug(log, "write({}) failed ({}) to wait for space of len={}: {}",
                                this, e.getClass().getSimpleName(), l, e.getMessage(), e);

                        if ((e instanceof WindowClosedException) && (!closedState.getAndSet(true))) {
                            if (debugEnabled) {
                                log.debug("write({})[len={}] closing due to window closed", this, l);
                            }
                        }

                        throw e;
                    } catch (InterruptedException e) {
                        throw (IOException) new InterruptedIOException(
                                "Interrupted while waiting for remote space on write len=" + l + " to " + this)
                                        .initCause(e);
                    }
                }
                session.resetIdleTimeout();
                continue;
            }

            ValidateUtils.checkTrue(l2 <= Integer.MAX_VALUE,
                    "Accumulated bytes length exceeds int boundary: %d", l2);
            buffer.putRawBytes(buf, s, (int) l2);
            bufferLength += l2;
            s += l2;
            l -= l2;
        }

        if (isNoDelay()) {
            flush();
        } else {
            session.resetIdleTimeout();
        }
    }

    @Override
    public synchronized void flush() throws IOException {
        AbstractChannel channel = getChannel();
        if (!isOpen()) {
            throw new SshChannelClosedException(
                    channel.getId(),
                    "flush(" + this + ") length=" + bufferLength + " - stream is already closed");
        }

        try {
            Session session = channel.getSession();
            boolean traceEnabled = log.isTraceEnabled();
            while (bufferLength > 0) {
                session.resetIdleTimeout();

                Buffer buf = buffer;
                long total = bufferLength;
                long available;
                try {
                    available = remoteWindow.waitForSpace(maxWaitTimeout);
                    if (traceEnabled) {
                        log.trace("flush({}) len={}, available={}", this, total, available);
                    }
                } catch (IOException e) {
                    LoggingUtils.debug(log, "flush({}) failed ({}) to wait for space of len={}: {}",
                            this, e.getClass().getSimpleName(), total, e.getMessage(), e);
                    throw e;
                }

                long lenToSend = Math.min(available, total);
                long length = Math.min(lenToSend, remoteWindow.getPacketSize());
                if (length > Integer.MAX_VALUE) {
                    throw new StreamCorruptedException(
                            "Accumulated " + SshConstants.getCommandMessageName(cmd)
                                                       + " command bytes size (" + length + ") exceeds int boundaries");
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
                    log.trace("flush({}) send {} len={}",
                            channel, SshConstants.getCommandMessageName(cmd), length);
                }
                packetWriter.writeData(buf);
            }
        } catch (WindowClosedException e) {
            if (!closedState.getAndSet(true)) {
                if (log.isDebugEnabled()) {
                    log.debug("flush({}) closing due to window closed", this);
                }
            }
            throw e;
        } catch (Exception e) {
            if (e instanceof IOException) {
                throw (IOException) e;
            } else if (e instanceof InterruptedException) {
                throw (IOException) new InterruptedIOException(
                        "Interrupted while waiting for remote space flush len=" + bufferLength + " to " + this)
                                .initCause(e);
            } else {
                throw new SshException(e);
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (!isOpen()) {
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("close({}) closing", this);
        }

        try {
            flush();

            if (isEofOnClose()) {
                AbstractChannel channel = getChannel();
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
