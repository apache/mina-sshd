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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

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

    protected enum WriteState {
        BUFFERED,
        NEED_FLUSH,
        NEED_SPACE
    }

    protected enum OpenState {
        OPEN,
        CLOSING,
        CLOSED
    }

    protected final AtomicReference<OpenState> openState = new AtomicReference<>(OpenState.OPEN);

    protected final Logger log;

    private final AbstractChannel channelInstance;
    private final ChannelStreamWriter packetWriter;
    private final RemoteWindow remoteWindow;
    private final Duration maxWaitTimeout;
    private final byte cmd;
    private final boolean eofOnClose;
    private final AtomicBoolean noDelay = new AtomicBoolean();

    private final Object bufferLock = new Object();
    private Buffer buffer;
    private int bufferLength;
    private int lastSize;
    private boolean isFlushing;

    public ChannelOutputStream(AbstractChannel channel, RemoteWindow remoteWindow, Logger log, byte cmd, boolean eofOnClose) {
        this(channel, remoteWindow,
             CoreModuleProperties.WAIT_FOR_SPACE_TIMEOUT.getRequired(channel),
             log, cmd, eofOnClose);
    }

    public ChannelOutputStream(AbstractChannel channel, RemoteWindow remoteWindow, long maxWaitTimeout, Logger log, byte cmd,
                               boolean eofOnClose) {
        this(channel, remoteWindow,
             Duration.ofMillis(maxWaitTimeout),
             log, cmd, eofOnClose);
    }

    public ChannelOutputStream(AbstractChannel channel, RemoteWindow remoteWindow, Duration maxWaitTimeout, Logger log,
                               byte cmd, boolean eofOnClose) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.packetWriter = channelInstance.resolveChannelStreamWriter(channel, cmd);
        this.remoteWindow = Objects.requireNonNull(remoteWindow, "No remote window");
        Objects.requireNonNull(maxWaitTimeout, "No maxWaitTimeout");
        ValidateUtils.checkTrue(GenericUtils.isPositive(maxWaitTimeout), "Non-positive max. wait time: %s", maxWaitTimeout);
        this.maxWaitTimeout = maxWaitTimeout;
        this.log = Objects.requireNonNull(log, "No logger");
        this.cmd = cmd;
        this.eofOnClose = eofOnClose;
        buffer = newBuffer(0);
    }

    @Override // co-variant return
    public AbstractChannel getChannel() {
        return channelInstance;
    }

    /**
     * @return Either {@link SshConstants#SSH_MSG_CHANNEL_DATA SSH_MSG_CHANNEL_DATA} or
     *         {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA SSH_MSG_CHANNEL_EXTENDED_DATA} indicating the output
     *         stream type
     */
    public byte getCommandType() {
        return cmd;
    }

    public boolean isEofOnClose() {
        return eofOnClose;
    }

    public boolean isNoDelay() {
        return noDelay.get();
    }

    public void setNoDelay(boolean noDelay) {
        this.noDelay.set(noDelay);
    }

    @Override
    public boolean isOpen() {
        return OpenState.OPEN == openState.get();
    }

    @Override
    public void write(int w) throws IOException {
        write(new byte[] { (byte) w }, 0, 1);
    }

    @Override
    public synchronized void write(byte[] buf, int s, int l) throws IOException {
        // This is the only use of this instance's monitor; it's used exclusively to synchronize concurrent writes.
        Channel channel = getChannel();
        if (!isOpen()) {
            throw new SshChannelClosedException(channel.getChannelId(),
                    "write(" + this + ") len=" + l + " - channel already closed");
        }
        Session session = channel.getSession();
        boolean debugEnabled = log.isDebugEnabled();
        boolean traceEnabled = log.isTraceEnabled();
        boolean flushed = false;
        WriteState state;
        int nanos = maxWaitTimeout.getNano();
        long millisInSecond = TimeUnit.NANOSECONDS.toMillis(nanos);
        long millis = TimeUnit.SECONDS.toMillis(maxWaitTimeout.getSeconds()) + millisInSecond;
        nanos -= TimeUnit.MILLISECONDS.toNanos(millisInSecond);
        while (l > 0) {
            flushed = false;
            state = WriteState.BUFFERED;
            synchronized (bufferLock) {
                while (isFlushing) {
                    try {
                        bufferLock.wait(millis, nanos);
                    } catch (InterruptedException e) {
                        InterruptedIOException interrupted = new InterruptedIOException(
                                channel.getChannelId() + ": write interrupted waiting for flush()");
                        interrupted.initCause(e);
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
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
                            state = WriteState.NEED_FLUSH;
                        } else {
                            state = WriteState.NEED_SPACE;
                        }
                        session.resetIdleTimeout();
                        break;
                    }

                    ValidateUtils.checkTrue(l2 <= Integer.MAX_VALUE, "Accumulated bytes length exceeds int boundary: %d", l2);
                    buffer.putRawBytes(buf, s, (int) l2);
                    bufferLength += l2;
                    s += l2;
                    l -= l2;
                }
            }
            switch (state) {
                case NEED_FLUSH:
                    flush();
                    flushed = true;
                    session.resetIdleTimeout();
                    break;
                case NEED_SPACE:
                    try {
                        long available = remoteWindow.waitForSpace(maxWaitTimeout);
                        if (traceEnabled) {
                            log.trace("write({}) len={} - available={}", this, l, available);
                        }
                    } catch (IOException e) {
                        LoggingUtils.debug(log, "write({}) failed ({}) to wait for space of len={}: {}",
                                this, e.getClass().getSimpleName(), l, e.getMessage(), e);

                        if ((e instanceof WindowClosedException) && (OpenState.OPEN == openState.getAndSet(OpenState.CLOSED))) {
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
                    session.resetIdleTimeout();
                    break;
                default:
                    // BUFFERED implies l == 0; outer loop will terminate
                    break;
            }
        }

        if (isNoDelay() && !flushed) {
            flush();
        } else {
            session.resetIdleTimeout();
        }
    }

    @Override
    public void flush() throws IOException {
        // Concurrent flushes are OK. We choose the simple way: if a flush is already going on, the second flush is
        // simply a no-op.
        //
        // The framework may flush concurrently when it closes the stream if there is an exception at an inopportune
        // moment, for instance during KEX.
        Channel channel = getChannel();
        if (OpenState.CLOSED.equals(openState.get())) {
            throw new SshChannelClosedException(channel.getChannelId(),
                    "flush(" + this + ") length=" + bufferLength + " - stream is already closed");
        }

        Session session = channel.getSession();
        boolean traceEnabled = log.isTraceEnabled();
        Buffer buf;
        int remaining;
        synchronized (bufferLock) {
            remaining = bufferLength;
            if (isFlushing) {
                return;
            }
            if (remaining == 0) {
                bufferLock.notifyAll();
                return;
            }
            isFlushing = true;
            buf = buffer;
        }
        try {
            while (remaining > 0) {
                session.resetIdleTimeout();

                long total = remaining;
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
                    throw new StreamCorruptedException("Accumulated " + SshConstants.getCommandMessageName(cmd)
                                                       + " command bytes size (" + length + ") exceeds int boundaries");
                }

                int pos = buf.wpos();
                buf.wpos((cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) ? 14 : 10);
                buf.putUInt(length);
                buf.wpos(buf.wpos() + (int) length);
                Buffer freshBuffer;
                if (total == length) {
                    freshBuffer = newBuffer((int) length);
                    remaining = 0;
                } else {
                    long leftover = total - length;
                    freshBuffer = newBuffer((int) Math.max(leftover, length));
                    freshBuffer.putRawBytes(buf.array(), pos - (int) leftover, (int) leftover);
                    remaining = (int) leftover;
                }
                synchronized (bufferLock) {
                    buffer = freshBuffer;
                    bufferLength = remaining;
                    lastSize = (int) length;
                }

                session.resetIdleTimeout();
                remoteWindow.waitAndConsume(length, maxWaitTimeout);
                if (traceEnabled) {
                    log.trace("flush({}) send {} len={}",
                            channel, SshConstants.getCommandMessageName(cmd), length);
                }
                packetWriter.writeData(buf);
                buf = freshBuffer;
            }
        } catch (WindowClosedException e) {
            if (OpenState.OPEN == openState.getAndSet(OpenState.CLOSED)) {
                if (log.isDebugEnabled()) {
                    log.debug("flush({}) closing due to window closed", this);
                }
            }
            throw e;
        } catch (InterruptedException e) {
            throw (IOException) new InterruptedIOException(
                    "Interrupted while waiting for remote space flush len=" + bufferLength + " to " + this).initCause(e);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        } finally {
            synchronized (bufferLock) {
                isFlushing = false;
                bufferLock.notifyAll();
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!openState.compareAndSet(OpenState.OPEN, OpenState.CLOSING)) {
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
                openState.set(OpenState.CLOSED);
            }
        }
    }

    protected Buffer newBuffer(int size) {
        Channel channel = getChannel();
        Session session = channel.getSession();
        Buffer buf = session.createBuffer(cmd, size <= 0 ? 12 : 12 + size);
        buf.putUInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buf.putUInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
        }
        buf.putUInt(0L);
        return buf;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] " + SshConstants.getCommandMessageName(cmd & 0xFF);
    }
}
