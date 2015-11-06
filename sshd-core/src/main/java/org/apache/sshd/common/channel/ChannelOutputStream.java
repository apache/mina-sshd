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
import java.nio.channels.Channel;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.slf4j.Logger;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelOutputStream extends OutputStream implements Channel {
    /**
     * Configure max. wait time (millis) to wait for space to become available
     */
    public static final String WAIT_FOR_SPACE_TIMEOUT = "channel-output-wait-for-space-timeout";
    public static final long DEFAULT_WAIT_FOR_SPACE_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    private final AbstractChannel channel;
    private final Window remoteWindow;
    private final long maxWaitTimeout;
    private final Logger log;
    private final byte cmd;
    private final byte[] b = new byte[1];
    private final AtomicBoolean closedState = new AtomicBoolean(false);
    private Buffer buffer;
    private int bufferLength;
    private int lastSize;
    private boolean noDelay;

    public ChannelOutputStream(AbstractChannel channel, Window remoteWindow, Logger log, byte cmd) {
        this(channel, remoteWindow, PropertyResolverUtils.getLongProperty(channel, WAIT_FOR_SPACE_TIMEOUT, DEFAULT_WAIT_FOR_SPACE_TIMEOUT), log, cmd);
    }

    public ChannelOutputStream(AbstractChannel channel, Window remoteWindow, long maxWaitTimeout, Logger log, byte cmd) {
        this.channel = ValidateUtils.checkNotNull(channel, "No channel");
        this.remoteWindow = ValidateUtils.checkNotNull(remoteWindow, "No remote window");
        ValidateUtils.checkTrue(maxWaitTimeout > 0L, "Non-positive max. wait time: %d", maxWaitTimeout);
        this.maxWaitTimeout = maxWaitTimeout;
        this.log = ValidateUtils.checkNotNull(log, "No logger");
        this.cmd = cmd;
        newBuffer(0);
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
        if (!isOpen()) {
            throw new SshException("write(" + this + ") len=" + l + " - channel already closed");
        }

        Session session = channel.getSession();
        while (l > 0) {
            // The maximum amount we should admit without flushing again
            // is enough to make up one full packet within our allowed
            // window size.  We give ourselves a credit equal to the last
            // packet we sent to allow the producer to race ahead and fill
            // out the next packet before we block and wait for space to
            // become available again.
            int l2 = Math.min(l, Math.min(remoteWindow.getSize() + lastSize, remoteWindow.getPacketSize()) - bufferLength);
            if (l2 <= 0) {
                if (bufferLength > 0) {
                    flush();
                } else {
                    session.resetIdleTimeout();
                    try {
                        remoteWindow.waitForSpace(maxWaitTimeout);
                    } catch (WindowClosedException e) {
                        if (!closedState.getAndSet(true)) {
                            if (log.isDebugEnabled()) {
                                log.debug("write({})[len={}] closing due to window closed", this, l);
                            }
                        }
                        throw e;
                    } catch (InterruptedException e) {
                        throw (IOException) new InterruptedIOException("Interrupted while waiting for remote space on write len=" + l + " to " + this).initCause(e);
                    }
                }
                session.resetIdleTimeout();
                continue;
            }
            buffer.putRawBytes(buf, s, l2);
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
        if (!isOpen()) {
            throw new SshException("flush(" + this + ") length=" + bufferLength + " - stream is already closed");
        }

        try {
            Session session = channel.getSession();
            while (bufferLength > 0) {
                session.resetIdleTimeout();

                Buffer buf = buffer;
                int total = bufferLength;
                int available = remoteWindow.waitForSpace(maxWaitTimeout);
                int length = Math.min(Math.min(available, total), remoteWindow.getPacketSize());
                int pos = buf.wpos();
                buf.wpos((cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) ? 14 : 10);
                buf.putInt(length);
                buf.wpos(buf.wpos() + length);
                if (total == length) {
                    newBuffer(length);
                } else {
                    int leftover = total - length;
                    newBuffer(Math.max(leftover, length));
                    buffer.putRawBytes(buf.array(), pos - leftover, leftover);
                    bufferLength = leftover;
                }
                lastSize = length;

                session.resetIdleTimeout();
                remoteWindow.waitAndConsume(length, maxWaitTimeout);
                if (log.isTraceEnabled()) {
                    log.trace("Send {} on channel {}",
                              (cmd == SshConstants.SSH_MSG_CHANNEL_DATA) ? "SSH_MSG_CHANNEL_DATA" : "SSH_MSG_CHANNEL_EXTENDED_DATA",
                              channel);
                }
                channel.writePacket(buf);
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
            } else {
                throw new SshException(e);
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (isOpen()) {
            if (log.isTraceEnabled()) {
                log.trace("close({}) closing", this);
            }

            try {
                flush();
                channel.sendEof();
            } finally {
                closedState.set(true);
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + channel + "]";
    }

    protected void newBuffer(int size) {
        Session session = channel.getSession();
        buffer = session.createBuffer(cmd, size <= 0 ? 12 : 12 + size);
        buffer.putInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buffer.putInt(1);
        }
        buffer.putInt(0);
        bufferLength = 0;
    }
}
