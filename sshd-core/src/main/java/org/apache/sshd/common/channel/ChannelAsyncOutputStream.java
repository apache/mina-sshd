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

import java.io.EOFException;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

public class ChannelAsyncOutputStream extends AbstractCloseable implements IoOutputStream, ChannelHolder {
    private final Channel channelInstance;
    private final ChannelStreamWriter packetWriter;
    private final byte cmd;
    private final AtomicReference<IoWriteFutureImpl> pendingWrite = new AtomicReference<>();
    private final Object packetWriteId;

    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.packetWriter = channelInstance.resolveChannelStreamWriter(channel, cmd);
        this.cmd = cmd;
        this.packetWriteId = channel.toString() + "[" + SshConstants.getCommandMessageName(cmd) + "]";
    }

    @Override
    public Channel getChannel() {
        return channelInstance;
    }

    public void onWindowExpanded() throws IOException {
        doWriteIfPossible(true);
    }

    @Override
    public synchronized IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
        if (isClosing()) {
            throw new EOFException("Closing: " + state);
        }

        IoWriteFutureImpl future = new IoWriteFutureImpl(packetWriteId, buffer);
        if (!pendingWrite.compareAndSet(null, future)) {
            throw new WritePendingException("A write operation is already pending");
        }
        doWriteIfPossible(false);
        return future;
    }

    @Override
    protected void preClose() {
        if (!(packetWriter instanceof Channel)) {
            try {
                packetWriter.close();
            } catch (IOException e) {
                error("preClose({}) Failed ({}) to pre-close packet writer: {}",
                        this, e.getClass().getSimpleName(), e.getMessage(), e);
            }
        }

        super.preClose();
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        return builder().when(pendingWrite.get()).build().close(false);
    }

    protected synchronized void doWriteIfPossible(boolean resume) {
        IoWriteFutureImpl future = pendingWrite.get();
        if (future == null) {
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({})[resume={}] no pending write future", this, resume);
            }
            return;
        }

        Buffer buffer = future.getBuffer();
        int total = buffer.available();
        if (total > 0) {
            Channel channel = getChannel();
            Window remoteWindow = channel.getRemoteWindow();
            long length;
            long remoteWindowSize = remoteWindow.getSize();
            long packetSize = remoteWindow.getPacketSize();
            if (total > remoteWindowSize) {
                // if we have a big message and there is enough space, send the next chunk
                if (remoteWindowSize >= packetSize) {
                    // send the first chunk as we have enough space in the window
                    length = packetSize;
                } else {
                    // do not chunk when the window is smaller than the packet size
                    length = 0;
                    // do a defensive copy in case the user reuses the buffer
                    IoWriteFutureImpl f = new IoWriteFutureImpl(future.getId(), new ByteArrayBuffer(buffer.getCompactData()));
                    f.addListener(w -> future.setValue(w.getException() != null ? w.getException() : w.isWritten()));
                    pendingWrite.set(f);
                    if (log.isTraceEnabled()) {
                        log.trace("doWriteIfPossible({})[resume={}] waiting for window space {}",
                                this, resume, remoteWindowSize);
                    }
                }
            } else if (total > packetSize) {
                if (buffer.rpos() > 0) {
                    // do a defensive copy in case the user reuses the buffer
                    IoWriteFutureImpl f = new IoWriteFutureImpl(future.getId(), new ByteArrayBuffer(buffer.getCompactData()));
                    f.addListener(w -> future.setValue(w.getException() != null ? w.getException() : w.isWritten()));
                    pendingWrite.set(f);
                    length = packetSize;
                    if (log.isTraceEnabled()) {
                        log.trace("doWriteIfPossible({})[resume={}] attempting to write {} out of {}",
                                this, resume, length, total);
                    }
                    doWriteIfPossible(resume);
                    return;
                } else {
                    length = packetSize;
                }
            } else {
                length = total;
                if (log.isTraceEnabled()) {
                    log.trace("doWriteIfPossible({})[resume={}] attempting to write {} bytes", this, resume, length);
                }
            }

            if (length > 0) {
                if (resume) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resuming {} write due to more space ({}) available in the remote window", this, length);
                    }
                }

                if (length >= (Integer.MAX_VALUE - 12)) {
                    throw new IllegalArgumentException(
                            "Command " + SshConstants.getCommandMessageName(cmd) + " length (" + length
                                                       + ") exceeds int boundaries");
                }

                Buffer buf = createSendBuffer(buffer, channel, length);
                remoteWindow.consume(length);

                try {
                    IoWriteFuture writeFuture = packetWriter.writeData(buf);
                    writeFuture.addListener(f -> onWritten(future, total, length, f));
                } catch (IOException e) {
                    future.setValue(e);
                }
            } else if (!resume) {
                if (log.isDebugEnabled()) {
                    log.debug("doWriteIfPossible({}) delaying write until space is available in the remote window", this);
                }
            }
        } else {
            boolean nullified = pendingWrite.compareAndSet(future, null);
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({}) current buffer sent - more={}", this, !nullified);
            }
            future.setValue(Boolean.TRUE);
        }
    }

    protected void onWritten(IoWriteFutureImpl future, int total, long length, IoWriteFuture f) {
        if (f.isWritten()) {
            if (total > length) {
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write of {} out of {}",
                            this, length, total);
                }
                doWriteIfPossible(false);
            } else {
                boolean nullified = pendingWrite.compareAndSet(future, null);
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write len={}, more={}",
                            this, total, !nullified);
                }
                future.setValue(Boolean.TRUE);
            }
        } else {
            Throwable reason = f.getException();
            debug("onWritten({}) failed ({}) to complete write of {} out of {}: {}",
                    this, reason.getClass().getSimpleName(), length, total, reason.getMessage(), reason);
            boolean nullified = pendingWrite.compareAndSet(future, null);
            if (log.isTraceEnabled()) {
                log.trace("onWritten({}) failed write len={}, more={}",
                        this, total, !nullified);
            }
            future.setValue(reason);
        }
    }

    protected Buffer createSendBuffer(Buffer buffer, Channel channel, long length) {
        Session s = channel.getSession();
        Buffer buf = s.createBuffer(cmd, (int) length + 12);
        buf.putInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buf.putInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
        }
        buf.putInt(length);
        buf.putRawBytes(buffer.array(), buffer.rpos(), (int) length);
        buffer.rpos(buffer.rpos() + (int) length);
        return buf;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] cmd=" + SshConstants.getCommandMessageName(cmd & 0xFF);
    }
}
