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
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.PacketWriter;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

public class ChannelAsyncOutputStream extends AbstractCloseable implements IoOutputStream, ChannelHolder {
    private final Channel channelInstance;
    private final PacketWriter packetWriter;
    private final byte cmd;
    private final AtomicReference<IoWriteFutureImpl> pendingWrite = new AtomicReference<>();
    private final Object packetWriteId;

    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.packetWriter = channelInstance.resolveChannelStreamPacketWriter(channel, cmd);
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
    public synchronized IoWriteFuture writePacket(Buffer buffer) throws IOException {
        if (isClosing()) {
            throw new EOFException("Closed");
        }

        IoWriteFutureImpl future = new IoWriteFutureImpl(packetWriteId, buffer);
        if (!pendingWrite.compareAndSet(null, future)) {
            throw new WritePendingException("No write pending future");
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
                log.error("preClose({}) Failed ({}) to pre-close packet writer: {}",
                        this, e.getClass().getSimpleName(), e.getMessage());
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
            long length = Math.min(Math.min(remoteWindow.getSize(), total), remoteWindow.getPacketSize());
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({})[resume={}] attempting to write {} out of {}", this, resume, length, total);
            }

            if (length > 0) {
                if (resume) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resuming {} write due to more space ({}) available in the remote window", this, length);
                    }
                }

                if (length >= (Integer.MAX_VALUE - 12)) {
                    throw new IllegalArgumentException("Command " + SshConstants.getCommandMessageName(cmd) + " length (" + length + ") exceeds int boundaries");
                }

                Session s = channel.getSession();
                Buffer buf = s.createBuffer(cmd, (int) length + 12);
                buf.putInt(channel.getRecipient());
                if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
                    buf.putInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
                }
                buf.putInt(length);
                buf.putRawBytes(buffer.array(), buffer.rpos(), (int) length);
                buffer.rpos(buffer.rpos() + (int) length);
                remoteWindow.consume(length);

                try {
                    ChannelAsyncOutputStream stream = this;
                    IoWriteFuture writeFuture = packetWriter.writePacket(buf);
                    writeFuture.addListener(new SshFutureListener<IoWriteFuture>() {
                        @Override
                        public void operationComplete(IoWriteFuture f) {
                            if (f.isWritten()) {
                                handleOperationCompleted();
                            } else {
                                handleOperationFailed(f.getException());
                            }
                        }

                        @SuppressWarnings("synthetic-access")
                        private void handleOperationCompleted() {
                            if (total > length) {
                                if (log.isTraceEnabled()) {
                                    log.trace("doWriteIfPossible({}) completed write of {} out of {}", stream, length, total);
                                }
                                doWriteIfPossible(false);
                            } else {
                                boolean nullified = pendingWrite.compareAndSet(future, null);
                                if (log.isTraceEnabled()) {
                                    log.trace("doWriteIfPossible({}) completed write len={}, more={}",
                                              stream, total, !nullified);
                                }
                                future.setValue(Boolean.TRUE);
                            }
                        }

                        @SuppressWarnings("synthetic-access")
                        private void handleOperationFailed(Throwable reason) {
                            if (log.isDebugEnabled()) {
                                log.debug("doWriteIfPossible({}) failed ({}) to complete write of {} out of {}: {}",
                                          stream, reason.getClass().getSimpleName(), length, total, reason.getMessage());
                            }

                            if (log.isTraceEnabled()) {
                                log.trace("doWriteIfPossible(" + this + ") write failure details", reason);
                            }

                            boolean nullified = pendingWrite.compareAndSet(future, null);
                            if (log.isTraceEnabled()) {
                                log.trace("doWriteIfPossible({}) failed write len={}, more={}",
                                          stream, total, !nullified);
                            }
                            future.setValue(reason);
                        }
                    });
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

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] cmd=" + SshConstants.getCommandMessageName(cmd & 0xFF);
    }
}
