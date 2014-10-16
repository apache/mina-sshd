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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Channel;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;

public class ChannelAsyncOutputStream extends CloseableUtils.AbstractCloseable implements IoOutputStream {

    private final Channel channel;
    private final byte cmd;
    private final AtomicReference<IoWriteFutureImpl> pendingWrite = new AtomicReference<IoWriteFutureImpl>();

    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this.channel = channel;
        this.cmd = cmd;
    }

    public void onWindowExpanded() throws IOException {
        doWriteIfPossible(true);
    }

    public synchronized IoWriteFuture write(final Buffer buffer) {
        final IoWriteFutureImpl future = new IoWriteFutureImpl(buffer);
        if (isClosing()) {
            future.setValue(new IOException("Closed"));
        } else {
            if (!pendingWrite.compareAndSet(null, future)) {
                throw new WritePendingException();
            }
            doWriteIfPossible(false);
        }
        return future;
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        return builder().when(pendingWrite.get()).build().close(false);
    }

    protected synchronized void doWriteIfPossible(boolean resume) {
        final IoWriteFutureImpl future = pendingWrite.get();
        if (future != null) {
            final Buffer buffer = future.buffer;
            final int total = buffer.available();
            if (total > 0) {
                final int length = Math.min(Math.min(channel.getRemoteWindow().getSize(), total), channel.getRemoteWindow().getPacketSize());
                if (length > 0) {
                    if (resume) {
                        log.debug("Resuming write due to more space available in the remote window");
                    }
                    Buffer buf = channel.getSession().createBuffer(cmd, length + 12);
                    buf.putInt(channel.getRecipient());
                    if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
                        buf.putInt(1);
                    }
                    buf.putInt(length);
                    buf.putRawBytes(buffer.array(), buffer.rpos(), length);
                    buffer.rpos(buffer.rpos() + length);
                    channel.getRemoteWindow().consume(length);
                    try {
                        channel.getSession().writePacket(buf).addListener(new SshFutureListener<org.apache.sshd.common.io.IoWriteFuture>() {
                            public void operationComplete(org.apache.sshd.common.io.IoWriteFuture f) {
                                if (total > length) {
                                    doWriteIfPossible(false);
                                } else {
                                    pendingWrite.compareAndSet(future, null);
                                    future.setValue(true);
                                }
                            }
                        });
                    } catch (IOException e) {
                        future.setValue(e);
                    }
                } else if (!resume) {
                    log.debug("Delaying write until space is available in the remote window");
                }
            } else {
                pendingWrite.compareAndSet(future, null);
                future.setValue(true);
            }
        }
    }

    @Override
    public String toString() {
        return "ChannelAsyncOutputStream[" + channel + "]";
    }

    public static class IoWriteFutureImpl extends DefaultSshFuture<IoWriteFuture> implements IoWriteFuture {

        final Buffer buffer;

        public IoWriteFutureImpl(Buffer buffer) {
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
            if (v instanceof Throwable) {
                return (Throwable) v;
            } else {
                return null;
            }
        }
    }
}
