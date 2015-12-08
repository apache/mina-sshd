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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

public class ChannelAsyncOutputStream extends AbstractCloseable implements IoOutputStream {

    private final Channel channel;
    private final byte cmd;
    private final AtomicReference<IoWriteFutureImpl> pendingWrite = new AtomicReference<>();

    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this.channel = channel;
        this.cmd = cmd;
    }

    public void onWindowExpanded() throws IOException {
        doWriteIfPossible(true);
    }

    @Override
    public synchronized IoWriteFuture write(final Buffer buffer) {
        final IoWriteFutureImpl future = new IoWriteFutureImpl(buffer);
        if (isClosing()) {
            future.setValue(new IOException("Closed"));
        } else {
            if (!pendingWrite.compareAndSet(null, future)) {
                throw new WritePendingException("No write pending future");
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
        if (future == null) {
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({})[resume={}] no pending write future", this, resume);
            }
            return;
        }

        final Buffer buffer = future.getBuffer();
        final int total = buffer.available();
        if (total > 0) {
            Window remoteWindow = channel.getRemoteWindow();
            final int length = Math.min(Math.min(remoteWindow.getSize(), total), remoteWindow.getPacketSize());
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({})[resume={}] attempting to write {} out of {}", this, resume, length, total);
            }

            if (length > 0) {
                if (resume) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resuming {} write due to more space ({}) available in the remote window", this, length);
                    }
                }

                Session s = channel.getSession();
                Buffer buf = s.createBuffer(cmd, length + 12);
                buf.putInt(channel.getRecipient());
                if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
                    buf.putInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
                }
                buf.putInt(length);
                buf.putRawBytes(buffer.array(), buffer.rpos(), length);
                buffer.rpos(buffer.rpos() + length);
                remoteWindow.consume(length);
                try {
                    s.writePacket(buf).addListener(new SshFutureListener<IoWriteFuture>() {
                        @SuppressWarnings("synthetic-access")
                        @Override
                        public void operationComplete(IoWriteFuture f) {
                            if (total > length) {
                                doWriteIfPossible(false);
                            } else {
                                pendingWrite.compareAndSet(future, null);
                                future.setValue(Boolean.TRUE);
                            }
                        }
                    });
                } catch (IOException e) {
                    future.setValue(e);
                }
            } else if (!resume) {
                log.debug("Delaying write to {} until space is available in the remote window", this);
            }
        } else {
            pendingWrite.compareAndSet(future, null);
            future.setValue(Boolean.TRUE);
        }
    }

    @Override
    public String toString() {
        return "ChannelAsyncOutputStream[" + channel + "]";
    }
}
