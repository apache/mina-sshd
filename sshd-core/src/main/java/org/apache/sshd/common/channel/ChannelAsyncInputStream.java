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

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultVerifiableSshFuture;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.io.ReadPendingException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelAsyncInputStream extends AbstractCloseable implements IoInputStream, ChannelHolder {
    private final Channel channelInstance;
    private final Buffer buffer = new ByteArrayBuffer();
    private final Object readFutureId;
    private IoReadFutureImpl pending;

    public ChannelAsyncInputStream(Channel channel) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.readFutureId = toString();
    }

    @Override
    public Channel getChannel() {
        return channelInstance;
    }

    public void write(Readable src) throws IOException {
        synchronized (buffer) {
            buffer.putBuffer(src);
        }
        doRead(true);
    }

    @Override
    public IoReadFuture read(Buffer buf) {
        IoReadFutureImpl future = new IoReadFutureImpl(readFutureId, buf);
        if (isClosing()) {
            synchronized (buffer) {
                if (pending != null) {
                    throw new ReadPendingException("Previous pending read not handled");
                }
                if (buffer.available() > 0) {
                    Buffer fb = future.buffer;
                    int nbRead = fb.putBuffer(buffer, false);
                    buffer.compact();
                    future.setValue(nbRead);
                } else {
                    future.setValue(new EOFException("Closed"));
                }
            }
        } else {
            synchronized (buffer) {
                if (pending != null) {
                    throw new ReadPendingException("Previous pending read not handled");
                }
                pending = future;
            }
            doRead(false);
        }
        return future;
    }

    @Override
    protected void preClose() {
        synchronized (buffer) {
            if (buffer.available() == 0) {
                if (pending != null) {
                    pending.setValue(new EOFException("Closed"));
                }
            }
        }
        super.preClose();
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        synchronized (buffer) {
            return builder().when(pending).build().close(false);
        }
    }

    @SuppressWarnings("synthetic-access")
    private void doRead(boolean resume) {
        IoReadFutureImpl future = null;
        int nbRead = 0;
        boolean debugEnabled = log.isDebugEnabled();
        synchronized (buffer) {
            if (buffer.available() > 0) {
                if (resume) {
                    if (debugEnabled) {
                        log.debug("Resuming read due to incoming data on {}", this);
                    }
                }
                future = pending;
                pending = null;
                if (future != null) {
                    nbRead = future.buffer.putBuffer(buffer, false);
                    buffer.compact();
                }
            } else {
                if (!resume) {
                    if (debugEnabled) {
                        log.debug("Delaying read until data is available on {}", this);
                    }
                }
            }
        }
        if (nbRead > 0) {
            Channel channel = getChannel();
            try {
                LocalWindow wLocal = channel.getLocalWindow();
                wLocal.check();
            } catch (IOException e) {
                Session session = channel.getSession();
                session.exceptionCaught(e);
            }
            future.setValue(nbRead);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "]";
    }

    public static class IoReadFutureImpl extends DefaultVerifiableSshFuture<IoReadFuture> implements IoReadFuture {

        final Buffer buffer;

        public IoReadFutureImpl(Object id, Buffer buffer) {
            super(id, null);
            this.buffer = buffer;
        }

        @Override
        public Buffer getBuffer() {
            return isDone() ? buffer : null;
        }

        @Override
        public IoReadFuture verify(long timeoutMillis) throws IOException {
            long startTime = System.nanoTime();
            Number result = verifyResult(Number.class, timeoutMillis);
            long endTime = System.nanoTime();
            if (log.isDebugEnabled()) {
                log.debug("Read {} bytes after {} nanos", result, endTime - startTime);
            }

            return this;
        }

        @Override
        public int getRead() {
            Object v = getValue();
            if (v == null) {
                return 0;
            } else if (v instanceof Number) {
                return ((Number) v).intValue();
            } else if (v instanceof EOFException) {
                return -1;
            } else if (v instanceof RuntimeException) {
                throw (RuntimeException) v;
            } else if (v instanceof Error) {
                throw (Error) v;
            } else if (v instanceof Throwable) {
                throw new RuntimeSshException("Error reading from channel.", (Throwable) v);
            } else {
                throw formatExceptionMessage(
                        IllegalStateException::new,
                        "Unknown read value type: %s",
                        v.getClass().getName());
            }
        }

        @Override
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
