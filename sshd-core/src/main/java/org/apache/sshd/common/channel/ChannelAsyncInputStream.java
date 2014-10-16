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

import org.apache.sshd.common.Channel;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoReadFuture;
import org.apache.sshd.common.io.ReadPendingException;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.Readable;

public class ChannelAsyncInputStream extends CloseableUtils.AbstractCloseable implements IoInputStream {

    private final Channel channel;
    private final Buffer buffer = new Buffer();
    private IoReadFutureImpl pending;

    public ChannelAsyncInputStream(Channel channel) {
        this.channel = channel;
    }

    public void write(Readable src) throws IOException {
        synchronized (buffer) {
            buffer.putBuffer(src);
        }
        doRead(true);
    }

    public IoReadFuture read(Buffer buf) {
        IoReadFutureImpl future = new IoReadFutureImpl(buf);
        if (isClosing()) {
            future.setValue(new IOException("Closed"));
        } else {
            synchronized (buffer) {
                if (pending != null) {
                    throw new ReadPendingException();
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
                    pending.setValue(new SshException("Closed"));
                }
            }
        }
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        synchronized (buffer) {
            return builder().when(pending).build().close(false);
        }
    }

    private void doRead(boolean resume) {
        IoReadFutureImpl future = null;
        int nbRead = 0;
        synchronized (buffer) {
            if (buffer.available() > 0) {
                if (resume) {
//                    LOGGER.debug("Resuming read due to incoming data");
                }
                future = pending;
                pending = null;
                if (future != null) {
                    nbRead = future.buffer.putBuffer(buffer, false);
                    buffer.compact();
                }
            } else {
                if (!resume) {
//                    LOGGER.debug("Delaying read until data is available");
                }
            }
        }
        if (nbRead > 0) {
            try {
                channel.getLocalWindow().consumeAndCheck(nbRead);
            } catch (IOException e) {
                channel.getSession().exceptionCaught(e);
            }
            future.setValue(nbRead);
        }
    }

    @Override
    public String toString() {
        return "ChannelAsyncInputStream[" + channel + "]";
    }

    public static class IoReadFutureImpl extends DefaultSshFuture<IoReadFuture> implements IoReadFuture {

        final Buffer buffer;

        public IoReadFutureImpl(Buffer buffer) {
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
            if (getValue() instanceof Throwable) {
                throw new SshException("Write failed", getException());
            }
        }
        public int getRead() {
            Object v = getValue();
            if (v instanceof RuntimeException) {
                throw (RuntimeException) v;
            } else if (v instanceof Error) {
                throw (Error) v;
            } else if (v instanceof Throwable) {
                throw (RuntimeSshException) new RuntimeSshException("Error reading from channel.").initCause((Throwable) v);
            } else if (v instanceof Integer) {
                return (Integer) v;
            } else {
                throw new IllegalStateException();
            }
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
