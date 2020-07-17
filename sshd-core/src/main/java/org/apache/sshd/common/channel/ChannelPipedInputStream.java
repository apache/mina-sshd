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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelPipedInputStream extends InputStream implements ChannelPipedSink {
    private final Window localWindow;
    private final Buffer buffer = new ByteArrayBuffer();
    private final byte[] b = new byte[1];
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final AtomicBoolean eofSent = new AtomicBoolean(false);

    private final Lock lock = new ReentrantLock();
    private final Condition dataAvailable = lock.newCondition();

    /**
     * {@link ChannelPipedOutputStream} is already closed and so we will not receive additional data. This is different
     * from the {@link #isOpen()}, which indicates that the reader of this {@link InputStream} will not be reading data
     * any more.
     */
    private final AtomicBoolean writerClosed = new AtomicBoolean(false);

    private long timeout;

    public ChannelPipedInputStream(PropertyResolver resolver, Window localWindow) {
        this(localWindow, CoreModuleProperties.WINDOW_TIMEOUT.getRequired(resolver));
    }

    public ChannelPipedInputStream(Window localWindow, Duration windowTimeout) {
        this(localWindow, Objects.requireNonNull(windowTimeout, "No window timeout provided").toMillis());
    }

    public ChannelPipedInputStream(Window localWindow, long windowTimeout) {
        this.localWindow = Objects.requireNonNull(localWindow, "No local window provided");
        this.timeout = windowTimeout;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    public long getTimeout() {
        return timeout;
    }

    @Override
    public int available() throws IOException {
        lock.lock();
        try {
            int avail = buffer.available();
            if ((avail == 0) && writerClosed.get()) {
                return -1;
            }
            return avail;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int read() throws IOException {
        synchronized (b) {
            int l = read(b, 0, 1);
            if (l == -1) {
                return -1;
            }
            return b[0] & 0xff;
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }

        long startTime = System.currentTimeMillis();
        lock.lock();
        try {
            for (int index = 0;; index++) {
                boolean openState = isOpen();
                boolean writerClosedState = writerClosed.get();
                if (((!openState) && writerClosedState && eofSent.get()) || ((!openState) && (!writerClosedState))) {
                    throw new IOException("Pipe closed after " + index + " cycles");
                }
                if (buffer.available() > 0) {
                    break;
                }
                if (writerClosed.get()) {
                    eofSent.set(true);
                    return -1; // no more data to read
                }

                try {
                    if (timeout > 0L) {
                        long remaining = timeout - (System.currentTimeMillis() - startTime);
                        if (remaining <= 0) {
                            throw new SocketException("Timeout (" + timeout + ") exceeded after " + index + " cycles");
                        }
                        dataAvailable.await(remaining, TimeUnit.MILLISECONDS);
                    } else {
                        dataAvailable.await();
                    }
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException(
                            "Interrupted at cycle #" + index + " while waiting for data to become available").initCause(e);
                }
            }

            if (len > buffer.available()) {
                len = buffer.available();
            }
            buffer.getRawBytes(b, off, len);
            if ((buffer.rpos() > localWindow.getPacketSize()) || (buffer.available() == 0)) {
                buffer.compact();
            }
        } finally {
            lock.unlock();
        }
        localWindow.consumeAndCheck(len);
        return len;
    }

    @Override
    public void eof() {
        lock.lock();
        try {
            writerClosed.set(true);
            dataAvailable.signalAll();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        lock.lock();
        try {
            dataAvailable.signalAll();
        } finally {
            open.set(false);
            lock.unlock();
        }
    }

    @Override
    public void receive(byte[] bytes, int off, int len) throws IOException {
        lock.lock();
        try {
            if (writerClosed.get() || (!isOpen())) {
                throw new IOException("Pipe closed");
            }
            buffer.putRawBytes(bytes, off, len);
            dataAvailable.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
