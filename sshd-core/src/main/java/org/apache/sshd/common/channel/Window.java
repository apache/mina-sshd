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

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * A {@link Channel} implements a sliding window flow control for data packets (SSH_MSG_CHANNEL_DATA and
 * SSH_MSG_CHANNEL_EXTENDED_DATA packets). Each channel has two windows, a local window describing how much data it is
 * prepared to receive (and the peer is allowed to send), and a remote window that reflects this side's view of the
 * peer's local window. When the local window size is zero, no data should be received; when the remote window size is
 * zero, no data should be sent. Peers update the other's remote window periodically, but at the latest when a window is
 * exhausted, by sending SSH_MSG_CHANNEL_WINDOW_ADJUST messages.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    LocalWindow
 * @see    RemoteWindow
 */
public abstract class Window extends AbstractLoggingBean implements ChannelHolder, Closeable {

    protected final Object lock = new Object();

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final Channel channelInstance;
    private final String suffix;

    private long size; // the window size
    private long maxSize; // actually uint32
    private long packetSize; // actually uint32

    protected Window(Channel channel, boolean isClient) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel provided");
        this.suffix = isClient ? "client" : "server";
    }

    protected static Predicate<Window> largerThan(long minSize) {
        return window -> window.size > minSize;
    }

    @Override
    public Channel getChannel() {
        return channelInstance;
    }

    public long getSize() {
        synchronized (lock) {
            return size;
        }
    }

    public long getMaxSize() {
        return maxSize;
    }

    public long getPacketSize() {
        return packetSize;
    }

    protected void init(long size, long packetSize, PropertyResolver resolver) {
        BufferUtils.validateUint32Value(size, "Illegal initial size: %d");
        BufferUtils.validateUint32Value(packetSize, "Illegal packet size: %d");
        ValidateUtils.checkTrue(packetSize > 0L, "Packet size must be positive: %d", packetSize);
        long limitPacketSize = CoreModuleProperties.LIMIT_PACKET_SIZE.getRequired(resolver);
        if (packetSize > limitPacketSize) {
            throw new IllegalArgumentException(
                    "Requested packet size (" + packetSize + ") exceeds max. allowed: " + limitPacketSize);
        }

        synchronized (lock) {
            this.maxSize = size;
            this.packetSize = packetSize;
            updateSize(size);
        }

        boolean debugEnabled = log.isDebugEnabled();
        if (initialized.getAndSet(true)) {
            if (debugEnabled) {
                log.debug("init({}) re-initializing", this);
            }
        }

        if (debugEnabled) {
            log.debug("init({}) size={}, max={}, packet={}", this, getSize(), getMaxSize(), getPacketSize());
        }
    }

    public abstract void consume(long len) throws IOException;

    protected void updateSize(long size) {
        BufferUtils.validateUint32Value(size, "Invalid updated size: %d", size);
        this.size = size;
        lock.notifyAll();
    }

    protected void checkInitialized(String location) {
        if (!initialized.get()) {
            throw new IllegalStateException(location + " - window not initialized: " + this);
        }
    }

    public boolean isOpen() {
        return !closed.get();
    }

    @Override
    public void close() throws IOException {
        if (!closed.getAndSet(true)) {
            if (log.isDebugEnabled()) {
                log.debug("Closing {}", this);
            }
        }

        // just in case someone is still waiting
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + suffix + "](" + getChannel() + ")";
    }
}
