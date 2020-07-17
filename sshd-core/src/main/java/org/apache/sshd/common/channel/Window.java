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
import java.io.StreamCorruptedException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * A Window for a given channel. Windows are used to not overflow the client or server when sending datas. Both clients
 * and servers have a local and remote window and won't send anymore data until the window has been expanded. When the
 * local window is
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Window extends AbstractLoggingBean implements java.nio.channels.Channel, ChannelHolder {
    /**
     * Default {@link Predicate} used to test if space became available
     */
    public static final Predicate<Window> SPACE_AVAILABLE_PREDICATE = input -> {
        // NOTE: we do not call "getSize()" on purpose in order to avoid the lock
        return input.size > 0;
    };

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AbstractChannel channelInstance;
    private final Object lock;
    private final String suffix;

    private long size; // the window size
    private long maxSize; // actually uint32
    private long packetSize; // actually uint32

    public Window(AbstractChannel channel, Object lock, boolean client, boolean local) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel provided");
        this.lock = (lock != null) ? lock : this;
        this.suffix = (client ? "client" : "server") + "/" + (local ? "local" : "remote");
    }

    @Override // co-variant return
    public AbstractChannel getChannel() {
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

    public void init(PropertyResolver resolver) {
        init(CoreModuleProperties.WINDOW_SIZE.getRequired(resolver),
                CoreModuleProperties.MAX_PACKET_SIZE.getRequired(resolver),
                resolver);
    }

    public void init(long size, long packetSize, PropertyResolver resolver) {
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

    public void expand(int window) {
        ValidateUtils.checkTrue(window >= 0, "Negative window size: %d", window);
        checkInitialized("expand");

        long expandedSize;
        synchronized (lock) {
            /*
             * See RFC-4254 section 5.2:
             *
             * "Implementations MUST correctly handle window sizes of up to 2^32 - 1 bytes. The window MUST NOT be
             * increased above 2^32 - 1 bytes.
             */
            expandedSize = size + window;
            if (expandedSize > BufferUtils.MAX_UINT32_VALUE) {
                updateSize(BufferUtils.MAX_UINT32_VALUE);
            } else {
                updateSize(expandedSize);
            }
        }

        if (expandedSize > Integer.MAX_VALUE) {
            log.warn("expand({}) window={} - truncated expanded size ({}) to {}", this, window, expandedSize,
                    Integer.MAX_VALUE);
        } else if (log.isDebugEnabled()) {
            log.debug("Increase {} by {} up to {}", this, window, expandedSize);
        }
    }

    public void consume(long len) {
        BufferUtils.validateUint32Value(len, "Invalid consumption length: %d");
        checkInitialized("consume");

        long remainLen;
        synchronized (lock) {
            remainLen = size - len;
            if (remainLen >= 0L) {
                updateSize(remainLen);
            }
        }

        if (remainLen < 0L) {
            throw new IllegalStateException(
                    "consume(" + this + ") required length (" + len + ") above available: " + (remainLen + len));
        }

        if (log.isTraceEnabled()) {
            log.trace("Consume {} by {} down to {}", this, len, remainLen);
        }
    }

    public void consumeAndCheck(long len) throws IOException {
        synchronized (lock) {
            try {
                consume(len);
                check(maxSize);
            } catch (RuntimeException e) {
                throw new StreamCorruptedException(
                        "consumeAndCheck(" + this + ")"
                                                   + " failed (" + e.getClass().getSimpleName() + ")"
                                                   + " to consume " + len + " bytes"
                                                   + ": " + e.getMessage());
            }
        }
    }

    public void check(long maxFree) throws IOException {
        BufferUtils.validateUint32Value(maxFree, "Invalid check size: %d");
        checkInitialized("check");

        long adjustSize = -1L;
        AbstractChannel channel = getChannel();
        synchronized (lock) {
            // TODO make the adjust factor configurable via FactoryManager property
            long size = this.size;
            if (size < (maxFree / 2)) {
                adjustSize = maxFree - size;
                channel.sendWindowAdjust(adjustSize);
                updateSize(maxFree);
            }
        }

        if (adjustSize >= 0L) {
            if (log.isDebugEnabled()) {
                log.debug("Increase {} by {} up to {}", this, adjustSize, maxFree);
            }
        }
    }

    /**
     * Waits for enough data to become available to consume the specified size
     *
     * @param  len                    Size of data to consume
     * @param  maxWaitTime            Max. time (millis) to wait for enough data to become available
     * @throws InterruptedException   If interrupted while waiting
     * @throws WindowClosedException  If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before enough data became available
     * @see                           #waitForCondition(Predicate, Duration)
     * @see                           #consume(long)
     */
    public void waitAndConsume(long len, long maxWaitTime)
            throws InterruptedException, WindowClosedException, SocketTimeoutException {
        waitAndConsume(len, Duration.ofMillis(maxWaitTime));
    }

    /**
     * Waits for enough data to become available to consume the specified size
     *
     * @param  len                    Size of data to consume
     * @param  maxWaitTime            Max. time to wait for enough data to become available
     * @throws InterruptedException   If interrupted while waiting
     * @throws WindowClosedException  If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before enough data became available
     * @see                           #waitForCondition(Predicate, Duration)
     * @see                           #consume(long)
     */
    public void waitAndConsume(long len, Duration maxWaitTime)
            throws InterruptedException, WindowClosedException, SocketTimeoutException {
        BufferUtils.validateUint32Value(len, "Invalid wait consume length: %d", len);
        checkInitialized("waitAndConsume");

        boolean debugEnabled = log.isDebugEnabled();
        synchronized (lock) {
            waitForCondition(input -> {
                // NOTE: we do not call "getSize()" on purpose in order to avoid the lock
                return input.size >= len;
            }, maxWaitTime);

            if (debugEnabled) {
                log.debug("waitAndConsume({}) - requested={}, available={}", this, len, size);
            }

            consume(len);
        }
    }

    /**
     * Waits until some data becomes available or timeout expires
     *
     * @param  maxWaitTime            Max. time (millis) to wait for space to become available
     * @return                        Amount of available data - always positive
     * @throws InterruptedException   If interrupted while waiting
     * @throws WindowClosedException  If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before space became available
     * @see                           #waitForCondition(Predicate, Duration)
     */
    public long waitForSpace(long maxWaitTime) throws InterruptedException, WindowClosedException, SocketTimeoutException {
        return waitForSpace(Duration.ofMillis(maxWaitTime));
    }

    /**
     * Waits until some data becomes available or timeout expires
     *
     * @param  maxWaitTime            Max. time to wait for space to become available
     * @return                        Amount of available data - always positive
     * @throws InterruptedException   If interrupted while waiting
     * @throws WindowClosedException  If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before space became available
     * @see                           #waitForCondition(Predicate, Duration)
     */
    public long waitForSpace(Duration maxWaitTime) throws InterruptedException, WindowClosedException, SocketTimeoutException {
        checkInitialized("waitForSpace");

        long available;
        synchronized (lock) {
            waitForCondition(SPACE_AVAILABLE_PREDICATE, maxWaitTime);
            available = size;
        }

        if (log.isDebugEnabled()) {
            log.debug("waitForSpace({}) available: {}", this, available);
        }

        return available;
    }

    /**
     * Waits up to a specified amount of time for a condition to be satisfied and signaled via the lock. <B>Note:</B>
     * assumes that lock is acquired when this method is called.
     *
     * @param  predicate              The {@link Predicate} to check if the condition has been satisfied - the argument
     *                                to the predicate is {@code this} reference
     * @param  maxWaitTime            Max. time to wait for the condition to be satisfied
     * @throws WindowClosedException  If window closed while waiting
     * @throws InterruptedException   If interrupted while waiting
     * @throws SocketTimeoutException If timeout expired before condition was satisfied
     * @see                           #isOpen()
     */
    protected void waitForCondition(Predicate<? super Window> predicate, Duration maxWaitTime)
            throws WindowClosedException, InterruptedException, SocketTimeoutException {
        Objects.requireNonNull(predicate, "No condition");
        ValidateUtils.checkTrue(GenericUtils.isPositive(maxWaitTime), "Non-positive max. wait time: %s",
                maxWaitTime.toString());

        Instant cur = Instant.now();
        Instant waitEnd = cur.plus(maxWaitTime);
        // The loop takes care of spurious wakeups
        while (isOpen() && (cur.compareTo(waitEnd) < 0)) {
            if (predicate.test(this)) {
                return;
            }

            Duration rem = Duration.between(cur, waitEnd);
            lock.wait(rem.toMillis(), rem.getNano() % 1_000_000);
            cur = Instant.now();
        }

        if (!isOpen()) {
            throw new WindowClosedException(toString());
        }

        throw new SocketTimeoutException("waitForCondition(" + this + ") timeout exceeded: " + maxWaitTime);
    }

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

    @Override
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
