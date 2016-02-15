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
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.Predicate;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A Window for a given channel.
 * Windows are used to not overflow the client or server when sending datas.
 * Both clients and servers have a local and remote window and won't send
 * anymore data until the window has been expanded.  When the local window
 * is
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Window extends AbstractLoggingBean implements java.nio.channels.Channel, ChannelHolder, PropertyResolver {
    /**
     * Default {@link Predicate} used to test if space became available
     */
    public static final Predicate<Window> SPACE_AVAILABLE_PREDICATE = new Predicate<Window>() {
        @SuppressWarnings("synthetic-access")
        @Override
        public boolean evaluate(Window input) {
            // NOTE: we do not call "getSize()" on purpose in order to avoid the lock
            return input.sizeHolder.get() > 0;
        }
    };

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicInteger sizeHolder = new AtomicInteger(0);
    private final AbstractChannel channelInstance;
    private final Object lock;
    private final String suffix;

    private int maxSize;
    private int packetSize;
    private Map<String, Object> props = Collections.<String, Object>emptyMap();

    public Window(AbstractChannel channel, Object lock, boolean client, boolean local) {
        this.channelInstance = ValidateUtils.checkNotNull(channel, "No channel provided");
        this.lock = (lock != null) ? lock : this;
        this.suffix = (client ? "client" : "server") + "/" + (local ? "local" : "remote");
    }

    @Override
    public Map<String, Object> getProperties() {
        return props;
    }

    @Override
    public PropertyResolver getParentPropertyResolver() {
        return getChannel();
    }

    @Override   // co-variant return
    public AbstractChannel getChannel() {
        return channelInstance;
    }

    public int getSize() {
        synchronized (lock) {
            return sizeHolder.get();
        }
    }

    public int getMaxSize() {
        return maxSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void init(PropertyResolver resolver) {
        init(PropertyResolverUtils.getIntProperty(resolver, FactoryManager.WINDOW_SIZE, FactoryManager.DEFAULT_WINDOW_SIZE),
             PropertyResolverUtils.getIntProperty(resolver, FactoryManager.MAX_PACKET_SIZE, FactoryManager.DEFAULT_MAX_PACKET_SIZE),
             resolver.getProperties());
    }

    public void init(int size, int packetSize, Map<String, Object> props) {
        ValidateUtils.checkTrue(size >= 0, "Illegal initial size: %d", size);
        ValidateUtils.checkTrue(packetSize > 0, "Illegal packet size: %d", packetSize);

        synchronized (lock) {
            this.maxSize = size;
            this.packetSize = packetSize;
            this.props = (props == null) ? Collections.<String, Object>emptyMap() : props;
            updateSize(size);
        }

        if (initialized.getAndSet(true)) {
            log.debug("init({}) re-initializing", this);
        }

        if (log.isDebugEnabled()) {
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
             *      "Implementations MUST correctly handle window sizes
             *      of up to 2^32 - 1 bytes.  The window MUST NOT be increased above
             *      2^32 - 1 bytes.
             */
            expandedSize = sizeHolder.get() + window;
            if (expandedSize > Integer.MAX_VALUE) {
                updateSize(Integer.MAX_VALUE);
            } else {
                updateSize((int) expandedSize);
            }
        }

        if (expandedSize > Integer.MAX_VALUE) {
            log.warn("expand({}) window={} - truncated expanded size ({}) to {}", this, window, expandedSize, Integer.MAX_VALUE);
        } else if (log.isDebugEnabled()) {
            log.debug("Increase {} by {} up to {}", this, window, expandedSize);
        }
    }

    public void consume(int len) {
        ValidateUtils.checkTrue(len >= 0, "Negative consumption length: %d", len);
        checkInitialized("consume");

        int remainLen;
        synchronized (lock) {
            remainLen = sizeHolder.get() - len;
            if (remainLen >= 0) {
                updateSize(remainLen);
            }
        }

        if (remainLen < 0) {
            throw new IllegalStateException("consume(" + this + ") required length (" + len + ") above available: " + (remainLen + len));
        }

        if (log.isTraceEnabled()) {
            log.trace("Consume {} by {} down to {}", this, len, remainLen);
        }
    }

    public void consumeAndCheck(int len) throws IOException {
        synchronized (lock) {
            try {
                consume(len);
                check(maxSize);
            } catch (RuntimeException e) {
                throw new StreamCorruptedException("consumeAndCheck(" + this + ")"
                                                 + " failed (" + e.getClass().getSimpleName() + ")"
                                                 + " to consume " + len + " bytes"
                                                 + ": " + e.getMessage());
            }
        }
    }

    public void check(int maxFree) throws IOException {
        ValidateUtils.checkTrue(maxFree >= 0, "Negative check size: %d", maxFree);
        checkInitialized("check");

        int adjustSize = -1;
        AbstractChannel channel = getChannel();
        synchronized (lock) {
            // TODO make the adjust factor configurable via FactoryManager property
            int size = sizeHolder.get();
            if (size < (maxFree / 2)) {
                adjustSize = maxFree - size;
                channel.sendWindowAdjust(adjustSize);
                updateSize(maxFree);
            }
        }

        if (adjustSize >= 0) {
            if (log.isDebugEnabled()) {
                log.debug("Increase {} by {} up to {}", this, adjustSize, maxFree);
            }
        }
    }

    /**
     * Waits for enough data to become available to consume the specified size
     *
     * @param len Size of data to consume
     * @param maxWaitTime ax. time (millis) to wait for enough data to become available
     * @throws InterruptedException If interrupted while waiting
     * @throws WindowClosedException If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before enough data became available
     * @see #waitForCondition(Predicate, long)
     * @see #consume(int)
     */
    public void waitAndConsume(final int len, long maxWaitTime) throws InterruptedException, WindowClosedException, SocketTimeoutException {
        ValidateUtils.checkTrue(len >= 0, "Negative wait consume length: %d", len);
        checkInitialized("waitAndConsume");

        synchronized (lock) {
            waitForCondition(new Predicate<Window>() {
                @SuppressWarnings("synthetic-access")
                @Override
                public boolean evaluate(Window input) {
                    // NOTE: we do not call "getSize()" on purpose in order to avoid the lock
                    return input.sizeHolder.get() >= len;
                }
            }, maxWaitTime);

            if (log.isDebugEnabled()) {
                log.debug("waitAndConsume({}) - requested={}, available={}", this, len, sizeHolder);
            }

            consume(len);
        }
    }

    /**
     * Waits until some data becomes available or timeout expires
     *
     * @param maxWaitTime Max. time (millis) to wait for space to become available
     * @return Amount of available data - always positive
     * @throws InterruptedException If interrupted while waiting
     * @throws WindowClosedException If window closed while waiting
     * @throws SocketTimeoutException If timeout expired before space became available
     * @see #waitForCondition(Predicate, long)
     */
    public int waitForSpace(long maxWaitTime) throws InterruptedException, WindowClosedException, SocketTimeoutException {
        checkInitialized("waitForSpace");

        synchronized (lock) {
            waitForCondition(SPACE_AVAILABLE_PREDICATE, maxWaitTime);
            if (log.isDebugEnabled()) {
                log.debug("waitForSpace({}) available: {}", this, sizeHolder);
            }
            return sizeHolder.get();
        }
    }

    /**
     * Waits up to a specified amount of time for a condition to be satisfied and
     * signaled via the lock. <B>Note:</B> assumes that lock is acquired when this
     * method is called.
     *
     * @param predicate The {@link Predicate} to check if the condition has been
     * satisfied - the argument to the predicate is {@code this} reference
     * @param maxWaitTime Max. time (millis) to wait for the condition to be satisfied
     * @throws WindowClosedException If window closed while waiting
     * @throws InterruptedException If interrupted while waiting
     * @throws SocketTimeoutException If timeout expired before condition was satisfied
     * @see #isOpen()
     */
    protected void waitForCondition(Predicate<? super Window> predicate, long maxWaitTime)
            throws WindowClosedException, InterruptedException, SocketTimeoutException {
        ValidateUtils.checkNotNull(predicate, "No condition");
        ValidateUtils.checkTrue(maxWaitTime > 0, "Non-positive max. wait time: %d", maxWaitTime);

        long maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(maxWaitTime);
        long remWaitNanos = maxWaitNanos;
        // The loop takes care of spurious wakeups
        while (isOpen() && (remWaitNanos > 0L)) {
            if (predicate.evaluate(this)) {
                return;
            }

            long curWaitMillis = TimeUnit.NANOSECONDS.toMillis(remWaitNanos);
            long nanoWaitStart = System.nanoTime();
            if (curWaitMillis > 0L) {
                lock.wait(curWaitMillis);
            } else {    // only nanoseconds remaining
                lock.wait(0L, (int) remWaitNanos);
            }
            long nanoWaitEnd = System.nanoTime();
            long nanoWaitDuration = nanoWaitEnd - nanoWaitStart;
            remWaitNanos -= nanoWaitDuration;
        }

        if (!isOpen()) {
            throw new WindowClosedException(toString());
        }

        throw new SocketTimeoutException("waitForCondition(" + this + ") timeout exceeded: " + maxWaitTime);
    }

    protected void updateSize(int size) {
        ValidateUtils.checkTrue(size >= 0, "Invalid size: %d", size);
        this.sizeHolder.set(size);
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
            log.debug("Closing {}", this);
        }

        // just in case someone is still waiting
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + suffix + "](" + String.valueOf(getChannel()) + ")";
    }
}
