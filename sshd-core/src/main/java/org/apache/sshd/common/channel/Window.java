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
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.session.Session;
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
public class Window extends AbstractLoggingBean implements java.nio.channels.Channel {
    private final AtomicInteger waitingCount = new AtomicInteger(0);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AbstractChannel channel;
    private final Object lock;
    private final String suffix;

    private int size;
    private int maxSize;
    private int packetSize;
    private Map<String, ?> props = Collections.<String, Object>emptyMap();

    public Window(AbstractChannel channel, Object lock, boolean client, boolean local) {
        this.channel = ValidateUtils.checkNotNull(channel, "No channel provided");
        this.lock = (lock != null) ? lock : this;
        this.suffix = ": " + (client ? "client" : "server") + " " + (local ? "local " : "remote") + " window";
    }

    public Map<String, ?> getProperties() {
        return props;
    }

    public int getSize() {
        synchronized (lock) {
            return size;
        }
    }

    public int getMaxSize() {
        return maxSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void init(Session session) {
        init(session.getFactoryManager());
    }

    public void init(FactoryManager manager) {
        init(manager.getProperties());
    }

    public void init(Map<String, ?> props) {
        init(FactoryManagerUtils.getIntProperty(props, FactoryManager.WINDOW_SIZE, AbstractChannel.DEFAULT_WINDOW_SIZE),
             FactoryManagerUtils.getIntProperty(props, FactoryManager.MAX_PACKET_SIZE, AbstractChannel.DEFAULT_PACKET_SIZE),
             props);
    }

    public void init(int size, int packetSize, Map<String, ?> props) {
        ValidateUtils.checkTrue(size >= 0, "Illegal initial size: %d", size);
        ValidateUtils.checkTrue(packetSize > 0, "Illegal packet size: %d", packetSize);

        synchronized (lock) {
            this.size = size;
            this.maxSize = size;
            this.packetSize = packetSize;
            this.props = (props == null) ? Collections.<String, Object>emptyMap() : props;
            lock.notifyAll();
        }

        initialized.set(true);

        if (log.isDebugEnabled()) {
            log.debug("init({}) size={}, max.={}, packet={}", this, getSize(), getMaxSize(), getPacketSize());
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
            expandedSize = size + window;
            if (expandedSize > Integer.MAX_VALUE) {
                size = Integer.MAX_VALUE;
            } else {
                size = (int) expandedSize;
            }
            lock.notifyAll();
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
            remainLen = size - len;
            if (remainLen >= 0) {
                size = remainLen;
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
                                                 + " failed " + e.getClass().getSimpleName() + ")"
                                                 + " to consume " + len + " bytes"
                                                 + ": " + e.getMessage());
            }
        }
    }

    public void check(int maxFree) throws IOException {
        ValidateUtils.checkTrue(maxFree >= 0, "Negative check size: %d", maxFree);
        checkInitialized("check");

        int adjustSize = -1;
        synchronized (lock) {
            // TODO make the adjust factor configurable via FactoryManager property
            if (size < (maxFree / 2)) {
                adjustSize = maxFree - size;
                channel.sendWindowAdjust(adjustSize);
                size = maxFree;
            }
        }

        if (adjustSize >= 0) {
            if (log.isDebugEnabled()) {
                log.debug("Increase {} by {} up to {}", this, adjustSize, maxFree);
            }
        }
    }

    public void waitAndConsume(int len) throws InterruptedException, WindowClosedException {
        ValidateUtils.checkTrue(len >= 0, "Negative wait consume length: %d", len);
        checkInitialized("waitAndConsume");

        synchronized (lock) {
            while ((size < len) && isOpen()) {
                int waiters = waitingCount.incrementAndGet();
                if (log.isDebugEnabled()) {
                    log.debug("waitAndConsume({}) - requested={}, available={}, waiters={}", this, len, size, waiters);
                }

                long nanoStart = System.nanoTime();
                try {
                    lock.wait();
                } finally {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    waiters = waitingCount.decrementAndGet();
                    if (log.isTraceEnabled()) {
                        log.debug("waitAndConsume({}) - requested={}, available={}, waiters={} - ended after {} nanos",
                                  this, len, size, waiters, nanoDuration);
                    }
                }
            }

            if (!isOpen()) {
                throw new WindowClosedException(toString());
            }

            if (log.isDebugEnabled()) {
                log.debug("waitAndConsume({}) - requested={}, available={}", this, len, size);
            }

            consume(len);
        }
    }

    /**
     * Waits (forever) until some data becomes available
     *
     * @return Amount of available data - always positive
     * @throws InterruptedException If interrupted while waiting
     * @throws WindowClosedException If window closed while waiting
     */
    public int waitForSpace() throws InterruptedException, WindowClosedException {
        checkInitialized("waitForSpace");

        synchronized (lock) {
            while ((size == 0) && isOpen()) {
                int waiters = waitingCount.incrementAndGet();
                if (log.isDebugEnabled()) {
                    log.debug("waitForSpace({}) - waiters={}", this, waiters);
                }

                long nanoStart = System.nanoTime();
                try {
                    lock.wait();
                } finally {
                    long nanoEnd = System.nanoTime();
                    long nanoDuration = nanoEnd - nanoStart;
                    waiters = waitingCount.decrementAndGet();
                    if (log.isTraceEnabled()) {
                        log.debug("waitForSpace({}) - waiters={} - ended after {} nanos", this, waiters, nanoDuration);
                    }
                }
            }

            if (!isOpen()) {
                throw new WindowClosedException(toString());
            }

            if (log.isDebugEnabled()) {
                log.debug("waitForSpace({}) available: {}", this, size);
            }
            return size;
        }
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
        if (isOpen()) {
            closed.set(true);
            log.debug("Closing {}", this);
        }

        // just in case someone is still waiting
        int waiters;
        synchronized (lock) {
            waiters = waitingCount.get();
            if (waiters > 0) {
                lock.notifyAll();
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("close({}) waiters={}", this, waiters);
        }
    }

    @Override
    public String toString() {
        return String.valueOf(channel) + suffix;
    }
}
