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

import java.net.SocketTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Predicate;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * A {@link Window} reflecting this side's view of the peer's {@link LocalWindow}. A {@code RemoteWindow} is initialized
 * when the peer announces its packet and window sizes in the initial message exchange when opening a channel. Whenever
 * this side wants to send data, it checks whether the remote window has still enough space; if not, it sends only as
 * much data as possible. When data is sent, the remote window size is reduced by the number of data bytes sent. When
 * the window size drops to zero, no data is sent at all, and this side will have to wait for an
 * SSH_MSG_CHANNEL_WINDOW_ADJUST message from the peer, which will increase the available window size again.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RemoteWindow extends Window {

    /**
     * Default {@link Predicate} used to test if space became available
     */
    private static final Predicate<Window> SPACE_AVAILABLE_PREDICATE = Window.largerThan(0);

    public RemoteWindow(Channel channel, boolean isClient) {
        super(channel, isClient);
    }

    /**
     * Initializes the {@link RemoteWindow} with the packet and window sizes received from the peer.
     *
     * @param size       the initial window size
     * @param packetSize the peer's advertised maximum packet size
     * @param resolver   {@PropertyResolver} to access properties
     */
    @Override
    public void init(long size, long packetSize, PropertyResolver resolver) {
        super.init(size, packetSize, resolver);
    }

    @Override
    public void consume(long len) {
        BufferUtils.validateUint32Value(len, "Invalid consumption length: %d");
        checkInitialized("consume");

        long remainLen;
        synchronized (lock) {
            remainLen = getSize() - len;
            if (remainLen >= 0L) {
                updateSize(remainLen);
            }
        }
        if (remainLen < 0L) {
            throw new IllegalStateException(
                    "consume(" + this + ") required length (" + len + ") above available: " + (remainLen + len));
        }
        if (log.isDebugEnabled()) {
            log.debug("Consume {} by {} down to {}", this, len, remainLen);
        }
    }

    public void expand(long increment) {
        BufferUtils.validateUint32Value(increment, "Invalid window expansion size: %d");
        checkInitialized("expand");

        long initialSize;
        long expandedSize;
        synchronized (lock) {
            /*
             * See RFC-4254 section 5.2:
             *
             * "Implementations MUST correctly handle window sizes of up to 2^32 - 1 bytes. The window MUST NOT be
             * increased above 2^32 - 1 bytes.
             */
            initialSize = getSize();
            expandedSize = Math.min(initialSize + increment, BufferUtils.MAX_UINT32_VALUE);
            updateSize(expandedSize);
        }

        if (expandedSize - initialSize != increment) {
            log.warn("expand({}) window increase from {} by {} too large, set to {}", this, initialSize, increment,
                    expandedSize);
        } else if (log.isDebugEnabled()) {
            log.debug("expand({}) increase window from {} by {} up to {}", this, initialSize, increment, expandedSize);
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
        if (len == 0) {
            return;
        }
        boolean debugEnabled = log.isDebugEnabled();
        synchronized (lock) {
            waitForCondition(largerThan(len - 1), maxWaitTime);

            if (debugEnabled) {
                log.debug("waitAndConsume({}) - requested={}, available={}", this, len, getSize());
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
            available = getSize();
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

}
