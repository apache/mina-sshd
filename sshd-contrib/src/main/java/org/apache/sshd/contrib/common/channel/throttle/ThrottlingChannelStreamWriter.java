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
package org.apache.sshd.contrib.common.channel.throttle;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.InterruptedByTimeoutException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.Property;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.channel.throttle.DefaultChannelStreamWriter;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A {@link ChannelStreamWriter} delegate implementation that &quot;throttles&quot; the output by having a limit on the
 * outstanding packets that have not been sent yet. The {@link #writeData(Buffer) writePacket} implementation make sure
 * that the limit has not been exceeded - if so, then it waits until pending packets have been successfully sent before
 * sending the next packet.
 *
 * <B>Note:</B> {@link #close() closing} the throttler does not close the delegate writer
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ThrottlingChannelStreamWriter extends AbstractLoggingBean
        implements ChannelStreamWriter, SshFutureListener<IoWriteFuture> {
    /** Timeout (seconds) for throttling packet writer to wait for pending packets send */
    public static final Property<Duration> WAIT_TIME
            = Property.durationSec("packet-writer-wait-time", Duration.ofSeconds(30L));

    /** Max. pending packets count */
    public static final Property<Integer> MAX_PEND_COUNT
            = Property.integer("packet-writer-max-pend-count", 4096);

    private final ChannelStreamWriter delegate;
    private final int maxPendingPackets;
    private final long maxWait;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final AtomicInteger availableCount;

    public ThrottlingChannelStreamWriter(Channel channel) {
        this(new DefaultChannelStreamWriter(channel), channel);
    }

    public ThrottlingChannelStreamWriter(ChannelStreamWriter delegate, PropertyResolver resolver) {
        this(delegate, MAX_PEND_COUNT.getRequired(resolver), WAIT_TIME.getRequired(resolver));
    }

    public ThrottlingChannelStreamWriter(ChannelStreamWriter delegate, int maxPendingPackets, TimeUnit waitUnit,
                                         long waitCount) {
        this(delegate, maxPendingPackets, waitUnit.toMillis(waitCount));
    }

    public ThrottlingChannelStreamWriter(ChannelStreamWriter delegate, int maxPendingPackets, Duration maxWait) {
        this(delegate, maxPendingPackets, maxWait.toMillis());
    }

    public ThrottlingChannelStreamWriter(ChannelStreamWriter delegate, int maxPendingPackets, long maxWait) {
        this.delegate = Objects.requireNonNull(delegate, "No delegate provided");
        ValidateUtils.checkTrue(maxPendingPackets > 0, "Invalid pending packets limit: %d", maxPendingPackets);
        this.maxPendingPackets = maxPendingPackets;
        this.availableCount = new AtomicInteger(maxPendingPackets);
        ValidateUtils.checkTrue(maxWait > 0L, "Invalid max. pending wait time: %d", maxWait);
        this.maxWait = maxWait;
    }

    public ChannelStreamWriter getDelegate() {
        return delegate;
    }

    public int getMaxPendingPackets() {
        return maxPendingPackets;
    }

    public int getAvailablePacketsCount() {
        return availableCount.get();
    }

    public long getMaxWait() {
        return maxWait;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public IoWriteFuture writeData(Buffer buffer) throws IOException {
        if (!isOpen()) {
            throw new ClosedSelectorException();
        }

        long remainWait = getMaxWait();
        int available;
        synchronized (availableCount) {
            while (availableCount.get() == 0) {
                long waitStart = System.currentTimeMillis();
                try {
                    availableCount.wait(remainWait);
                } catch (InterruptedException e) {
                    throw new InterruptedIOException(
                            "Interrupted after " + (System.currentTimeMillis() - waitStart) + " msec.");
                }
                long waitDuration = System.currentTimeMillis() - waitStart;
                if (waitDuration <= 0L) {
                    waitDuration = 1L;
                }
                remainWait -= waitDuration;
                if (remainWait <= 0L) {
                    throw new InterruptedByTimeoutException();
                }
            }

            available = availableCount.decrementAndGet();
        }

        if (log.isTraceEnabled()) {
            log.trace("writePacket({}) available={} after {} msec.", this, available, getMaxWait() - remainWait);
        }
        if (available < 0) {
            throw new EOFException("Negative available packets count: " + available);
        }

        ChannelStreamWriter writer = getDelegate();
        return writer.writeData(buffer).addListener(this);
    }

    @Override
    public void operationComplete(IoWriteFuture future) {
        if (future.isDone()) {
            if (future.isWritten()) {
                int available;
                synchronized (availableCount) {
                    available = isOpen() ? availableCount.incrementAndGet() : Integer.MIN_VALUE;
                    availableCount.notifyAll();
                }

                if (available > 0) {
                    if (log.isTraceEnabled()) {
                        log.trace("operationComplete({}) available={}", this, available);
                    }
                    return;
                }

                /*
                 * If non-positive it may be that close has been signaled or mis-count - in any case, don't take any
                 * chances
                 */
                log.error("operationComplete({}) invalid available count: {}", this, available);
            } else {
                Throwable err = future.getException();
                log.error("operationComplete({}) Error ({}) signalled: {}", this, err.getClass().getSimpleName(),
                        err.getMessage());
            }
        } else {
            log.error("operationComplete({}) Incomplete future signalled: {}", this, future);
        }

        try {
            close();
        } catch (IOException e) {
            log.warn("operationComplete({}) unexpected ({}) due to close: {}",
                    this, e.getClass().getSimpleName(), e.getMessage());
        }
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            if (log.isDebugEnabled()) {
                log.debug("close({}) closing");
            }
        }

        // Do it again if called - no harm
        synchronized (availableCount) {
            availableCount.set(-1);
            availableCount.notifyAll();
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[delegate=" + getDelegate()
               + ", maxWait=" + getMaxWait()
               + ", maxPending=" + getMaxPendingPackets()
               + ", available=" + getAvailablePacketsCount()
               + "]";
    }
}
