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
import java.time.Duration;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.channel.exception.SshChannelBufferedOutputException;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.functors.UnaryEquator;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * An {@link IoOutputStream} capable of queuing write requests.
 */
public class BufferedIoOutputStream extends AbstractInnerCloseable implements IoOutputStream, ChannelIdentifier {
    protected final Object id;
    protected final long channelId;
    protected final int maxPendingBytesCount;
    protected final Duration maxWaitForPendingWrites;
    protected final IoOutputStream out;
    protected final AtomicInteger pendingBytesCount = new AtomicInteger();
    protected final AtomicLong writtenBytesCount = new AtomicLong();
    protected final Queue<IoWriteFutureImpl> writes = new ConcurrentLinkedQueue<>();
    protected final AtomicReference<IoWriteFutureImpl> currentWrite = new AtomicReference<>();
    protected final AtomicReference<SshChannelBufferedOutputException> pendingException = new AtomicReference<>();

    public BufferedIoOutputStream(Object id, long channelId, IoOutputStream out, PropertyResolver resolver) {
        this(id, channelId, out, CoreModuleProperties.BUFFERED_IO_OUTPUT_MAX_PENDING_WRITE_SIZE.getRequired(resolver),
             CoreModuleProperties.BUFFERED_IO_OUTPUT_MAX_PENDING_WRITE_WAIT.getRequired(resolver));
    }

    public BufferedIoOutputStream(Object id, long channelId, IoOutputStream out, int maxPendingBytesCount,
                                  Duration maxWaitForPendingWrites) {
        this.id = Objects.requireNonNull(id, "No stream identifier provided");
        this.channelId = channelId;
        this.out = Objects.requireNonNull(out, "No delegate output stream provided");
        this.maxPendingBytesCount = maxPendingBytesCount;
        ValidateUtils.checkTrue(maxPendingBytesCount > 0, "Invalid max. pending bytes count: %d", maxPendingBytesCount);
        this.maxWaitForPendingWrites = Objects.requireNonNull(maxWaitForPendingWrites, "No max. pending time value provided");
    }

    @Override
    public long getChannelId() {
        return channelId;
    }

    public Object getId() {
        return id;
    }

    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
        if (isClosing()) {
            throw new EOFException("Closed/ing - state=" + state);
        }

        waitForAvailableWriteSpace(buffer.available());

        IoWriteFutureImpl future = new IoWriteFutureImpl(getId(), buffer);
        writes.add(future);
        startWriting();
        return future;
    }

    protected void waitForAvailableWriteSpace(int requiredSize) throws IOException {
        /*
         * NOTE: this code allows a single pending write to give this mechanism "the slip" and
         * exit the loop "unscathed" even though there is a pending exception. However, the goal
         * here is to avoid an OOM by having an unlimited accumulation of pending write requests
         * due to fact that the peer is not consuming the sent data. Please note that the pending
         * exception is "sticky" - i.e., the next write attempt will fail. This also means that if
         * the write request that "got away" was the last one by chance and it was consumed by the
         * peer there will be no exception thrown - which is also fine since as mentioned the goal
         * is not to enforce a strict limit on the pending bytes size but rather on the accumulation
         * of the pending write requests.
         *
         * We could have counted pending requests rather than bytes. However, we also want to avoid
         * having a large amount of data pending consumption by the peer as well. This code strikes
         * such a balance by allowing a single pending request to exceed the limit, but at the same
         * time prevents too many bytes from pending by having a bunch of pending requests that while
         * below the imposed number limit may cumulatively represent a lot of pending bytes.
         */

        long expireTime = System.currentTimeMillis() + maxWaitForPendingWrites.toMillis();
        synchronized (pendingBytesCount) {
            for (int count = pendingBytesCount.get();
                 /*
                  * The (count > 0) condition is put in place to allow a single pending
                  * write to exceed the maxPendingBytesCount as long as there are no
                  * other pending ones.
                  */
                 (count > 0)
                         // Not already over the limit or about to be over it
                         && ((count + requiredSize) > maxPendingBytesCount)
                         // No pending exception signaled
                         && (pendingException.get() == null);
                 count = pendingBytesCount.get()) {
                long remTime = expireTime - System.currentTimeMillis();
                if (remTime <= 0L) {
                    pendingException.compareAndSet(null,
                            new SshChannelBufferedOutputException(channelId,
                                    "Max. pending write timeout expired after " + writtenBytesCount + " bytes"));
                    throw pendingException.get();
                }

                try {
                    pendingBytesCount.wait(remTime);
                } catch (InterruptedException e) {
                    pendingException.compareAndSet(null,
                            new SshChannelBufferedOutputException(channelId,
                                    "Waiting for pending writes interrupted after " + writtenBytesCount + " bytes"));
                    throw pendingException.get();
                }
            }

            IOException e = pendingException.get();
            if (e != null) {
                throw e;
            }

            pendingBytesCount.addAndGet(requiredSize);
        }
    }

    private IoWriteFutureImpl getWriteRequest() {
        IoWriteFutureImpl future = null;
        while (future == null) {
            future = writes.peek();
            // No more pending requests
            if (future == null) {
                return null;
            }

            // Don't try to write any further if pending exception signaled
            Throwable pendingError = pendingException.get();
            if (pendingError != null) {
                log.error("startWriting({})[{}] propagate to {} write requests pending error={}[{}]", getId(), out,
                        writes.size(), getClass().getSimpleName(), pendingError.getMessage());

                IoWriteFutureImpl currentFuture = currentWrite.getAndSet(null);
                for (IoWriteFutureImpl pendingWrite : writes) {
                    // Checking reference by design
                    if (UnaryEquator.isSameReference(pendingWrite, currentFuture)) {
                        continue; // will be taken care of when its listener is eventually called
                    }

                    future.setValue(pendingError);
                }

                writes.clear();
                return null;
            }

            // Cannot honor this request yet since other pending one incomplete
            if (!currentWrite.compareAndSet(null, future)) {
                return null;
            }

            if (future.isDone()) {
                // A write was on-going, and finishWrite hadn't removed the future yet when we got it
                // above. See https://github.com/apache/mina-sshd/issues/263 .
                // Re-try.
                currentWrite.set(null);
                future = null;
            }
        }
        return future;
    }

    protected void startWriting() throws IOException {
        IoWriteFutureImpl future = getWriteRequest();
        if (future == null) {
            return;
        }
        Buffer buffer = future.getBuffer();
        int bufferSize = buffer.available();
        out.writeBuffer(buffer).addListener(f -> {
            if (f.isWritten()) {
                future.setValue(Boolean.TRUE);
            } else {
                future.setValue(f.getException());
            }
            finishWrite(future, bufferSize);
        });
    }

    protected void finishWrite(IoWriteFutureImpl future, int bufferSize) {
        /*
         * Update the pending bytes count only if successfully written,
         * otherwise signal an error
         */
        if (future.isWritten()) {
            long writtenSize = writtenBytesCount.addAndGet(bufferSize);

            int stillPending;
            synchronized (pendingBytesCount) {
                stillPending = pendingBytesCount.addAndGet(0 - bufferSize);
                pendingBytesCount.notifyAll();
            }

            /*
             * NOTE: since the pending exception is updated outside the synchronized block
             * a pending write could be successfully enqueued, however this is acceptable
             * - see comment in waitForAvailableWriteSpace
             */
            if (stillPending < 0) {
                log.error("finishWrite({})[{}] - pending byte counts underflow ({}) after {} bytes", getId(), out, stillPending,
                        writtenSize);
                pendingException.compareAndSet(null,
                        new SshChannelBufferedOutputException(channelId, "Pending byte counts underflow"));
            }
        } else {
            Throwable t = future.getException();
            if (t instanceof SshChannelBufferedOutputException) {
                pendingException.compareAndSet(null, (SshChannelBufferedOutputException) t);
            } else {
                pendingException.compareAndSet(null, new SshChannelBufferedOutputException(channelId, t));
            }

            // In case someone waiting so that they can detect the exception
            synchronized (pendingBytesCount) {
                pendingBytesCount.notifyAll();
            }
        }

        writes.remove(future);
        currentWrite.compareAndSet(future, null);
        try {
            startWriting();
        } catch (IOException e) {
            if (e instanceof SshChannelBufferedOutputException) {
                pendingException.compareAndSet(null, (SshChannelBufferedOutputException) e);
            } else {
                pendingException.compareAndSet(null, new SshChannelBufferedOutputException(channelId, e));
            }
            error("finishWrite({})[{}] failed ({}) re-start writing: {}",
                    getId(), out, e.getClass().getSimpleName(), e.getMessage(), e);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().when(getId(), writes).close(out).build();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "(" + getId() + "@" + channelId + ")[" + out + "]";
    }
}
