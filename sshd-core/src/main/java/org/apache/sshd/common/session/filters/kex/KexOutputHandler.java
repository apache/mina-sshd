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
package org.apache.sshd.common.session.filters.kex;

import java.io.IOException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.common.session.helpers.PendingWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.slf4j.Logger;

/**
 * Manages SSH message sending during a key exchange. RFC 4253 specifies that during a key exchange, no high-level
 * messages are to be sent, but a receiver must be able to deal with messages "in flight" until the peer's
 * {@link SshConstants#SSH_MSG_KEXINIT} message is received.
 * <p>
 * Apache MINA sshd queues up high-level messages that threads try to send while a key exchange is ongoing, and sends
 * them once the key exchange is done. Sending queued messages may make the peer re-trigger a new key exchange, in which
 * case sending queued messages stops and is resumed at the end of the new key exchange.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc4253#section-7">RFC 4253</a>
 */
public class KexOutputHandler implements OutputHandler {

    // With asynchronous flushing we get a classic producer-consumer problem. The flushing thread is the single
    // consumer, and there is a risk that it might get overrun by the producers. The classical solution of using a
    // LinkedBlockingQueue with a fixed maximum capacity doesn't work: we cannot make the producers block when the queue
    // is full; we might deadlock or be unable to handle any incoming message.
    //
    // We need an unbounded queue that never blocks the producers, but that manages to throttle them such that the
    // flushing thread can actually finish, and we still can handle incoming messages (in particular also the peer's
    // SSH_MSG_NEW_KEYS, since we start flushing already after having sent our own SSH_MSG_NEW_KEYS).
    //
    // This is achieved by giving the flushing thread priority over the threads that might enqueue additional packets
    // and flushing at least two packets at a time. Additionally the flush loop releases and shortly afterwards
    // re-acquires the write lock, so normally not many readers (i.e., writePacket() calls) will get a chance to enqueue
    // new packets.

    /**
     * An {@link ExecutorService} used to flush the queue asynchronously.
     *
     * @see #flushQueue(DefaultKeyExchangeFuture)
     */
    protected static ExecutorService flushRunner = ThreadUtils.newCachedThreadPool("kex-flusher");

    /**
     * We need the flushing thread to have priority over writing threads. So we use a lock that favors writers over
     * readers, and any state updates and the flushing thread are writers, while writePacket() is a reader.
     */
    protected final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(false);

    /**
     * The {@link KexFilter} this {@link KexOutputHandler} belongs to.
     */
    protected final KexFilter filter;

    /**
     * The {@link Logger} to use.
     */
    protected final Logger log;

    /**
     * Queues up high-level packets written during an ongoing key exchange.
     */
    protected final Queue<PendingWriteFuture> pendingPackets = new ConcurrentLinkedQueue<>();

    /**
     * Indicates that all pending packets have been flushed. Set to {@code true} by the flushing thread, or at the end
     * of KEX if there are no packets to be flushed. Set to {@code false} when a new KEX starts. Initially {@code true}.
     */
    protected final AtomicBoolean kexFlushed = new AtomicBoolean(true);

    /**
     * Indicates that the handler has been shut down.
     */
    protected final AtomicBoolean shutDown = new AtomicBoolean();

    /**
     * Never {@code null}. Used to block some threads when writing packets while pending packets are still being flushed
     * at the end of a KEX to avoid overrunning the flushing thread. Always set, initially fulfilled. At the beginning
     * of a KEX a new future is installed, which is fulfilled at the end of the KEX once there are no more pending
     * packets to be flushed.
     */
    protected final AtomicReference<DefaultKeyExchangeFuture> kexFlushedFuture = new AtomicReference<>();

    /**
     * Creates a new {@link KexOutputHandler} for the given {@code session}, using the given {@code Logger}.
     *
     * @param filter {@link KexFilter} the new instance belongs to
     * @param log    {@link Logger} to use for writing log messages
     */
    public KexOutputHandler(KexFilter filter, Logger log) {
        this.filter = Objects.requireNonNull(filter);
        this.log = Objects.requireNonNull(log);
        // Start with a fulfilled kexFlushed future.
        DefaultKeyExchangeFuture initialFuture = new DefaultKeyExchangeFuture(this.toString(), null);
        initialFuture.setValue(Boolean.TRUE);
        kexFlushedFuture.set(initialFuture);
    }

    public void updateState(Runnable update) {
        updateState(() -> {
            update.run();
            return null;
        });
    }

    public <V> V updateState(Supplier<V> update) {
        lock.writeLock().lock();
        try {
            return update.get();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Initializes the state for a new key exchange. {@code allPacketsFlushed} will be {@code false}, and a new future
     * to be fulfilled when all queued packets will be flushed once the key exchange is done is set. The currently set
     * future from an earlier key exchange is returned. The returned future may or may not be fulfilled; if it isn't,
     * there are still left-over pending packets to write from the previous key exchange, which will be written once the
     * new key exchange flushes pending packets.
     *
     * @return the previous {@link DefaultKeyExchangeFuture} indicating whether all pending packets were flushed.
     */
    public DefaultKeyExchangeFuture initNewKeyExchange() {
        return updateState(() -> {
            kexFlushed.set(false);
            return kexFlushedFuture.getAndSet(
                    new DefaultKeyExchangeFuture(filter.getSession().toString(), filter.getSession().getFutureLock()));
        });
    }

    /**
     * To be called when the key exchange is done. If there are any pending packets, returns a future that will be
     * fulfilled when {@link #flushQueue(DefaultKeyExchangeFuture)} with that future as argument has flushed all pending
     * packets, if there are any.
     *
     * @return the current {@link DefaultKeyExchangeFuture} and the number of currently pending packets
     */
    public SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture> terminateKeyExchange() {
        return updateState(() -> {
            int numPending = pendingPackets.size();
            if (numPending == 0) {
                kexFlushed.set(true);
            }
            return new SimpleImmutableEntry<>(Integer.valueOf(numPending), kexFlushedFuture.get());
        });
    }

    /**
     * Pretends all pending packets had been written. To be called when the {@link AbstractSession} closes.
     */
    public void shutdown() {
        shutDown.set(true);
        SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture> items = updateState(() -> {
            kexFlushed.set(true);
            return new SimpleImmutableEntry<>(
                    Integer.valueOf(pendingPackets.size()),
                    kexFlushedFuture.get());
        });
        items.getValue().setValue(Boolean.valueOf(items.getKey().intValue() == 0));
    }

    /**
     * Writes a packet. If a key exchange is ongoing, only low-level messages are written directly; all other messages
     * are queued and will be written once {@link #flushQueue(DefaultKeyExchangeFuture)} is called when the key exchange
     * is done. Packets written while there are still pending packets to be flushed will either be queued, too.
     * <p>
     * If a packet was written, a key exchange may be triggered via {@link AbstractSession#checkRekey()}.
     * </p>
     *
     * @param  buffer      packet to write
     * @throws IOException if an error occurs
     */
    @Override
    public IoWriteFuture send(int cmd, Buffer buffer) throws IOException {
        // While exchanging key, queue high level packets.
        boolean isLowLevelMessage = cmd <= SshConstants.SSH_MSG_KEX_LAST && cmd != SshConstants.SSH_MSG_SERVICE_REQUEST
                && cmd != SshConstants.SSH_MSG_SERVICE_ACCEPT;
        IoWriteFuture future = null;
        try {
            if (isLowLevelMessage) {
                // Low-level messages can always be sent.
                future = filter.write(cmd, buffer, true);
            } else {
                future = writeOrEnqueue(cmd, buffer);
                if (!(future instanceof PendingWriteFuture)) {
                    filter.startKexIfNeeded();
                }
            }
        } finally {
            filter.getSession().resetIdleTimeout();
        }
        return future;
    }

    /**
     * Writes an SSH packet. If no KEX is ongoing and there are no pending packets queued to be written after KEX, the
     * buffer is written directly. Otherwise, the write is enqueued or the calling thread is blocked until all pending
     * packets have been written, depending on the result of {@link #isBlockAllowed(int)}. If the calling thread holds
     * the monitor of the session's {@link AbstractSession#getFutureLock()}, it is never blocked and the write is
     * queued.
     * <p>
     * If {@code timeout <= 0} or {@code unit == null}, a time-out of "forever" is assumed. Note that a timeout applies
     * only if the calling thread is blocked.
     * </p>
     *
     * @param  cmd         SSH command from the buffer
     * @param  buffer      {@link Buffer} containing the packet to write
     * @return             an {@link IoWriteFuture} that will be fulfilled once the packet has indeed been written.
     * @throws IOException if an error occurs
     */
    protected IoWriteFuture writeOrEnqueue(int cmd, Buffer buffer) throws IOException {
        for (;;) {
            // We must decide _and_ write the packet while holding the lock. If we'd write the packet outside this
            // lock, there is no guarantee that a concurrently running KEX_INIT received from the peer doesn't change
            // the state to RUN and grabs the encodeLock before the thread executing this write operation. If this
            // happened, we might send a high-level messages after our KEX_INIT, which is not allowed by RFC 4253.
            //
            // Use the readLock here to give KEX state updates and the flushing thread priority.
            lock.readLock().lock();
            try {
                if (shutDown.get()) {
                    throw new SshException("Write attempt on closing session: " + SshConstants.getCommandMessageName(cmd));
                }
                KexState state = filter.getKexState().get();
                boolean kexDone = KexState.DONE.equals(state) || KexState.KEYS.equals(state);
                if (kexDone && kexFlushed.get()) {
                    // Not in KEX, no pending packets: out it goes.
                    return filter.write(cmd, buffer, false);
                } else {
                    // Still in KEX or still flushing. Enqueue the packet; it will get written by the flushing thread at
                    // the end of KEX. See the javadoc of KexFilter.
                    //
                    // If so many packets are queued that flushing them triggers another KEX flushing stops
                    // and will be resumed at the end of the new KEX.
                    if (kexDone && log.isDebugEnabled()) {
                        log.debug("writeOrEnqueue({})[{}]: Queuing packet while flushing", filter.getSession(),
                                SshConstants.getCommandMessageName(cmd));
                    }
                    return enqueuePendingPacket(cmd, buffer);
                }
            } finally {
                lock.readLock().unlock();
            }
        }
    }

    /**
     * Enqueues a packet to be written once a running key exchange terminates.
     *
     * @param  cmd    the SSH command from the buffer
     * @param  buffer the {@link Buffer} containing the packet to be sent
     * @return        the enqueued {@link PendingWriteFuture}
     */
    protected PendingWriteFuture enqueuePendingPacket(int cmd, Buffer buffer) {
        String cmdName = SshConstants.getCommandMessageName(cmd);
        PendingWriteFuture future;
        int numPending;
        future = new PendingWriteFuture(cmdName, buffer);
        pendingPackets.add(future);
        numPending = pendingPackets.size();

        if (log.isDebugEnabled()) {
            if (numPending == 1) {
                log.debug("enqueuePendingPacket({})[{}] Start flagging packets as pending until key exchange is done",
                        filter.getSession(),
                        cmdName);
            } else {
                log.debug("enqueuePendingPacket({})[{}] enqueued until key exchange is done (pending={})", filter.getSession(),
                        cmdName,
                        numPending);
            }
        }
        return future;
    }

    /**
     * Flushes all packets enqueued while a key exchange was ongoing. If writing the pending packets triggers a new key
     * exchange, flushing is stopped and is to be resumed by another call to this method when the new key exchange is
     * done.
     *
     * @param flushDone the future obtained from {@code getFlushedFuture}; will be fulfilled once all pending packets
     *                  have been written
     */
    protected void flushQueue(DefaultKeyExchangeFuture flushDone) {
        // kexFlushed must be set to true in all cases when this thread exits, **except** if a new KEX has started while
        // flushing.
        flushRunner.submit(() -> {
            List<SimpleImmutableEntry<PendingWriteFuture, IoWriteFuture>> pendingFutures = new ArrayList<>();
            boolean allFlushed = false;
            DefaultKeyExchangeFuture newFuture = null;
            // A Throwable when doWritePacket fails, or Boolean.FALSE if the session closes while flushing.
            Object error = null;
            try {
                boolean warnedAboutChunkLimit = false;
                int lastSize = -1;
                int take = 2;
                while (!allFlushed) {
                    // Using the writeLock this thread gets priority over the readLock used by writePacket(). Note that
                    // the outer loop essentially is just a loop around the critical region, so typically only one
                    // reader (i.e., writePacket() call) gets the lock before we get it again, and thus the flush really
                    // should rarely need to increase the chunk size. Data pumping threads in the application remain
                    // blocked until flushing is done.
                    lock.writeLock().lock();
                    try {
                        if (pendingPackets.isEmpty()) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): All packets at end of KEX flushed", filter.getSession());
                            }
                            kexFlushed.set(true);
                            allFlushed = true;
                            break;
                        }

                        if (!filter.getSession().isOpen()) {
                            log.info("flushQueue({}): Session closed while flushing pending packets at end of KEX",
                                    filter.getSession());
                            DefaultIoWriteFuture aborted = new DefaultIoWriteFuture(filter.getSession(), null);
                            aborted.setValue(new SshException("Session closed while flushing pending packets at end of KEX"));
                            drainQueueTo(pendingFutures, aborted);
                            kexFlushed.set(true);
                            error = Boolean.FALSE;
                            break;
                        }

                        DefaultKeyExchangeFuture currentFuture = kexFlushedFuture.get();
                        if (currentFuture != flushDone) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): Stopping flushing pending packets", filter.getSession());
                            }
                            // Another KEX was started. Exit and hook up the flushDone future with the new future.
                            newFuture = currentFuture;
                            break;
                        }
                        int newSize = pendingPackets.size();
                        if (lastSize < 0) {
                            log.info("flushQueue({}): {} pending packets to flush", filter.getSession(), newSize);
                        } else if (newSize >= lastSize) {
                            log.info("flushQueue({}): queue size before={} now={}", filter.getSession(), lastSize, newSize);
                            // More new enqueues while we had written. Try writing more in one go to make progress.
                            if (take < 64) {
                                take *= 2;
                            } else if (!warnedAboutChunkLimit) {
                                warnedAboutChunkLimit = true;
                                log.warn("flushQueue({}): maximum queue flush chunk of 64 reached", filter.getSession());
                            }
                        }
                        lastSize = newSize;
                        if (log.isDebugEnabled()) {
                            log.debug("flushQueue({}): flushing {} packets", filter.getSession(), Math.min(lastSize, take));
                        }
                        for (int i = 0; i < take; i++) {
                            PendingWriteFuture pending = pendingPackets.poll();
                            if (pending == null) {
                                break;
                            }
                            IoWriteFuture written;
                            try {
                                if (log.isTraceEnabled()) {
                                    log.trace("flushQueue({}): Flushing a packet at end of KEX for {}", filter.getSession(),
                                            pending.getId());
                                }
                                Buffer buf = pending.getBuffer();
                                int cmd = buf.rawByte(buf.rpos()) & 0xFF;
                                written = filter.write(cmd, buf, true);
                            } catch (Throwable e) {
                                log.error("flushQueue({}): Exception while flushing packet at end of KEX for {}",
                                        filter.getSession(),
                                        pending.getId(), e);
                                AbstractIoWriteFuture aborted = new AbstractIoWriteFuture(pending.getId(), null) {
                                    // Nothing extra
                                };
                                aborted.setValue(e);
                                pendingFutures.add(new SimpleImmutableEntry<>(pending, aborted));
                                drainQueueTo(pendingFutures, aborted);
                                kexFlushed.set(true);
                                // Remember the error, but close the session outside of the lock critical region.
                                error = e;
                                return;
                            }
                            pendingFutures.add(new SimpleImmutableEntry<>(pending, written));
                            if (log.isTraceEnabled()) {
                                log.trace("flushQueue({}): Flushed a packet at end of KEX for {}", filter.getSession(),
                                        pending.getId());
                            }
                            filter.getSession().resetIdleTimeout();
                        }
                        if (pendingPackets.isEmpty()) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): All packets at end of KEX flushed", filter.getSession());
                            }
                            kexFlushed.set(true);
                            allFlushed = true;
                            break;
                        }
                    } finally {
                        lock.writeLock().unlock();
                    }
                }
            } finally {
                if (allFlushed) {
                    flushDone.setValue(Boolean.TRUE);
                } else if (error != null) {
                    // We'll close the session (or it is closing already). Pretend we had written everything.
                    flushDone.setValue(error);
                    if (error instanceof Throwable) {
                        filter.getSession().exceptionCaught((Throwable) error);
                    }
                } else if (newFuture != null) {
                    newFuture.addListener(f -> {
                        Throwable failed = f.getException();
                        flushDone.setValue(failed != null ? failed : Boolean.TRUE);
                    });
                }
                // Connect all futures of packets that we wrote. We do this at the end instead of one-by-one inside the
                // loop to minimize the risk that woken up threads waiting on these futures queue up additional packets.
                pendingFutures.forEach(e -> e.getValue().addListener(e.getKey()));
            }
        });
    }

    private void drainQueueTo(
            List<SimpleImmutableEntry<PendingWriteFuture, IoWriteFuture>> pendingAborted,
            IoWriteFuture aborted) {
        PendingWriteFuture pending = pendingPackets.poll();
        while (pending != null) {
            pendingAborted.add(new SimpleImmutableEntry<>(pending, aborted));
            pending = pendingPackets.poll();
        }
    }
}
