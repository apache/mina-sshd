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
package org.apache.sshd.common.session.helpers;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.future.DefaultKeyExchangeFuture;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.KexState;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.slf4j.Logger;

/**
 * Manages SSH message sending during a key exchange. RFC 4253 specifies that during a key exchange, no high-level
 * messages are to be sent, but a receiver must be able to deal with messages "in flight" until the peer's
 * {@link SshConstants#SSH_MSG_KEX_INIT} message is received.
 * <p>
 * Apache MINA sshd queues up high-level messages that threads try to send while a key exchange is ongoing, and sends
 * them once the key exchange is done. Sending queued messages may make the peer re-trigger a new key exchange, in which
 * case sending queued messages stops and is resumed at the end of the new key exchange.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc4253#section-7">RFC 4253</a>
 */
public class KeyExchangeMessageHandler {

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
     * We need the flushing thread to have priority over writing threads. So we use a lock that favors writers over
     * readers, and any state updates and the flushing thread are writers, while writePacket() is a reader.
     */
    protected final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(false);

    /**
     * An {@link ExecutorService} used to flush the queue asynchronously.
     *
     * @see {@link #flushQueue(DefaultKeyExchangeFuture)}
     */
    protected final ExecutorService flushRunner = Executors.newSingleThreadExecutor();

    /**
     * The {@link AbstractSession} this {@link KeyExchangeMessageHandler} belongs to.
     */
    protected final AbstractSession session;

    /**
     * The {@link Logger} to use.
     */
    protected final Logger log;

    /**
     * Queues up high-level packets written during an ongoing key exchange.
     */
    protected final Queue<PendingWriteFuture> pendingPackets = new ConcurrentLinkedQueue<>();

    /**
     * Indicates that all pending packets have been flushed.
     */
    protected volatile boolean kexFlushed = true;

    /**
     * Never {@code null}. Used to block some threads when writing packets while pending packets are still being flushed
     * at the end of a KEX to avoid overrunning the flushing thread. Always set, initially fulfilled. At the beginning
     * of a KEX a new future is installed, which is fulfilled at the end of the KEX once there are no more pending
     * packets to be flushed.
     */
    protected volatile DefaultKeyExchangeFuture kexFlushedFuture;

    /**
     * Creates a new {@link KeyExchangeMessageHandler} for the given {@code session}, using the given {@code Logger}.
     *
     * @param session {@link AbstractSession} the new instance belongs to
     * @param log     {@link Logger} to use for writing log messages
     */
    public KeyExchangeMessageHandler(AbstractSession session, Logger log) {
        this.session = Objects.requireNonNull(session);
        this.log = Objects.requireNonNull(log);
        // Start with a fulfilled kexFlushed future.
        kexFlushedFuture = new DefaultKeyExchangeFuture(session.toString(), session.getFutureLock());
        kexFlushedFuture.setValue(Boolean.TRUE);
    }

    public void updateState(Runnable update) {
        updateState(() -> {
            update.run();
            return null;
        });
    }

    public <V> V updateState(Supplier<V> update) {
        boolean locked = false;
        // If we already have 'lock' as a reader, don't try to get the write lock -- the flushing thread is blocked
        // currently anyway, and lock promotion from a readlock to a writelock is not possible. Contention between
        // multiple readers is the business of the caller!
        //
        // See also writeOrEnqueue() below.
        if (lock.getReadHoldCount() == 0) {
            lock.writeLock().lock();
            locked = true;
        }
        try {
            return update.get();
        } finally {
            if (locked) {
                lock.writeLock().unlock();
            }
        }
    }

    /**
     * Initializes the state for a new key exchange. {@link #allPacketsFlushed()} will be {@code false}, and a new
     * future to be fulfilled when all queued packets will be flushed once the key exchange is done is set. The
     * currently set future from an earlier key exchange is returned. The returned future may or may not be fulfilled;
     * if it isn't, there are still left-over pending packets to write from the previous key exchange, which will be
     * written once the new key exchange flushes pending packets.
     *
     * @return the previous {@link DefaultKeyExchangeFuture} indicating whether all pending packets were flushed.
     */
    public DefaultKeyExchangeFuture initNewKeyExchange() {
        return updateState(() -> {
            kexFlushed = false;
            DefaultKeyExchangeFuture oldFuture = kexFlushedFuture;
            kexFlushedFuture = new DefaultKeyExchangeFuture(session.toString(), session.getFutureLock());
            return oldFuture;
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
                kexFlushed = true;
            }
            return new SimpleImmutableEntry<>(Integer.valueOf(numPending), kexFlushedFuture);
        });
    }

    /**
     * Pretends all pending packets had been written. To be called when the {@link AbstractSession} closes.
     */
    public void shutdown() {
        SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture> items = updateState(() -> {
            kexFlushed = true;
            return new SimpleImmutableEntry<Integer, DefaultKeyExchangeFuture>(
                    Integer.valueOf(pendingPackets.size()),
                    kexFlushedFuture);
        });
        items.getValue().setValue(Boolean.valueOf(items.getKey().intValue() == 0));
        flushRunner.shutdownNow();
    }

    /**
     * Writes a packet. If a key exchange is ongoing, only low-level messages are written directly; all other messages
     * are queued and will be written once {@link #flushQueue(DefaultKeyExchangeFuture)} is called when the key exchange
     * is done. Packets written while there are still pending packets to be flushed will either be queued, too, or the
     * calling thread will be blocked with the given timeout until all packets have been flushed. Whether a write will
     * be blocked is determined by {@link #isBlockAllowed(int)}.
     * <p>
     * If a packet was written, a key exchange may be triggered via {@link AbstractSession#checkRekey()}.
     * </p>
     * <p>
     * If {@code timeout <= 0} or {@code unit == null}, a time-out of "forever" is assumed. Note that a timeout applies
     * only if the calling thread is blocked.
     * </p>
     *
     * @param  buffer      packet to write
     * @param  timeout     number of {@link TimeUnit}s to wait at most if the calling thread is blocked
     * @param  unit        {@link TimeUnit} of {@code timeout}
     * @return             an {@link IoWriteFuture} that will be fulfilled once the packet has indeed been written.
     * @throws IOException if an error occurs
     */
    public IoWriteFuture writePacket(Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        // While exchanging key, queue high level packets.
        byte[] bufData = buffer.array();
        int cmd = bufData[buffer.rpos()] & 0xFF;
        boolean enqueued = false;
        boolean isLowLevelMessage = cmd <= SshConstants.SSH_MSG_KEX_LAST && cmd != SshConstants.SSH_MSG_SERVICE_REQUEST
                && cmd != SshConstants.SSH_MSG_SERVICE_ACCEPT;
        try {
            if (isLowLevelMessage) {
                // Low-level messages can always be sent.
                return session.doWritePacket(buffer);
            }
            IoWriteFuture future = writeOrEnqueue(cmd, buffer, timeout, unit);
            enqueued = future instanceof PendingWriteFuture;
            return future;
        } finally {
            session.resetIdleTimeout();
            if (!enqueued) {
                try {
                    session.checkRekey();
                } catch (GeneralSecurityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("writePacket({}) failed ({}) to check re-key: {}", session, e.getClass().getSimpleName(),
                                e.getMessage(), e);
                    }
                    throw ValidateUtils.initializeExceptionCause(
                            new ProtocolException("Failed (" + e.getClass().getSimpleName() + ")"
                                                  + " to check re-key necessity: " + e.getMessage()),
                            e);
                } catch (Exception e) {
                    ExceptionUtils.rethrowAsIoException(e);
                }
            }
        }
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
     * @param  timeout     number of {@link TimeUnit}s to wait at most if the calling thread is blocked
     * @param  unit        {@link TimeUnit} of {@code timeout}
     * @return             an {@link IoWriteFuture} that will be fulfilled once the packet has indeed been written.
     * @throws IOException if an error occurs
     */
    protected IoWriteFuture writeOrEnqueue(int cmd, Buffer buffer, long timeout, TimeUnit unit) throws IOException {
        boolean holdsFutureLock = Thread.holdsLock(session.getFutureLock());
        for (;;) {
            DefaultKeyExchangeFuture block = null;
            // We must decide _and_ write the packet while holding the lock. If we'd write the packet outside this
            // lock, there is no guarantee that a concurrently running KEX_INIT received from the peer doesn't change
            // the state to RUN and grabs the encodeLock before the thread executing this write operation. If this
            // happened, we might send a high-level messages after our KEX_INIT, which is not allowed by RFC 4253.
            //
            // Use the readLock here to give KEX state updates and the flushing thread priority.
            lock.readLock().lock();
            try {
                KexState state = session.kexState.get();
                boolean kexDone = KexState.DONE.equals(state) || KexState.KEYS.equals(state);
                if (kexDone && kexFlushed) {
                    // Not in KEX, no pending packets: out it goes.
                    return session.doWritePacket(buffer);
                } else if (!holdsFutureLock && isBlockAllowed(cmd)) {
                    // KEX done, but still flushing: block until flushing is done, if we may block.
                    //
                    // The future lock is a _very_ global lock used for synchronization in many futures, and in
                    // particular in the key exchange related futures; and it is accessible by client code. If we
                    // block a thread holding that monitor, none of the futures that use that lock can ever be
                    // fulfilled, including the future this thread would wait upon.
                    //
                    // It would seem that calling writePacket() while holding *any* (session global) Apache MINA
                    // sshd lock in client code would be extremely bad practice. But note that the deprecated
                    // ClientUserAuthServiceOld does exactly that. While that deprecated service doesn't send
                    // channel data, there might be client code that does similar things. But this is also the
                    // reason why we must be careful to never synchronize on the futureLock while holding the
                    // kexLock: if that happened while code concurrently running called writePacket() while holding
                    // the futureLock, we might get a deadlock due to lock inversion.
                    //
                    // Blocking here will prevent data-pumping application threads from overrunning the flushing
                    // thread and ensures that the flushing thread does indeed terminate.
                    //
                    // Note that we block only for channel data.
                    block = kexFlushedFuture;
                } else {
                    // Still in KEX or still flushing and we cannot block the thread. Enqueue the packet; it will
                    // get written by the flushing thread at the end of KEX. Note that theoretically threads may
                    // queue arbitrarily many packets during KEX. However, such a scenario is mostly limited to
                    // "data pumping" threads that typically will block during KEX waiting until window space is
                    // available on the channel again, which can happen only at the end of KEX.
                    // (SSH_CHANNEL_WINDOW_ADJUST is not a low-level message and will not be sent during KEX.)
                    //
                    // If so many packets are queued that flushing them triggers another KEX flushing stops
                    // and will be resumed at the end of the new KEX.
                    if (kexDone && log.isDebugEnabled()) {
                        log.debug("writeOrEnqueue({})[{}]: Queuing packet while flushing", session,
                                SshConstants.getCommandMessageName(cmd));
                    }
                    return enqueuePendingPacket(cmd, buffer);
                }
            } finally {
                lock.readLock().unlock();
            }
            if (block != null) {
                if (timeout <= 0 || unit == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("writeOrEnqueue({})[{}]: Blocking thread {} until KEX is over", session,
                                SshConstants.getCommandMessageName(cmd), Thread.currentThread());
                    }
                    block.await();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("writeOrEnqueue({})[{}]: Blocking thread {} until KEX is over or timeout {} {}", session,
                                SshConstants.getCommandMessageName(cmd), Thread.currentThread(), timeout, unit);
                    }
                    block.await(timeout, unit);
                }
                if (log.isDebugEnabled()) {
                    log.debug("writeOrEnqueue({})[{}]: Thread {} awakens after KEX done", session,
                            SshConstants.getCommandMessageName(cmd), Thread.currentThread());
                }
            }
        }
    }

    /**
     * Tells whether the calling thread may be blocked in {@link #writePacket(Buffer, long, TimeUnit)}. This
     * implementation blocks writes of channel data packets unless written by an {@link ThreadUtils#isInternalThread()
     * internal thread}.
     * <p>
     * Typically an internal thread is one of the reading threads of Apache MINA sshd handling an SSH protocol message:
     * it's holding the {@link AbstractSession#decodeLock}; blocking it would mean we couldn't handle any other incoming
     * message, not even disconnections or another key exchange triggered by having lots of data queued.
     * </p>
     *
     * @param  cmd SSH command of the buffer to be written
     * @return     {@code true} if the thread may be blocked; {@code false} if the packet written <em>must</em> be
     *             queued without blocking the thread
     */
    protected boolean isBlockAllowed(int cmd) {
        boolean isChannelData = cmd == SshConstants.SSH_MSG_CHANNEL_DATA || cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA;
        return isChannelData && !ThreadUtils.isInternalThread();
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
                log.debug("enqueuePendingPacket({})[{}] Start flagging packets as pending until key exchange is done", session,
                        cmdName);
            } else {
                log.debug("enqueuePendingPacket({})[{}] enqueued until key exchange is done (pending={})", session, cmdName,
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
     * @param flushDone the future obtained from {@link #getFlushedFuture()}; will be fulfilled once all pending packets
     *                  have been written
     */
    protected void flushQueue(DefaultKeyExchangeFuture flushDone) {
        flushRunner.submit(() -> {
            List<SimpleImmutableEntry<PendingWriteFuture, IoWriteFuture>> pendingFutures = new ArrayList<>();
            boolean allFlushed = false;
            DefaultKeyExchangeFuture newFuture = null;
            try {
                boolean warnedAboutChunkLimit = false;
                int lastSize = -1;
                int take = 2;
                while (!allFlushed) {
                    if (!session.isOpen()) {
                        log.info("flushQueue({}): Session closed while flushing pending packets at end of KEX", session);
                        flushDone.setValue(Boolean.FALSE);
                        return;
                    }
                    // Using the writeLock this thread gets priority over the readLock used by writePacket(). Note that
                    // the outer loop essentially is just a loop around the critical region, so typically only one
                    // reader (i.e., writePacket() call) gets the lock before we get it again, and thus the flush really
                    // should rarely need to increase the chunk size. Data pumping threads in the application remain
                    // blocked until flushing is done.
                    lock.writeLock().lock();
                    try {
                        if (pendingPackets.isEmpty()) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): All packets at end of KEX flushed", session);
                            }
                            kexFlushed = true;
                            allFlushed = true;
                            break;
                        }
                        if (kexFlushedFuture != flushDone) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): Stopping flushing pending packets", session);
                            }
                            // Another KEX was started. Exit and hook up the flushDone future with the new future.
                            newFuture = kexFlushedFuture;
                            break;
                        }
                        int newSize = pendingPackets.size();
                        if (lastSize < 0) {
                            log.info("flushQueue({}): {} pending packets to flush", session, newSize);
                        } else if (newSize >= lastSize) {
                            log.info("flushQueue({}): queue size before={} now={}", session, lastSize, newSize);
                            // More new enqueues while we had written. Try writing more in one go to make progress.
                            if (take < 64) {
                                take *= 2;
                            } else if (!warnedAboutChunkLimit) {
                                warnedAboutChunkLimit = true;
                                log.warn("flushQueue({}): maximum queue flush chunk of 64 reached", session);
                            }
                        }
                        lastSize = newSize;
                        if (log.isDebugEnabled()) {
                            log.debug("flushQueue({}): flushing {} packets", session, Math.min(lastSize, take));
                        }
                        for (int i = 0; i < take; i++) {
                            PendingWriteFuture pending = pendingPackets.poll();
                            if (pending == null) {
                                break;
                            }
                            IoWriteFuture written;
                            try {
                                if (log.isTraceEnabled()) {
                                    log.trace("flushQueue({}): Flushing a packet at end of KEX for {}", session,
                                            pending.getId());
                                }
                                written = session.doWritePacket(pending.getBuffer());
                                pendingFutures.add(new SimpleImmutableEntry<>(pending, written));
                                if (log.isTraceEnabled()) {
                                    log.trace("flushQueue({}): Flushed a packet at end of KEX for {}", session,
                                            pending.getId());
                                }
                                session.resetIdleTimeout();
                            } catch (Throwable e) {
                                log.error("flushQueue({}): Exception while flushing packet at end of KEX for {}", session,
                                        pending.getId(), e);
                                pending.setException(e);
                                flushDone.setValue(e);
                                session.exceptionCaught(e);
                                return;
                            }
                        }
                        if (pendingPackets.isEmpty()) {
                            if (log.isDebugEnabled()) {
                                log.debug("flushQueue({}): All packets at end of KEX flushed", session);
                            }
                            kexFlushed = true;
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
                } else if (newFuture != null) {
                    newFuture.addListener(f -> {
                        Throwable error = f.getException();
                        if (error != null) {
                            flushDone.setValue(error);
                        } else {
                            flushDone.setValue(Boolean.TRUE);
                        }
                    });
                }
                // Connect all futures of packets that we wrote. We do this at the end instead of one-by-one inside the
                // loop to minimize the risk that woken up threads waiting on these futures queue up additional packets.
                pendingFutures.forEach(e -> e.getValue().addListener(e.getKey()));
            }
        });
    }
}
