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

package org.apache.sshd.client.channel;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channel;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * This is a specialized {@link SshFutureListener} that is used to enqueue data that is sent while the channel is being
 * set-up, so that when it is established it will send them in the same order as they have been received.
 *
 * It also serves as a &quot;backstop&quot; in case session is closed (normally) while the packets as still being
 * written.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientChannelPendingMessagesQueue
        extends AbstractLoggingBean
        implements SshFutureListener<OpenFuture>, Channel, ClientChannelHolder {
    protected final Deque<Map.Entry<Buffer, Consumer<? super Throwable>>> pendingQueue = new LinkedList<>();
    protected final DefaultOpenFuture completedFuture;

    private final ClientChannel clientChannel;
    private final AtomicBoolean open = new AtomicBoolean(true);

    public ClientChannelPendingMessagesQueue(ClientChannel channel) {
        this.clientChannel = Objects.requireNonNull(channel, "No channel provided");
        this.completedFuture = new DefaultOpenFuture(getClass().getSimpleName() + "[" + channel + "]", null);
    }

    @Override
    public ClientChannel getClientChannel() {
        return clientChannel;
    }

    /**
     * @return An internal {@link OpenFuture} that can be used to wait for all internal pending messages to be flushed
     *         before actually signaling that operation is complete
     */
    public OpenFuture getCompletedFuture() {
        return completedFuture;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void close() throws IOException {
        markClosed();

        // NOTE: do not close the channel here - it may need to remain open for other purposes
        int numPending = clearPendingQueue();
        if (log.isDebugEnabled()) {
            log.debug("close({}) cleared {} pending messages", this, numPending);
        }
    }

    /**
     * Marks the queue as closed
     *
     * @return {@code true} if was open and now is closed
     */
    protected boolean markClosed() {
        OpenFuture f = getCompletedFuture();
        if (!f.isDone()) {
            f.setException(new CancellationException("Cancelled"));
        }
        return open.getAndSet(false);
    }

    /**
     * Checks if the future is already open and manages the message handling accordingly:
     * <ul>
     * <p>
     * <li>If channel is not open yet, it enqueues the request</li>
     * </p>
     *
     * <p>
     * <li>If channel is open but there are still pending messages not yet written out, it will wait for them to be
     * written (or exception signaled) before proceeding to write out the incoming message.</li>
     * </p>
     *
     * <p>
     * <li>Otherwise (i.e., channel is open and no pending messages yet) it will write the message to the underlying
     * channel immediately.</li>
     * </p>
     * </ul>
     * 
     * @param  buffer      The message {@link Buffer}
     * @param  errHandler  The error handler to invoke it had to enqueue the message and was unsuccessful in writing it.
     *                     Must be non-{@code null} if future not open yet. Otherwise, if {@code null} and exception
     *                     occurs it will be simple re-thrown
     * @return             The total number of still pending messages - zero if none and message was written (either
     *                     immediately or after waiting for the pending ones to be written).
     * @throws IOException If wrote the message directly, encountered an error and no handler was provided.
     */
    public int handleIncomingMessage(Buffer buffer, Consumer<? super Throwable> errHandler) throws IOException {
        if (!isOpen()) {
            throw new EOFException("Queue is closed");
        }

        Objects.requireNonNull(buffer, "No message to enqueue");
        OpenFuture future = getCompletedFuture();
        synchronized (pendingQueue) {
            boolean enqueue = !future.isDone();
            if (enqueue) {
                Objects.requireNonNull(errHandler, "No pending message error handler provided");
            }

            if (enqueue) {
                pendingQueue.add(new SimpleImmutableEntry<>(buffer, errHandler));
                pendingQueue.notifyAll(); // in case anyone is waiting
            } else {
                writeMessage(buffer, errHandler);
            }

            return pendingQueue.size();
        }
    }

    protected void writeMessage(Buffer buffer, Consumer<? super IOException> errHandler) throws IOException {
        ClientChannel channel = getClientChannel();
        try {
            if (!isOpen()) {
                throw new EOFException("Queue is marked as closed");
            }

            if (!channel.isOpen()) {
                throw new EOFException("Client channel is closed/closing");
            }

            Session session = channel.getSession();
            if (!session.isOpen()) {
                throw new EOFException("Client session is closed/closing");
            }

            OutputStream outputStream = channel.getInvertedIn();
            outputStream.write(buffer.array(), buffer.rpos(), buffer.available());
            outputStream.flush();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("writeMessage({}) failed ({}) to output message: {}",
                        this, e.getClass().getSimpleName(), e.getMessage());
            }
            if (errHandler != null) {
                errHandler.accept(e);
            }

            markCompletionException(e);
            throw e;
        }
    }

    @Override
    public void operationComplete(OpenFuture future) {
        Throwable err = future.getException();
        if (err != null) {
            markCompletionException(err);

            if (markClosed()) {
                log.warn("operationComplete({}) {}[{}] signaled",
                        this, err.getClass().getSimpleName(), err.getMessage());
            } else {
                log.warn("operationComplete({}) got {}[{}] signal while queue is closed",
                        this, err.getClass().getSimpleName(), err.getMessage());
            }

            clearPendingQueue();
        } else {
            flushPendingQueue();
        }
    }

    protected void flushPendingQueue() {
        int numSent = 0;
        try {
            boolean debugEnabled = log.isDebugEnabled();
            if (debugEnabled) {
                log.debug("flushPendingQueue({}) start sending pending messages", this);
            }

            synchronized (pendingQueue) {
                for (; !pendingQueue.isEmpty(); numSent++) {
                    Map.Entry<Buffer, Consumer<? super Throwable>> msgEntry = pendingQueue.removeFirst();
                    writeMessage(msgEntry.getKey(), msgEntry.getValue());
                }

                markCompletionSuccessful();
            }

            if (debugEnabled) {
                log.debug("flushPendingQueue({}) sent {} pending messages", this, numSent);
            }
        } catch (IOException e) {
            markCompletionException(e);

            boolean closed = markClosed();
            int numPending = clearPendingQueue();
            log.warn("flushPendingQueue({}) Failed ({}) after {} successfully sent messages (pending={}, markClosed={}): {}",
                    this, e.getClass().getSimpleName(), numSent, numPending, closed, e.getMessage());
        }
    }

    protected OpenFuture markCompletionSuccessful() {
        OpenFuture f = getCompletedFuture();
        f.setOpened();
        return f;
    }

    protected OpenFuture markCompletionException(Throwable err) {
        OpenFuture f = getCompletedFuture();
        f.setException(err);
        return f;
    }

    protected int clearPendingQueue() {
        int numEntries;
        synchronized (pendingQueue) {
            numEntries = pendingQueue.size();
            if (numEntries > 0) {
                pendingQueue.clear();
            }
            pendingQueue.notifyAll(); // in case anyone waiting
        }

        return numEntries;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[channel=" + getClientChannel()
               + ", open=" + isOpen()
               + "]";
    }
}
