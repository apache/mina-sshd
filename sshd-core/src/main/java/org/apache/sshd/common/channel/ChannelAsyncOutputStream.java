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
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriter;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.WritePendingException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

public class ChannelAsyncOutputStream extends AbstractCloseable implements IoOutputStream, ChannelHolder {

    /**
     * Encapsulates the state of the current write operation. Access is always under lock (on writeState's monitor), the
     * lock is held only shortly and never while writing.
     */
    protected final WriteState writeState = new WriteState();

    private final Channel channelInstance;
    private final ChannelStreamWriter packetWriter;
    private final byte cmd;
    private final Object packetWriteId;

    private boolean sendChunkIfRemoteWindowIsSmallerThanPacketSize;

    /**
     * @param channel The {@link Channel} through which the stream is communicating
     * @param cmd     Either {@link SshConstants#SSH_MSG_CHANNEL_DATA SSH_MSG_CHANNEL_DATA} or
     *                {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA SSH_MSG_CHANNEL_EXTENDED_DATA} indicating the
     *                output stream type
     */
    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this(channel, cmd, false);
    }

    /**
     * @param channel                                        The {@link Channel} through which the stream is
     *                                                       communicating
     * @param cmd                                            Either {@link SshConstants#SSH_MSG_CHANNEL_DATA
     *                                                       SSH_MSG_CHANNEL_DATA} or
     *                                                       {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA
     *                                                       SSH_MSG_CHANNEL_EXTENDED_DATA} indicating the output stream
     *                                                       type
     * @param sendChunkIfRemoteWindowIsSmallerThanPacketSize Determines the chunking behaviour, if the remote window
     *                                                       size is smaller than the packet size. Can be used to
     *                                                       establish compatibility with certain clients, that wait
     *                                                       until the window size is 0 before adjusting it.
     * @see                                                  <A HREF=
     *                                                       "https://issues.apache.org/jira/browse/SSHD-1123">SSHD-1123</A>
     */
    public ChannelAsyncOutputStream(Channel channel, byte cmd, boolean sendChunkIfRemoteWindowIsSmallerThanPacketSize) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
        this.sendChunkIfRemoteWindowIsSmallerThanPacketSize = sendChunkIfRemoteWindowIsSmallerThanPacketSize;
        this.packetWriter = channelInstance.resolveChannelStreamWriter(channel, cmd);
        this.cmd = cmd;
        this.packetWriteId = channel.toString() + "[" + SshConstants.getCommandMessageName(cmd) + "]";
    }

    @Override
    public Channel getChannel() {
        return channelInstance;
    }

    /**
     * @return Either {@link SshConstants#SSH_MSG_CHANNEL_DATA SSH_MSG_CHANNEL_DATA} or
     *         {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA SSH_MSG_CHANNEL_EXTENDED_DATA} indicating the output
     *         stream type
     */
    public byte getCommandType() {
        return cmd;
    }

    /**
     * {@inheritDoc}
     *
     * This write operation is <em>asynchronous</em>: if there is not enough window space, it may keep the write pending
     * or write only part of the buffer and keep the rest pending. Concurrent writes are not allowed and will throw a
     * {@link WritePendingException}. Any subsequent write <em>must</em> occur only once the returned future is
     * fulfilled; for instance triggered via a listener on the returned future. Try to avoid doing a subsequent write
     * directly in a future listener, though; doing so may lead to deep chains of nested listener calls with deep stack
     * traces, and may ultimately lead to a stack overflow.
     *
     * @throws WritePendingException if a concurrent write is attempted
     */
    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
        if (isClosing()) {
            throw new EOFException("Closing: " + writeState);
        }

        IoWriteFutureImpl future = new IoWriteFutureImpl(packetWriteId, buffer);
        synchronized (writeState) {
            if (!State.Opened.equals(writeState.openState)) { // Double check.
                throw new EOFException("Closing: " + writeState);
            }
            if (writeState.writeInProgress) {
                throw new WritePendingException("A write operation is already pending");
            }
            writeState.lastWrite = future;
            writeState.pendingWrite = future;
            writeState.writeInProgress = true;
            writeState.waitingOnIo = false;
        }
        doWriteIfPossible(false);
        return future;
    }

    @Override
    protected void preClose() {
        synchronized (writeState) {
            writeState.openState = state.get();
        }
        super.preClose();
    }

    @Override
    protected void doCloseImmediately() {
        try {
            // Can't close this in preClose(); a graceful close waits for the currently pending write to finish and thus
            // still needs the packet writer.
            if (!(packetWriter instanceof Channel)) {
                try {
                    packetWriter.close();
                } catch (IOException e) {
                    error("preClose({}) Failed ({}) to pre-close packet writer: {}",
                            this, e.getClass().getSimpleName(), e.getMessage(), e);
                }
            }
            super.doCloseImmediately();
        } finally {
            shutdown();
        }
    }

    protected void shutdown() {
        IoWriteFutureImpl current = null;
        synchronized (writeState) {
            writeState.openState = State.Closed;
            current = writeState.pendingWrite;
            writeState.pendingWrite = null;
            writeState.waitingOnIo = false;
        }
        if (current != null) {
            terminateFuture(current);
        }
    }

    protected void terminateFuture(IoWriteFutureImpl future) {
        if (!future.isDone()) {
            if (future.getBuffer().available() > 0) {
                future.setValue(new EOFException("Channel closing"));
            } else {
                future.setValue(Boolean.TRUE);
            }
        }
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        IoWriteFutureImpl last;
        synchronized (writeState) {
            last = writeState.lastWrite;
        }
        if (last == null) {
            return builder().build().close(false);
        }
        return builder().when(last).build().close(false);
    }

    public void onWindowExpanded() throws IOException {
        doWriteIfPossible(true);
    }

    protected void doWriteIfPossible(boolean resume) {
        IoWriteFutureImpl currentWrite = null;
        State openState;
        synchronized (writeState) {
            writeState.windowExpanded = resume;
            openState = writeState.openState;
            if (writeState.pendingWrite == null || resume && writeState.waitingOnIo) {
                // Just set the flag if there's nothing to write, or a writePacket() call is in progress.
                // In the latter case, we'll check again below. Also set the flag only if there is a chained
                // future waiting on some I/O to finish. In that case, that future will execute the next write
                // anyway.
                return;
            } else {
                currentWrite = writeState.pendingWrite;
                writeState.pendingWrite = null;
                writeState.windowExpanded = false;
                writeState.waitingOnIo = false;
            }
        }
        while (currentWrite != null) {
            if (State.Immediate.equals(openState) || State.Closed.equals(openState)) {
                // For gracefully closing, allow the write to proceed. We'll terminate the write only if it should block
                // because of not enough window space.
                terminateFuture(currentWrite);
                break;
            }
            IoWriteFutureImpl nextWrite = writePacket(currentWrite, resume);
            if (nextWrite == null) {
                // We're either done, or we hooked up a listener to write the next chunk.
                break;
            }
            // We're waiting on the window to be expanded. If it already was expanded, try again, otherwise just record
            // the future; it'll be run via onWindowExpanded().
            synchronized (writeState) {
                writeState.waitingOnIo = false;
                openState = writeState.openState;
                if (writeState.windowExpanded) {
                    writeState.windowExpanded = false;
                    currentWrite = nextWrite; // Try again.
                } else {
                    if (State.Opened.equals(openState)) {
                        writeState.pendingWrite = nextWrite;
                    } else {
                        writeState.writeInProgress = false;
                    }
                    currentWrite = null;
                }
            }
            // If the channel is closing, we can't wait for the window to be expanded anymore. Just abort.
            if (currentWrite == null && !State.Opened.equals(openState)) {
                terminateFuture(nextWrite);
                break;
            }
        }
    }

    /**
     * Try to write as much of the current buffer as possible. If the buffer is larger than the packet size split it in
     * packets, writing one after the other by chaining futures. If there is not enough window space, stop writing.
     * Writing will be resumed once the window has been enlarged again.
     *
     * @param  future {@link IoWriteFutureImpl} for the current write
     * @param  resume whether being called in response to a remote window adjustment
     * @return        {@code null} if all written, or if the rest will be written via a future listener. Otherwise a
     *                future for the remaining writes.
     */
    protected IoWriteFutureImpl writePacket(IoWriteFutureImpl future, boolean resume) {
        Buffer buffer = future.getBuffer();
        int total = buffer.available();
        if (total > 0) {
            Channel channel = getChannel();
            Window remoteWindow = channel.getRemoteWindow();
            long length;
            long remoteWindowSize = remoteWindow.getSize();
            long packetSize = remoteWindow.getPacketSize();
            if (total > remoteWindowSize) {
                // if we have a big message and there is enough space, send the next chunk
                if (remoteWindowSize >= packetSize) {
                    // send the first chunk as we have enough space in the window
                    length = packetSize;
                } else {
                    // Window size is even smaller than packet size. Determine how to handle this.
                    if (isSendChunkIfRemoteWindowIsSmallerThanPacketSize()) {
                        length = remoteWindowSize;
                    } else {
                        // do not chunk when the window is smaller than the packet size
                        if (future instanceof BufferedFuture) {
                            return future;
                        }
                        // do a defensive copy in case the user reuses the buffer
                        IoWriteFutureImpl f
                                = new BufferedFuture(future.getId(), new ByteArrayBuffer(buffer.getCompactData()));
                        f.addListener(w -> future.setValue(w.getException() != null ? w.getException() : w.isWritten()));
                        if (log.isTraceEnabled()) {
                            log.trace("doWriteIfPossible({})[resume={}] waiting for window space {}",
                                    this, resume, remoteWindowSize);
                        }
                        return f;
                    }
                }
            } else if (total > packetSize) {
                if (buffer.rpos() > 0 && !(future instanceof BufferedFuture)) {
                    // do a defensive copy in case the user reuses the buffer
                    IoWriteFutureImpl f = new BufferedFuture(future.getId(), new ByteArrayBuffer(buffer.getCompactData()));
                    f.addListener(w -> future.setValue(w.getException() != null ? w.getException() : w.isWritten()));
                    length = packetSize;
                    if (log.isTraceEnabled()) {
                        log.trace("doWriteIfPossible({})[resume={}] attempting to write {} out of {}",
                                this, resume, length, total);
                    }
                    return writePacket(f, resume);
                } else {
                    length = packetSize;
                }
            } else {
                length = total;
                if (log.isTraceEnabled()) {
                    log.trace("doWriteIfPossible({})[resume={}] attempting to write {} bytes", this, resume, length);
                }
            }

            if (length > 0) {
                if (resume) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resuming {} write due to more space ({}) available in the remote window", this, length);
                    }
                }

                if (length >= (Integer.MAX_VALUE - 12)) {
                    throw new IllegalArgumentException(
                            "Command " + SshConstants.getCommandMessageName(cmd) + " length (" + length
                                                       + ") exceeds int boundaries");
                }

                Buffer buf = createSendBuffer(buffer, channel, length);
                remoteWindow.consume(length);

                IoWriteFuture writeFuture;
                try {
                    writeFuture = packetWriter.writeData(buf);
                } catch (IOException e) {
                    synchronized (writeState) {
                        writeState.writeInProgress = false;
                    }
                    future.setValue(e);
                    return null;
                }
                synchronized (writeState) {
                    writeState.pendingWrite = future;
                    writeState.waitingOnIo = true;
                }
                writeFuture.addListener(f -> onWritten(future, total, length, f));
            } else {
                // remote window has zero size?
                if (!resume && log.isDebugEnabled()) {
                    log.debug("doWriteIfPossible({}) delaying write until space is available in the remote window", this);
                }
                return future;
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("doWriteIfPossible({}) current buffer sent", this);
            }
            synchronized (writeState) {
                writeState.writeInProgress = false;
            }
            future.setValue(Boolean.TRUE);
        }
        return null;
    }

    protected void onWritten(IoWriteFutureImpl future, int total, long length, IoWriteFuture f) {
        if (f.isWritten()) {
            if (total > length) {
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write of {} out of {}",
                            this, length, total);
                }
                doWriteIfPossible(false);
            } else {
                synchronized (writeState) {
                    if (writeState.pendingWrite == future) {
                        writeState.pendingWrite = null;
                        writeState.writeInProgress = false;
                        writeState.waitingOnIo = false;
                    } else {
                        log.error("onWritten({}) future changed", this);
                    }
                }
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write len={}, more={}", this, total);
                }
                future.setValue(Boolean.TRUE);
            }
        } else {
            Throwable reason = f.getException();
            debug("onWritten({}) failed ({}) to complete write of {} out of {}: {}",
                    this, reason.getClass().getSimpleName(), length, total, reason.getMessage(), reason);
            synchronized (writeState) {
                if (writeState.pendingWrite == future) {
                    writeState.pendingWrite = null;
                    writeState.writeInProgress = false;
                    writeState.waitingOnIo = false;
                } else {
                    log.error("onWritten({}) future changed", this);
                }
            }
            if (log.isTraceEnabled()) {
                log.trace("onWritten({}) failed write len={}, more={}", this, total);
            }
            future.setValue(reason);
        }
    }

    protected Buffer createSendBuffer(Buffer buffer, Channel channel, long length) {
        SessionContext.validateSessionPayloadSize(length, "Invalid send buffer length: %d");

        Session s = channel.getSession();
        Buffer buf = s.createBuffer(cmd, (int) length + 12);
        buf.putUInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buf.putUInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
        }
        buf.putUInt(length);
        buf.putRawBytes(buffer.array(), buffer.rpos(), (int) length);
        buffer.rpos(buffer.rpos() + (int) length);
        return buf;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] cmd=" + SshConstants.getCommandMessageName(cmd & 0xFF);
    }

    public boolean isSendChunkIfRemoteWindowIsSmallerThanPacketSize() {
        return sendChunkIfRemoteWindowIsSmallerThanPacketSize;
    }

    public void setSendChunkIfRemoteWindowIsSmallerThanPacketSize(boolean sendChunkIfRemoteWindowIsSmallerThanPacketSize) {
        this.sendChunkIfRemoteWindowIsSmallerThanPacketSize = sendChunkIfRemoteWindowIsSmallerThanPacketSize;
    }

    /**
     * Marker type to avoid repeated buffering in
     * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)}.
     */
    protected static class BufferedFuture extends IoWriteFutureImpl {

        BufferedFuture(Object id, Buffer buffer) {
            super(id, buffer);
        }
    }

    /**
     * Collects state variables; access is always synchronized on the single instance per stream.
     */
    protected static class WriteState {

        /**
         * The future describing the last executed *buffer* write {@link ChannelAsyncOutputStream#writeBuffer(Buffer)}.
         * Used for graceful closing.
         */
        protected IoWriteFutureImpl lastWrite;

        /**
         * The future describing the current packet write; if {@code null}, there is nothing to write or
         * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)} is running.
         */
        protected IoWriteFutureImpl pendingWrite;

        /**
         * Flag to throw an exception if non-sequential {@link ChannelAsyncOutputStream#writeBuffer(Buffer)} calls
         * should occur.
         */
        protected boolean writeInProgress;

        /**
         * Set to true when there was a remote window expansion while
         * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)} was in progress. If set,
         * {@link ChannelAsyncOutputStream#doWriteIfPossible(boolean)} will run a
         * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)} again...
         */
        protected boolean windowExpanded;

        /**
         * ...unless the current {@link #pendingWrite} is waiting on I/O (which will either finish or continue the write
         * anyway).
         */
        protected boolean waitingOnIo;

        /**
         * A copy of the channel state.
         */
        protected State openState = State.Opened;

        protected WriteState() {
            super();
        }
    }
}
