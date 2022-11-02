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

    /**
     * @param channel The {@link Channel} through which the stream is communicating
     * @param cmd     Either {@link SshConstants#SSH_MSG_CHANNEL_DATA SSH_MSG_CHANNEL_DATA} or
     *                {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA SSH_MSG_CHANNEL_EXTENDED_DATA} indicating the
     *                output stream type
     */
    public ChannelAsyncOutputStream(Channel channel, byte cmd) {
        this.channelInstance = Objects.requireNonNull(channel, "No channel");
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
                throw new WritePendingException(
                        "A write operation is already pending; cannot write " + buffer.available() + " bytes");
            }
            writeState.totalLength = buffer.available();
            writeState.toSend = writeState.totalLength;
            writeState.lastWrite = future;
            writeState.pendingWrite = future;
            writeState.writeInProgress = true;
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
        synchronized (writeState) {
            writeState.openState = state.get();
        }
        try {
            // Can't close this in preClose(); a graceful close waits for the currently pending write to finish and thus
            // still needs the packet writer.
            if (!(packetWriter instanceof Channel)) {
                try {
                    packetWriter.close();
                } catch (IOException e) {
                    error("doCloseImmediately({}) Failed ({}) to close packet writer: {}",
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
        int total;
        int notSent;
        synchronized (writeState) {
            writeState.openState = State.Closed;
            current = writeState.pendingWrite;
            writeState.pendingWrite = null;
            total = writeState.totalLength;
            notSent = writeState.toSend;
        }
        if (current != null) {
            terminateFuture(current);
        }
        if (notSent > 0) {
            log.warn("doCloseImmediately({}): still have {} bytes of {} on closing channel", this, notSent, total);
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
        IoWriteFuture last;
        IoWriteFutureImpl current;
        synchronized (writeState) {
            last = writeState.lastWrite;
            current = writeState.pendingWrite;
        }
        if (last == null) {
            return builder().build().close(false);
        }
        if (log.isDebugEnabled() && (current instanceof BufferedFuture) && ((BufferedFuture) current).waitOnWindow) {
            log.debug("doCloseGracefully({}): writing last data (waiting on window expansion)", this);
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
            writeState.windowExpanded |= resume;
            if (writeState.pendingWrite == null) {
                // Just set the flag if there's nothing to write, or a writePacket() call is in progress.
                // In the latter case, we'll check again below.
                return;
            } else {
                openState = writeState.openState;
                currentWrite = writeState.pendingWrite;
                writeState.pendingWrite = null;
                writeState.windowExpanded = false;
            }
        }
        while (currentWrite != null) {
            if (abortWrite(openState)) {
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
                openState = writeState.openState;
                if (writeState.windowExpanded) {
                    writeState.windowExpanded = false;
                    resume = true;
                    currentWrite = nextWrite; // Try again.
                } else {
                    if (!abortWrite(openState)) {
                        writeState.pendingWrite = nextWrite;
                    } else {
                        writeState.writeInProgress = false;
                    }
                    currentWrite = null;
                }
            }
            if (currentWrite == null && abortWrite(openState)) {
                terminateFuture(nextWrite);
                break;
            }
        }
    }

    private boolean abortWrite(State openState) {
        // Allow writing if the stream is open or being gracefully closed. Note: the Session will still exist,
        // and the window may still be expanded. If the packet writer is the channel itself, the channel must
        // allow writing even if closing (until it finally is closed).
        return State.Immediate.equals(openState) || State.Closed.equals(openState);
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
        int stillToSend = buffer.available();
        if (stillToSend <= 0) {
            if (log.isTraceEnabled()) {
                log.trace("writePacket({}) current buffer sent", this);
            }
            synchronized (writeState) {
                writeState.writeInProgress = false;
            }
            future.setValue(Boolean.TRUE);
            return null;
        }
        Channel channel = getChannel();
        RemoteWindow remoteWindow = channel.getRemoteWindow();
        // An erratum on RFC 4254 at https://www.rfc-editor.org/errata/rfc4254 claims that the 4 bytes for the data
        // length had to be included in window computations. Which raises the question of what should happen if the
        // remaining window size is < 4. If the peer waits for the window size to drop to zero before sending its window
        // adjustment, the channel would block, since we cannot even send a zero-sized data chunk to consume the last
        // bytes. Probably that erratum is itself erroneous?
        //
        // At least OpenSSH does appear *not* to include the 4 bytes for the data length in the window computations. It
        // does do so _partially_ for "datagram" (TunnelForward) channels, but there it appears to do it (as of OpenSSH
        // 9.1) inconsistently: when writing to the channel, it decreases the remote window size by the data length; but
        // when reading from the channel, it decreases the local window size by the data length + 4. That appears to be
        // a bug?
        //
        // PuTTY also does not include these 4 bytes.
        long remoteWindowSize = remoteWindow.getSize();
        long packetSize = remoteWindow.getPacketSize();
        int chunkLength = (int) Math.min(stillToSend, Math.min(packetSize, remoteWindowSize));

        IoWriteFutureImpl f = future;
        if (chunkLength < stillToSend && !(f instanceof BufferedFuture)) {
            // We can send only part of the data remaining: copy the buffer (if it hasn't been copied before) because
            // the original may be re-used, then send the bit we can send, and queue up a future for sending the rest.
            Buffer copied = new ByteArrayBuffer(stillToSend);
            copied.putBuffer(buffer, false);
            f = new BufferedFuture(future.getId(), copied);
            f.addListener(w -> future.setValue(w.getException() != null ? w.getException() : w.isWritten()));
        }
        if (chunkLength <= 0) {
            // Cannot send anything now -- we have to wait for a window adjustment.
            if (log.isTraceEnabled()) {
                log.trace("writePacket({})[resume={}] waiting for window space {}", this, resume, remoteWindowSize);
            }
            ((BufferedFuture) f).waitOnWindow = true;
            return f;
        }
        if (f instanceof BufferedFuture) {
            ((BufferedFuture) f).waitOnWindow = false;
        }
        buffer = f.getBuffer();
        // Write the chunk
        if (log.isTraceEnabled()) {
            log.trace("writePacket({})[resume={}] attempting to write {} out of {}", this, resume, chunkLength,
                    stillToSend);
        }
        if (chunkLength >= (Integer.MAX_VALUE - 12)) {
            // This check is a bit pointless. We allocate a buffer in createSendBuffer of chunkLength + 12 bytes, but:
            // 1. session.createBuffer() will add more for SSH protocol overheads like the header and padding.
            // 2. Some Java VMs may have a limit that is actually a few bytes short of Integer.MAX_VALUE.
            // 3. The channel's packet size should never be that large.
            IllegalArgumentException error = new IllegalArgumentException(
                    "Command " + SshConstants.getCommandMessageName(cmd) + " length (" + chunkLength
                                                                          + ") exceeds int boundaries");
            synchronized (writeState) {
                writeState.writeInProgress = false;
            }
            f.setValue(error);
            throw error;
        }

        remoteWindow.consume(chunkLength);

        IoWriteFuture writeFuture;
        try {
            writeFuture = packetWriter.writeData(createSendBuffer(buffer, channel, chunkLength));
        } catch (Throwable e) {
            synchronized (writeState) {
                writeState.writeInProgress = false;
            }
            f.setValue(e);
            return null;
        }
        IoWriteFutureImpl thisFuture = f;
        writeFuture.addListener(w -> onWritten(thisFuture, stillToSend, chunkLength, w));
        // If something remains it will be written via the listener we just added.
        return null;
    }

    protected void onWritten(IoWriteFutureImpl future, int total, int length, IoWriteFuture f) {
        if (f.isWritten()) {
            if (total > length) {
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write of {} out of {}",
                            this, length, total);
                }
                synchronized (writeState) {
                    writeState.toSend -= length;
                    writeState.pendingWrite = future;
                }

                doWriteIfPossible(false);
            } else {
                synchronized (writeState) {
                    writeState.toSend = 0;
                    writeState.pendingWrite = null;
                    writeState.writeInProgress = false;
                }
                if (log.isTraceEnabled()) {
                    log.trace("onWritten({}) completed write len={}", this, total);
                }
                future.setValue(Boolean.TRUE);
            }
        } else {
            Throwable reason = f.getException();
            debug("onWritten({}) failed ({}) to complete write of {} out of {}: {}",
                    this, reason.getClass().getSimpleName(), length, total, reason.getMessage(), reason);
            synchronized (writeState) {
                writeState.pendingWrite = null;
                writeState.writeInProgress = false;
            }
            future.setValue(reason);
        }
    }

    protected Buffer createSendBuffer(Buffer buffer, Channel channel, int length) {
        SessionContext.validateSessionPayloadSize(length, "Invalid send buffer length: %d");

        Session s = channel.getSession();
        Buffer buf = s.createBuffer(cmd, length + 12);
        buf.putUInt(channel.getRecipient());
        if (cmd == SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA) {
            buf.putUInt(SshConstants.SSH_EXTENDED_DATA_STDERR);
        }
        buf.putUInt(length);
        buf.putRawBytes(buffer.array(), buffer.rpos(), length);
        buffer.rpos(buffer.rpos() + length);
        return buf;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getChannel() + "] cmd=" + SshConstants.getCommandMessageName(cmd & 0xFF);
    }

    /**
     * Marker type to avoid repeated buffering in
     * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)}.
     */
    protected static class BufferedFuture extends IoWriteFutureImpl {

        protected boolean waitOnWindow;

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
        protected IoWriteFuture lastWrite;

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
         * {@link ChannelAsyncOutputStream#writePacket(IoWriteFutureImpl, boolean)} again.
         */
        protected boolean windowExpanded;

        /**
         * A copy of this stream's state as set by the superclass.
         */
        protected State openState = State.Opened;

        /**
         * Number of bytes to send in total.
         */
        protected int totalLength;

        /**
         * Number of bytes still to send.
         */
        protected int toSend;

        protected WriteState() {
            super();
        }
    }
}
