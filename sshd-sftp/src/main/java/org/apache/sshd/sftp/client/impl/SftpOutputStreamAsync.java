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
package org.apache.sshd.sftp.client.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.time.Duration;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.helpers.PacketBuffer;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.output.OutputStreamWithChannel;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.SftpClientHolder;
import org.apache.sshd.sftp.client.SftpMessage;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements an output stream for a given remote file
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpOutputStreamAsync extends OutputStreamWithChannel implements SftpClientHolder {
    protected final Logger log;
    protected final byte[] bb = new byte[1];
    protected final int bufferSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long offset;
    protected final Deque<SftpAckData> pendingAcks = new LinkedList<>();

    private final AbstractSftpClient clientInstance;
    private final String path;
    private final byte[] handleId;
    private final boolean ownsHandle;
    private final Buffer[] bufferPool = new Buffer[2];
    private final int packetSize;
    private final int sftpPreamble;
    private final boolean usePacket;

    private int nextBuffer;
    private SftpMessage lastMsg;

    /**
     * Creates a new stream to write data to a remote file.
     *
     * @param  client      {@link AbstractSftpClient} to use for writing data
     * @param  bufferSize  SFTP packet length to use. Most servers have a limit of 256kB. If zero, the stream picks a
     *                     size such that each SFTP packet fits into a single SSH packet, i.e., roughly 32kB.
     * @param  path        remote path to write to
     * @param  mode        {@link OpenMode}s for opening the file.
     * @throws IOException if the remote file cannot be opened
     */
    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, Collection<OpenMode> mode)
            throws IOException {
        this(client, bufferSize, path, client.open(path, mode), true);
    }

    /**
     * Creates a new stream to write data to a remote file.
     *
     * @param client     {@link AbstractSftpClient} to use for writing data
     * @param bufferSize SFTP packet length to use. Most servers have a limit of 256kB. If zero, the stream picks a size
     *                   such that each SFTP packet fits into a single SSH packet, i.e., roughly 32kB.
     * @param handle     {@link CloseableHandle} of the remote file to write to; will be closed when this output stream
     *                   is closed
     */
    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, CloseableHandle handle) {
        this(client, bufferSize, path, handle, true);
    }

    /**
     * Creates a new stream to write data to a remote file.
     *
     * @param client      {@link AbstractSftpClient} to use for writing data
     * @param bufferSize  SFTP packet length to use. Most servers have a limit of 256kB. If zero, the stream picks a
     *                    size such that each SFTP packet fits into a single SSH packet, i.e., roughly 32kB.
     * @param handle      {@link CloseableHandle} of the remote file to write to
     * @param closeHandle whether to close the {@code handle} when this output stream is closed
     */
    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, CloseableHandle handle, boolean closeHandle) {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = handle;
        this.handleId = this.handle.getIdentifier();
        // SFTP WRITE packet header:
        // 9 = length + type + sftp request id
        // 4 = handle length
        // handle bytes
        // 8 = file offset
        // 4 = length of actual data
        this.sftpPreamble = 9 + 4 + handleId.length + 8 + 4;
        this.ownsHandle = closeHandle;
        this.packetSize = (int) client.getChannel().getRemoteWindow().getPacketSize();
        int bufSize = bufferSize;
        if (bufSize == 0) {
            bufSize = packetSize;
        } else {
            ValidateUtils.checkTrue(bufferSize >= SftpClient.MIN_WRITE_BUFFER_SIZE, "SFTP write buffer too small: %d < %d",
                    bufferSize, SftpClient.MIN_WRITE_BUFFER_SIZE);
            bufSize += sftpPreamble;
        }
        this.usePacket = bufSize <= packetSize;
        if (usePacket) {
            // 9 = SSH_MSG_CHANNEL_DATA + recipient channel + length (RFC 4254); length <= packet size
            bufSize += 9;
        }
        this.bufferSize = bufSize;
    }

    @Override
    public final AbstractSftpClient getClient() {
        return clientInstance;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    /**
     * The remotely accessed file path
     *
     * @return Remote file path
     */
    public final String getPath() {
        return path;
    }

    @Override
    public boolean isOpen() {
        return (handle != null) && handle.isOpen();
    }

    @Override
    public void write(int b) throws IOException {
        bb[0] = (byte) b;
        write(bb, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(b, off, len);
        internalTransfer(in::read, false);
    }

    public long transferFrom(InputStream stream) throws IOException {
        return internalTransfer(stream::read, true);
    }

    public long transferFrom(ReadableByteChannel stream, long count) throws IOException {
        return internalTransfer(new ChannelReader(stream, count), false);
    }

    private Buffer getBuffer(Session session) {
        Buffer buf = bufferPool[nextBuffer];
        if (buf == null) {
            if (nextBuffer == 1 && lastMsg != null && lastMsg.getFuture().isDone()) {
                // No need to allocate a second buffer, we may re-use the 0 buffer
                nextBuffer = 0;
                buf = bufferPool[0];
            } else {
                if (usePacket) {
                    buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA, bufferSize);
                } else {
                    buf = new ByteArrayBuffer(bufferSize, false);
                }
                bufferPool[nextBuffer] = buf;
            }
        }
        nextBuffer ^= 1;
        int hdr;
        if (buf instanceof PacketBuffer) {
            // 9 = SshConstants.SSH_MSG_CHANNEL_DATA + recipient channel + length (RFC 4254)
            hdr = SshConstants.SSH_PACKET_HEADER_LEN + 9 + sftpPreamble;
        } else {
            // Only the SFTP header. The channel will split this large SFTP packet into smaller SSH packets anyway, and
            // allocate its own SSH_MSG_CHANNEL_DATA packets. (Larger SFTP packets may result in less ACKs, but involve
            // copying buffers around.)
            hdr = sftpPreamble;
        }
        buf.rpos(hdr);
        buf.wpos(hdr);
        return buf;
    }

    @FunctionalInterface
    private interface ByteInput {
        int read(byte[] buffer, int offset, int length) throws IOException;
    }

    private static class ChannelReader implements ByteInput {
        private final ReadableByteChannel src;
        private long stillToRead;

        ChannelReader(ReadableByteChannel src, long toRead) {
            this.src = src;
            this.stillToRead = toRead;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (stillToRead <= 0) {
                return -1;
            }
            ByteBuffer wrap = ByteBuffer.wrap(buffer, offset, (int) Math.min(length, stillToRead));
            int actuallyRead = src.read(wrap);
            if (actuallyRead < 0) {
                // EOF.
                stillToRead = 0;
                return -1;
            }
            stillToRead -= actuallyRead;
            return actuallyRead;
        }
    }

    private long internalTransfer(ByteInput stream, boolean forceFlush) throws IOException {
        SftpClient client = getClient();
        Session session = client.getSession();

        boolean traceEnabled = log.isTraceEnabled();
        long writtenCount = 0;
        boolean eof = false;
        do {
            if (buffer == null) {
                buffer = getBuffer(session);
            }

            int pos = buffer.wpos();
            int off = pos;
            int toRead = bufferSize - off;
            while (toRead > 0) {
                int n = stream.read(buffer.array(), off, toRead);
                if (n < 0) {
                    eof = true;
                    break;
                }
                off += n;
                toRead -= n;
            }

            writtenCount += off - pos;
            buffer.wpos(off);
            if (off == bufferSize || eof && forceFlush && buffer.available() > 0) {
                if (traceEnabled) {
                    log.trace("write({}) flush after {} bytes", this, writtenCount);
                }
                internalFlush();
            }
        } while (!eof);
        return writtenCount;
    }

    @Override
    public void flush() throws IOException {
        internalFlush();
        if (lastMsg != null) {
            lastMsg.waitUntilSent();
            lastMsg = null;
        }
    }

    private void internalFlush() throws IOException {
        if (!isOpen()) {
            throw new IOException("flush(" + getPath() + ") stream is closed");
        }

        boolean debugEnabled = log.isDebugEnabled();
        AbstractSftpClient client = getClient();
        for (int ackIndex = 1;; ackIndex++) {
            SftpAckData ack = pendingAcks.peek();
            if (ack == null) {
                if (debugEnabled) {
                    log.debug("flush({}) processed {} pending writes", this, ackIndex);
                }
                break;
            }

            if (debugEnabled) {
                log.debug("flush({}) waiting for ack #{}: {}", this, ackIndex, ack);
            }

            Buffer buf = client.receive(ack.id, Duration.ZERO);
            if (buf == null) {
                if (debugEnabled) {
                    log.debug("flush({}) no response for ack #{}: {}", this, ackIndex, ack);
                }
                break;
            }

            if (debugEnabled) {
                log.debug("flush({}) processing ack #{}: {}", this, ackIndex, ack);
            }

            pendingAcks.removeFirst();
            checkStatus(client, buf);
        }

        if (buffer == null) {
            if (debugEnabled) {
                log.debug("flush({}) no pending buffer to flush", this);
            }
            return;
        }

        int avail = buffer.available();

        int wpos = buffer.wpos();
        // 4 = handle length
        // handle bytes
        // 8 = file offset
        // 4 = length of actual data
        buffer.rpos(buffer.rpos() - 16 - handleId.length);
        buffer.wpos(buffer.rpos());
        buffer.putBytes(handleId);
        buffer.putLong(offset);
        buffer.putUInt(avail);
        buffer.wpos(wpos);

        if (lastMsg != null) {
            lastMsg.waitUntilSent();
        }
        lastMsg = client.write(SftpConstants.SSH_FXP_WRITE, buffer);
        SftpAckData ack = new SftpAckData(lastMsg.getId(), offset, avail);
        if (debugEnabled) {
            log.debug("flush({}) enqueue pending ack={}", this, ack);
        }
        pendingAcks.add(ack);

        offset += avail;
        buffer = null;
    }

    private void checkStatus(AbstractSftpClient client, Buffer buf) throws IOException {
        if (buf.available() >= 13) {
            int rpos = buf.rpos();
            buf.rpos(rpos + 4); // Skip length
            int cmd = buf.getUByte();
            if (cmd != SftpConstants.SSH_FXP_STATUS) {
                throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                        "Unexpected SFTP response; expected SSH_FXP_STATUS but got "
                                                                          + SftpConstants.getCommandMessageName(cmd));
            }
            buf.rpos(rpos + 9); // Skip ahead until after the id
            if (buf.getInt() == SftpConstants.SSH_FX_OK) {
                return;
            }
            // Reset and do the full parse
            buf.rpos(rpos);
        }
        SftpResponse response = SftpResponse.parse(SftpConstants.SSH_FXP_WRITE, buf);
        client.checkResponseStatus(SftpConstants.SSH_FXP_WRITE, response.getId(), SftpStatus.parse(response));
    }

    @Override
    public void close() throws IOException {
        if (!isOpen()) {
            return;
        }

        try {
            boolean debugEnabled = log.isDebugEnabled();

            try {
                int pendingSize = (buffer == null) ? 0 : buffer.available();
                if (pendingSize > 0) {
                    if (debugEnabled) {
                        log.debug("close({}) flushing {} pending bytes", this, pendingSize);
                    }
                    internalFlush();
                }
                if (lastMsg != null) {
                    lastMsg.waitUntilSent();
                    lastMsg = null;
                }

                Duration idleTimeout = CoreModuleProperties.IDLE_TIMEOUT.getRequired(getClient().getClientSession());
                if (GenericUtils.isNegativeOrNull(idleTimeout)) {
                    idleTimeout = CoreModuleProperties.IDLE_TIMEOUT.getRequiredDefault();
                }
                AbstractSftpClient client = getClient();
                for (int ackIndex = 1; !pendingAcks.isEmpty(); ackIndex++) {
                    SftpAckData ack = pendingAcks.removeFirst();
                    if (debugEnabled) {
                        log.debug("close({}) processing ack #{}: {}", this, ackIndex, ack);
                    }

                    Buffer buf = client.receive(ack.id, idleTimeout);
                    if (buf == null) {
                        log.debug("close({}) no ack response for {}", this, ack);
                        break;
                    }
                    if (debugEnabled) {
                        log.debug("close({}) processing ack #{} response for {}", this, ackIndex, ack);
                    }
                    checkStatus(client, buf);
                }
            } finally {
                if (ownsHandle) {
                    if (debugEnabled) {
                        log.debug("close({}) closing file handle", this);
                    }
                    handle.close();
                }
            }
        } finally {
            handle = null;
            buffer = null;
            bufferPool[0] = null;
            bufferPool[1] = null;
            lastMsg = null;
        }
    }

    @Override
    public String toString() {
        SftpClient client = getClient();
        return getClass().getSimpleName()
               + "[" + client.getSession() + "]"
               + "[" + getPath() + "]";
    }
}
