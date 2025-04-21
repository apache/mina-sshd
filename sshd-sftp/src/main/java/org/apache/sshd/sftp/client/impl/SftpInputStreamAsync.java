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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.LocalWindow;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.input.InputStreamWithChannel;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.SftpClientHolder;
import org.apache.sshd.sftp.common.SftpConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SftpInputStreamAsync extends InputStreamWithChannel implements SftpClientHolder {

    private static final int MIN_BUFFER_SIZE = 8 * 1024;

    protected final Logger log;
    protected final byte[] bb = new byte[1];
    protected final long fileSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long requestOffset;
    protected long clientOffset;
    protected final Deque<SftpAckData> pendingReads = new LinkedList<>();
    protected boolean eofIndicator;
    protected int bufferSize;
    protected int maxReceived;
    protected long shortReads;
    protected boolean bufferAdjusted;

    private final AbstractSftpClient clientInstance;
    private final String path;
    private final boolean ownsHandle;

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize,
                                String path, Collection<OpenMode> mode)
            throws IOException {
        this(client, bufferSize, 0, client.stat(path).getSize(), path, client.open(path, mode));
    }

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize, long clientOffset, long fileSize,
                                String path, CloseableHandle handle) {
        this(client, bufferSize, clientOffset, fileSize, path, handle, true);
    }

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize, long clientOffset, long fileSize,
                                String path, CloseableHandle handle, boolean closeHandle) {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = handle;
        this.ownsHandle = closeHandle;
        this.bufferSize = bufferSize;
        this.requestOffset = clientOffset;
        this.clientOffset = clientOffset;
        this.fileSize = fileSize;
    }

    @Override
    public final AbstractSftpClient getClient() {
        return clientInstance;
    }

    /**
     * The remotely accessed file path
     *
     * @return Remote file path
     */
    public final String getPath() {
        return path;
    }

    /**
     * Check if the stream is at EOF
     *
     * @return <code>true</code> if all the data has been consumer
     */
    public boolean isEof() {
        return eofIndicator && hasNoData();
    }

    @Override
    public boolean isOpen() {
        return (handle != null) && handle.isOpen();
    }

    @Override
    public int read() throws IOException {
        int read = read(bb, 0, 1);
        if (read > 0) {
            return bb[0] & 0xFF;
        }
        return read;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (!isOpen()) {
            throw new IOException("read(" + getPath() + ") stream closed");
        }

        AtomicInteger offset = new AtomicInteger(off);
        int res = (int) doRead(len, buf -> {
            int l = buf.available();
            buf.getRawBytes(b, offset.getAndAdd(l), l);
        });
        if (res == 0 && eofIndicator && hasNoData()) {
            res = -1;
        }
        return res;
    }

    public long transferTo(long len, WritableByteChannel out) throws IOException {
        if (!isOpen()) {
            throw new IOException("transferTo(" + getPath() + ") stream closed");
        }

        long numXfered = doRead(len, buf -> {
            ByteBuffer bb = ByteBuffer.wrap(buf.array(), buf.rpos(), buf.available());
            while (bb.hasRemaining()) {
                out.write(bb);
            }
        });
        if (log.isDebugEnabled()) {
            log.debug("transferTo({}) transferred {}/{} bytes", this, numXfered, len);
        }
        return numXfered;
    }

    @SuppressWarnings("PMD.MissingOverride")
    public long transferTo(OutputStream out) throws IOException {
        if (!isOpen()) {
            throw new IOException("transferTo(" + getPath() + ") stream closed");
        }

        long numXfered = doRead(Long.MAX_VALUE, buf -> out.write(buf.array(), buf.rpos(), buf.available()));
        if (log.isDebugEnabled()) {
            log.debug("transferTo({}) transferred {} bytes", this, numXfered);
        }
        return numXfered;
    }

    interface BufferConsumer {
        void consume(Buffer buffer) throws IOException;
    }

    private long doRead(long max, BufferConsumer consumer) throws IOException {
        long orgOffset = clientOffset;
        while (max > 0) {
            if (hasNoData()) {
                if (eofIndicator) {
                    break;
                }
                boolean backtracked = false;
                if (!pendingReads.isEmpty()) {
                    backtracked = fillData();
                }
                if (!eofIndicator && !backtracked) {
                    // Do not send additional requests if we had missing data that we had to fetch synchronously, and we
                    // do have more outstanding requests to avoid jumping back and forth in the file all the time.
                    sendRequests();
                }
            } else {
                int nb = (int) Math.min(max, buffer.available());
                consumer.consume(new ByteArrayBuffer(buffer.array(), buffer.rpos(), nb));
                buffer.rpos(buffer.rpos() + nb);
                clientOffset += nb;
                max -= nb;
            }
        }
        return clientOffset - orgOffset;
    }

    @Override
    public long skip(long n) throws IOException {
        if (!isOpen()) {
            throw new IOException("skip(" + getPath() + ") stream closed");
        }

        if ((clientOffset == 0L) && pendingReads.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("skip({}) virtual skip of {} bytes", this, n);
            }
            requestOffset = n;
            clientOffset = n;
            return n;
        }

        return super.skip(n);
    }

    protected boolean hasNoData() {
        return (buffer == null) || (buffer.available() == 0);
    }

    protected void sendRequests() throws IOException {
        AbstractSftpClient client = getClient();
        Channel channel = client.getChannel();
        LocalWindow localWindow = channel.getLocalWindow();
        long windowSize = localWindow.getMaxSize();
        Session session = client.getSession();
        byte[] id = handle.getIdentifier();
        boolean debugEnabled = log.isTraceEnabled();
        if (fileSize > 0 && requestOffset > fileSize) {
            // We'd be issuing requests for reading beyond the expected EOF. Do that only one by one.
            if (!pendingReads.isEmpty()) {
                return;
            }
            // Beyond the expected file size we do single sequential requests; no ahead of time requests.
            // Hence the requestOffset is always just beyond the current buffer. If the initial position
            // is beyond the file size, buffer may still be null here.
            requestOffset = clientOffset + (buffer != null ? buffer.available() : 0);
        }
        while (pendingReads.size() < Math.max(1, windowSize / bufferSize)) {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA,
                    23 /* sftp packet */ + 16 + id.length);
            buf.rpos(23);
            buf.wpos(23);
            buf.putBytes(id);
            buf.putLong(requestOffset);
            buf.putUInt(bufferSize);
            int reqId = client.send(SftpConstants.SSH_FXP_READ, buf);
            SftpAckData ack = new SftpAckData(reqId, requestOffset, bufferSize);
            if (debugEnabled) {
                log.debug("sendRequests({}) enqueue pending ack: {}", this, ack);
            }
            pendingReads.add(ack);
            requestOffset += bufferSize;
            if (fileSize > 0 && requestOffset > fileSize) {
                break;
            }
        }
    }

    protected boolean fillData() throws IOException {
        SftpAckData ack = pendingReads.pollFirst();
        boolean traceEnabled = log.isTraceEnabled();
        boolean debugEnabled = log.isDebugEnabled();
        if (ack == null) {
            if (traceEnabled) {
                log.trace("fillData({}) no pending ack", this);
            }
            return false;
        }

        if (traceEnabled) {
            log.trace("fillData({}) process ack={}", this, ack);
        }
        boolean alreadyEof = eofIndicator;
        pollBuffer(ack);

        if (!alreadyEof && clientOffset < ack.offset) {
            shortReads++;
            // We are missing some data: request it synchronously to fill the gap.
            int nb = (int) (ack.offset - clientOffset);
            byte[] data = new byte[nb + buffer.available()];
            if (traceEnabled) {
                log.trace("fillData({}) reading {} bytes", this, nb);
            }

            AtomicReference<Boolean> eof = new AtomicReference<>();
            SftpClient client = getClient();
            int cur = 0;
            while (cur < nb) {
                int dlen = client.read(handle, clientOffset + cur, data, cur, nb - cur, eof);
                if (dlen > 0) {
                    cur += dlen;
                }
                Boolean eofSignal = eof.getAndSet(null);
                if ((dlen < 0) || ((eofSignal != null) && eofSignal.booleanValue())) {
                    eofIndicator = true;
                    break;
                }
            }

            if (debugEnabled) {
                log.debug("fillData({}) read {} of {} bytes - EOF={}", this, cur, nb, eofIndicator);
            }

            if (cur == 0) {
                // Got no data but an EOF. File got shorter? Prepare an empty buffer.
                buffer.rpos(buffer.wpos());
            } else if (cur < nb) {
                // Could not fill the gap, got an EOF. Use just the data we got now.
                buffer = new ByteArrayBuffer(data, 0, cur);
            } else {
                // cur == nb: Gap filled.
                buffer.getRawBytes(data, cur, buffer.available());
                buffer = new ByteArrayBuffer(data);
            }
            if (!eofIndicator && !bufferAdjusted) {
                int newBufferSize = adjustBufferIfNeeded(bufferSize, shortReads, maxReceived, ack.offset - clientOffset);
                if (newBufferSize > 0 && newBufferSize < bufferSize) {
                    int originalSize = bufferSize;
                    bufferSize = newBufferSize;
                    bufferAdjusted = true;
                    if (debugEnabled) {
                        log.debug("adjustBufferIfNeeded({}) changing SFTP buffer size: {} -> {}", this, originalSize,
                                bufferSize);
                    }
                } else if (newBufferSize > bufferSize) {
                    throw new IllegalStateException("New buffer size " + newBufferSize + " > existing size " + bufferSize);
                }
            }
            return !pendingReads.isEmpty();
        }
        return false;
    }

    /**
     * Dynamically adjust the SFTP buffer size, if it is too large. Although it is possible to reduce the buffer size to
     * a single byte, in practice some sane lower limit (like, 8kB) should be maintained.
     *
     * @param  currentBufferSize the current SFTP buffer size
     * @param  nOfShortReads     the number of short reads so far
     * @param  maxBufferReceived the maximum number of bytes the server returned in any previous read request
     * @param  gap               the size of the gap just filled
     * @return                   a new buffer size in the range [1..currentBufferSize].
     */
    protected int adjustBufferIfNeeded(int currentBufferSize, long nOfShortReads, int maxBufferReceived, long gap) {
        if (currentBufferSize > MIN_BUFFER_SIZE && nOfShortReads > 4) {
            return Math.max(MIN_BUFFER_SIZE, maxBufferReceived);
        }
        return currentBufferSize;
    }

    protected void pollBuffer(SftpAckData ack) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("pollBuffer({}) polling ack={}", this, ack);
        }

        AbstractSftpClient client = getClient();
        SftpResponse response = client.response(SftpConstants.SSH_FXP_READ, ack.id);
        if (log.isDebugEnabled()) {
            log.debug("pollBuffer({}) response={} for ack={} - len={}", this, response.getType(), ack, response.getLength());
        }
        AtomicReference<Boolean> eofSignalled = new AtomicReference<>();
        Buffer buf = client.checkDataResponse(ack, response, eofSignalled);
        if (buf == null) {
            eofIndicator = true;
        } else {
            maxReceived = Math.max(buf.available(), maxReceived);
            Boolean eof = eofSignalled.get();
            if (eof != null && eof.booleanValue()) {
                eofIndicator = true;
            }
            this.buffer = buf;
        }
    }

    @Override
    public void close() throws IOException {
        if (!isOpen()) {
            return;
        }

        try {
            boolean debugEnabled = log.isDebugEnabled();
            try {
                for (int ackIndex = 1; !pendingReads.isEmpty(); ackIndex++) {
                    SftpAckData ack = pendingReads.removeFirst();
                    if (debugEnabled) {
                        log.debug("close({}) process ack #{}: {}", this, ackIndex, ack);
                    }
                    pollBuffer(ack);
                }
            } finally {
                if (ownsHandle) {
                    if (debugEnabled) {
                        log.debug("close({}) closing file handle; {} short reads", this, shortReads);
                    }
                    handle.close();
                }
            }
        } finally {
            handle = null;
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
