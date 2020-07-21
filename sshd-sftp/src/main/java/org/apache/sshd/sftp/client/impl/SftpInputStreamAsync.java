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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.InputStreamWithChannel;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SftpInputStreamAsync extends InputStreamWithChannel {
    protected final Logger log;
    protected final byte[] bb = new byte[1];
    protected final int bufferSize;
    protected final long fileSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long requestOffset;
    protected long clientOffset;
    protected final Deque<SftpAckData> pendingReads = new LinkedList<>();
    protected boolean eofIndicator;

    private final AbstractSftpClient clientInstance;
    private final String path;

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize,
                                String path, Collection<OpenMode> mode) throws IOException {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = client.open(path, mode);
        this.bufferSize = bufferSize;
        this.fileSize = client.stat(handle).getSize();
    }

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize, long clientOffset, long fileSize,
                                String path, CloseableHandle handle) {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = handle;
        this.bufferSize = bufferSize;
        this.clientOffset = clientOffset;
        this.fileSize = fileSize;
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote file
     */
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

        int idx = off;
        while ((len > 0) && (!eofIndicator)) {
            if (hasNoData()) {
                fillData();
                if (eofIndicator && (hasNoData())) {
                    break;
                }
                sendRequests();
            } else {
                int nb = Math.min(buffer.available(), len);
                buffer.getRawBytes(b, off, nb);
                off += nb;
                len -= nb;
                clientOffset += nb;
            }
        }

        int res = off - idx;
        if ((res == 0) && eofIndicator) {
            res = -1;
        }
        return res;
    }

    public long transferTo(long max, WritableByteChannel out) throws IOException {
        if (!isOpen()) {
            throw new IOException("transferTo(" + getPath() + ") stream closed");
        }

        long orgOffset = clientOffset;
        long totalRequested = max;
        while ((!eofIndicator) && (max > 0L)) {
            if (hasNoData()) {
                fillData();
                if (eofIndicator && hasNoData()) {
                    break;
                }
                sendRequests();
            } else {
                int nb = buffer.available();
                int toRead = (int) Math.min(nb, max);
                ByteBuffer bb = ByteBuffer.wrap(buffer.array(), buffer.rpos(), toRead);
                while (bb.hasRemaining()) {
                    out.write(bb);
                }
                buffer.rpos(buffer.rpos() + toRead);
                clientOffset += toRead;
                max -= toRead;
            }
        }

        long numXfered = clientOffset - orgOffset;
        if (log.isDebugEnabled()) {
            log.debug("transferTo({}) transferred {}/{} bytes", numXfered, totalRequested);
        }
        return numXfered;
    }

    @SuppressWarnings("PMD.MissingOverride")
    public long transferTo(OutputStream out) throws IOException {
        if (!isOpen()) {
            throw new IOException("transferTo(" + getPath() + ") stream closed");
        }

        long orgOffset = clientOffset;
        while (!eofIndicator) {
            if (hasNoData()) {
                fillData();
                if (eofIndicator && hasNoData()) {
                    break;
                }
                sendRequests();
            } else {
                int nb = buffer.available();
                out.write(buffer.array(), buffer.rpos(), nb);
                buffer.rpos(buffer.rpos() + nb);
                clientOffset += nb;
            }
        }

        long numXfered = clientOffset - orgOffset;
        if (log.isDebugEnabled()) {
            log.debug("transferTo({}) transferred {} bytes", this, numXfered);
        }
        return numXfered;
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
            clientOffset = n;
            return n;
        }

        return super.skip(n);
    }

    protected boolean hasNoData() {
        return (buffer == null) || (buffer.available() == 0);
    }

    protected void sendRequests() throws IOException {
        if (eofIndicator) {
            if (log.isDebugEnabled()) {
                log.debug("sendRequests({}) EOF indicator ON", this);
            }
            return;
        }

        AbstractSftpClient client = getClient();
        Channel channel = client.getChannel();
        Window localWindow = channel.getLocalWindow();
        long windowSize = localWindow.getMaxSize();
        Session session = client.getSession();
        byte[] id = handle.getIdentifier();
        boolean traceEnabled = log.isTraceEnabled();
        for (int ackIndex = 1;
             (pendingReads.size() < (int) (windowSize / bufferSize)) && (requestOffset < (fileSize + bufferSize))
                     || pendingReads.isEmpty();
             ackIndex++) {
            Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA,
                    23 /* sftp packet */ + 16 + id.length);
            buf.rpos(23);
            buf.wpos(23);
            buf.putBytes(id);
            buf.putLong(requestOffset);
            buf.putInt(bufferSize);
            int reqId = client.send(SftpConstants.SSH_FXP_READ, buf);
            SftpAckData ack = new SftpAckData(reqId, requestOffset, bufferSize);
            if (traceEnabled) {
                log.trace("sendRequests({}) enqueue pending ack #{}: {}", this, ackIndex, ack);
            }
            pendingReads.add(ack);
            requestOffset += bufferSize;
        }
    }

    protected void fillData() throws IOException {
        SftpAckData ack = pendingReads.pollFirst();
        boolean traceEnabled = log.isTraceEnabled();
        if (ack == null) {
            if (traceEnabled) {
                log.trace("fillData({}) no pending ack", this);
            }
            return;
        }

        if (traceEnabled) {
            log.trace("fillData({}) process ack={}", this, ack);
        }
        pollBuffer(ack);

        if ((!eofIndicator) && (clientOffset < ack.offset)) {
            // we are actually missing some data
            // so request is synchronously
            byte[] data = new byte[(int) (ack.offset - clientOffset + buffer.available())];
            int nb = (int) (ack.offset - clientOffset);
            if (traceEnabled) {
                log.trace("fillData({}) reading {} bytes", this, nb);
            }

            AtomicReference<Boolean> eof = new AtomicReference<>();
            SftpClient client = getClient();
            for (int cur = 0; cur < nb;) {
                int dlen = client.read(handle, clientOffset, data, cur, nb - cur, eof);
                Boolean eofSignal = eof.getAndSet(null);
                if ((dlen < 0) || ((eofSignal != null) && eofSignal.booleanValue())) {
                    eofIndicator = true;
                }
                cur += dlen;
            }

            if (traceEnabled) {
                log.trace("fillData({}) read {} bytes - EOF={}", this, nb, eofIndicator);
            }

            buffer.getRawBytes(data, nb, buffer.available());
            buffer = new ByteArrayBuffer(data);
        }
    }

    protected void pollBuffer(SftpAckData ack) throws IOException {
        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("pollBuffer({}) polling ack={}", this, ack);
        }

        AbstractSftpClient client = getClient();
        Buffer buf = client.receive(ack.id);
        int length = buf.getInt();
        int type = buf.getUByte();
        int id = buf.getInt();
        if (traceEnabled) {
            log.trace("pollBuffer({}) response={} for ack={} - len={}", this, type, ack, length);
        }
        client.validateIncomingResponse(SshConstants.SSH_MSG_CHANNEL_DATA, id, type, length, buf);

        if (type == SftpConstants.SSH_FXP_DATA) {
            int dlen = buf.getInt();
            int rpos = buf.rpos();
            buf.rpos(rpos + dlen);
            Boolean b = SftpHelper.getEndOfFileIndicatorValue(buf, client.getVersion());
            if ((b != null) && b.booleanValue()) {
                eofIndicator = true;
            }
            buf.rpos(rpos);
            buf.wpos(rpos + dlen);
            this.buffer = buf;
        } else if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buf.getInt();
            String msg = buf.getString();
            String lang = buf.getString();
            if (substatus == SftpConstants.SSH_FX_EOF) {
                eofIndicator = true;
            } else {
                client.checkResponseStatus(SshConstants.SSH_MSG_CHANNEL_DATA, id, substatus, msg, lang);
            }
        } else {
            IOException err = client.handleUnexpectedPacket(SshConstants.SSH_MSG_CHANNEL_DATA,
                    SftpConstants.SSH_FXP_STATUS, id, type, length, buf);
            if (err != null) {
                throw err;
            }
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
                if (debugEnabled) {
                    log.debug("close({}) closing file handle", this);
                }
                handle.close();
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
