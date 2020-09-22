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
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.OutputStreamWithChannel;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.common.SftpConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements an output stream for a given remote file
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpOutputStreamAsync extends OutputStreamWithChannel {
    protected final Logger log;
    protected final byte[] bb = new byte[1];
    protected final int bufferSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long offset;
    protected final Deque<SftpAckData> pendingWrites = new LinkedList<>();

    private final AbstractSftpClient clientInstance;
    private final String path;

    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, Collection<OpenMode> mode) throws IOException {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = client.open(path, mode);
        this.bufferSize = bufferSize;
    }

    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, CloseableHandle handle) throws IOException {
        this.log = LoggerFactory.getLogger(getClass());
        this.clientInstance = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = handle;
        this.bufferSize = bufferSize;
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote file
     */
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
        byte[] id = handle.getIdentifier();
        SftpClient client = getClient();
        Session session = client.getSession();

        boolean traceEnabled = log.isTraceEnabled();
        int writtenCount = 0;
        int totalLen = len;
        do {
            if (buffer == null) {
                if (traceEnabled) {
                    log.trace("write({}) allocate buffer size={} after {}/{} bytes",
                            this, bufferSize, writtenCount, totalLen);
                }

                buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA, bufferSize);
                int hdr = 9 + 16 + 8 + id.length + buffer.wpos();
                buffer.rpos(hdr);
                buffer.wpos(hdr);
            }

            int max = bufferSize - (9 + 16 + id.length + 72);
            int nb = Math.min(len, Math.max(0, max - buffer.available()));
            buffer.putRawBytes(b, off, nb);

            off += nb;
            len -= nb;
            writtenCount += nb;

            if (buffer.available() >= max) {
                if (traceEnabled) {
                    log.trace("write({}) flush after {}/{} bytes", this, writtenCount, totalLen);
                }
                flush();
            }
        } while (len > 0);
    }

    @Override
    public void flush() throws IOException {
        if (!isOpen()) {
            throw new IOException("flush(" + getPath() + ") stream is closed");
        }

        boolean debugEnabled = log.isDebugEnabled();
        AbstractSftpClient client = getClient();
        for (int ackIndex = 0;;) {
            SftpAckData ack = pendingWrites.peek();
            if (ack == null) {
                if (debugEnabled) {
                    log.debug("flush({}) processed {} pending writes", this, ackIndex);
                }
                break;
            }

            ackIndex++;
            if (debugEnabled) {
                log.debug("flush({}) waiting for ack #{}: {}", this, ackIndex, ack);
            }

            Buffer response = client.receive(ack.id, 0L);
            if (response == null) {
                if (debugEnabled) {
                    log.debug("flush({}) no response for ack #{}: {}", this, ackIndex, ack);
                }
                break;
            }

            if (debugEnabled) {
                log.debug("flush({}) processing ack #{}: {}", this, ackIndex, ack);
            }

            ack = pendingWrites.removeFirst();
            client.checkResponseStatus(SftpConstants.SSH_FXP_WRITE, response);
        }

        if (buffer == null) {
            if (debugEnabled) {
                log.debug("flush({}) no pending buffer to flush", this);
            }
            return;
        }

        byte[] id = handle.getIdentifier();
        int avail = buffer.available();
        Buffer buf;
        if (buffer.rpos() >= (16 + id.length)) {
            int wpos = buffer.wpos();
            buffer.rpos(buffer.rpos() - 16 - id.length);
            buffer.wpos(buffer.rpos());
            buffer.putBytes(id);
            buffer.putLong(offset);
            buffer.putInt(avail);
            buffer.wpos(wpos);
            buf = buffer;
        } else {
            buf = new ByteArrayBuffer(id.length + avail + Long.SIZE /* some extra fields */, false);
            buf.putBytes(id);
            buf.putLong(offset);
            buf.putBytes(buffer.array(), buffer.rpos(), avail);
        }

        int reqId = client.send(SftpConstants.SSH_FXP_WRITE, buf);
        SftpAckData ack = new SftpAckData(reqId, offset, avail);
        if (debugEnabled) {
            log.debug("flush({}) enqueue pending ack={}", this, ack);
        }
        pendingWrites.add(ack);

        offset += avail;
        buffer = null;
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
                    flush();
                }

                AbstractSftpClient client = getClient();
                for (int ackIndex = 1; !pendingWrites.isEmpty(); ackIndex++) {
                    SftpAckData ack = pendingWrites.removeFirst();
                    if (debugEnabled) {
                        log.debug("close({}) processing ack #{}: {}", this, ackIndex, ack);
                    }

                    Buffer response = client.receive(ack.id);
                    if (debugEnabled) {
                        log.debug("close({}) processing ack #{} response for {}", this, ackIndex, ack);
                    }
                    client.checkResponseStatus(SftpConstants.SSH_FXP_WRITE, response);
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
