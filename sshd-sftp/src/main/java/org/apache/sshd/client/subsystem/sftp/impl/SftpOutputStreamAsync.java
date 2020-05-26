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
package org.apache.sshd.client.subsystem.sftp.impl;

import java.io.IOException;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;

import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.SftpClient.OpenMode;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.OutputStreamWithChannel;

/**
 * Implements an output stream for a given remote file
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpOutputStreamAsync extends OutputStreamWithChannel {
    protected final byte[] bb = new byte[1];
    protected final int bufferSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long offset;
    protected final Deque<SftpAckData> pendingWrites = new LinkedList<>();

    private final AbstractSftpClient client;
    private final String path;

    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, Collection<OpenMode> mode) throws IOException {
        this.client = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = client.open(path, mode);
        this.bufferSize = bufferSize;
    }

    public SftpOutputStreamAsync(AbstractSftpClient client, int bufferSize,
                                 String path, CloseableHandle handle) throws IOException {
        this.client = Objects.requireNonNull(client, "No SFTP client instance");
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
        return client;
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
        Session session = client.getSession();

        do {
            if (buffer == null) {
                buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA, bufferSize);
                int hdr = 9 + 16 + 8 + id.length + buffer.wpos();
                buffer.rpos(hdr);
                buffer.wpos(hdr);
            }
            int max = bufferSize - (9 + 16 + id.length + 72);
            int nb = Math.min(len, max - (buffer.wpos() - buffer.rpos()));
            buffer.putRawBytes(b, off, nb);
            if (buffer.available() == max) {
                flush();
            }
            off += nb;
            len -= nb;
        } while (len > 0);
    }

    @Override
    public void flush() throws IOException {
        if (!isOpen()) {
            throw new IOException("flush(" + getPath() + ") stream is closed");
        }

        for (;;) {
            SftpAckData ack = pendingWrites.peek();
            if (ack != null) {
                Buffer response = client.receive(ack.id, 0L);
                if (response != null) {
                    pendingWrites.removeFirst();
                    client.checkResponseStatus(SftpConstants.SSH_FXP_WRITE, response);
                } else {
                    break;
                }
            } else {
                break;
            }
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
        pendingWrites.add(new SftpAckData(reqId, offset, avail));

        offset += avail;
        buffer = null;
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            try {
                try {
                    if ((buffer != null) && (buffer.available() > 0)) {
                        flush();
                    }
                    while (!pendingWrites.isEmpty()) {
                        SftpAckData ack = pendingWrites.removeFirst();
                        Buffer response = client.receive(ack.id);
                        client.checkResponseStatus(SftpConstants.SSH_FXP_WRITE, response);
                    }
                } finally {
                    handle.close();
                }
            } finally {
                handle = null;
            }
        }
    }
}
