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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.SftpClient.OpenMode;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpHelper;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.InputStreamWithChannel;

public class SftpInputStreamAsync extends InputStreamWithChannel {
    protected final byte[] bb = new byte[1];
    protected final int bufferSize;
    protected final long fileSize;
    protected Buffer buffer;
    protected CloseableHandle handle;
    protected long requestOffset;
    protected long clientOffset;
    protected final Deque<SftpAckData> pendingReads = new LinkedList<>();
    protected boolean eofIndicator;

    private final AbstractSftpClient client;
    private final String path;

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize,
                                String path, Collection<OpenMode> mode) throws IOException {
        this.client = Objects.requireNonNull(client, "No SFTP client instance");
        this.path = path;
        this.handle = client.open(path, mode);
        this.bufferSize = bufferSize;
        this.fileSize = client.stat(handle).getSize();
    }

    public SftpInputStreamAsync(AbstractSftpClient client, int bufferSize, long clientOffset, long fileSize,
                                String path, CloseableHandle handle) {
        this.client = Objects.requireNonNull(client, "No SFTP client instance");
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
        return client;
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
        while (len > 0 && !eofIndicator) {
            if (hasNoData()) {
                fillData();
                if (eofIndicator && (hasNoData())) {
                    break;
                }
                sendRequests();
            } else {
                int nb = Math.min(buffer.available(), len);
                buffer.getRawBytes(b, off, nb);
                idx += nb;
                len -= nb;
                clientOffset += nb;
            }
        }
        int res = idx - off;
        if (res == 0 && eofIndicator) {
            res = -1;
        }
        return res;
    }

    public long transferTo(long max, WritableByteChannel out) throws IOException {
        if (!isOpen()) {
            throw new IOException("transferTo(" + getPath() + ") stream closed");
        }

        long orgOffset = clientOffset;
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
        return clientOffset - orgOffset;
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
        return clientOffset - orgOffset;
    }

    @Override
    public long skip(long n) throws IOException {
        if (!isOpen()) {
            throw new IOException("skip(" + getPath() + ") stream closed");
        }
        if ((clientOffset == 0L) && pendingReads.isEmpty()) {
            clientOffset = n;
            return n;
        }
        return super.skip(n);
    }

    protected boolean hasNoData() {
        return (buffer == null) || (buffer.available() == 0);
    }

    protected void sendRequests() throws IOException {
        if (!eofIndicator) {
            Channel channel = client.getChannel();
            Window localWindow = channel.getLocalWindow();
            long windowSize = localWindow.getMaxSize();
            Session session = client.getSession();
            byte[] id = handle.getIdentifier();

            while ((pendingReads.size() < (int) (windowSize / bufferSize)) && (requestOffset < (fileSize + bufferSize))
                    || pendingReads.isEmpty()) {
                Buffer buf = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_DATA,
                        23 /* sftp packet */ + 16 + id.length);
                buf.rpos(23);
                buf.wpos(23);
                buf.putBytes(id);
                buf.putLong(requestOffset);
                buf.putInt(bufferSize);
                int reqId = client.send(SftpConstants.SSH_FXP_READ, buf);
                pendingReads.add(new SftpAckData(reqId, requestOffset, bufferSize));
                requestOffset += bufferSize;
            }
        }
    }

    protected void fillData() throws IOException {
        SftpAckData ack = pendingReads.pollFirst();
        if (ack != null) {
            pollBuffer(ack);
            if ((!eofIndicator) && (clientOffset < ack.offset)) {
                // we are actually missing some data
                // so request is synchronously
                byte[] data = new byte[(int) (ack.offset - clientOffset + buffer.available())];
                int cur = 0;
                int nb = (int) (ack.offset - clientOffset);
                AtomicReference<Boolean> eof = new AtomicReference<>();
                while (cur < nb) {
                    int dlen = client.read(handle, clientOffset, data, cur, nb - cur, eof);
                    Boolean eofSignal = eof.getAndSet(null);
                    eofIndicator = (dlen < 0) || ((eofSignal != null) && eofSignal.booleanValue());
                    cur += dlen;
                }
                buffer.getRawBytes(data, nb, buffer.available());
                buffer = new ByteArrayBuffer(data);
            }
        }
    }

    protected void pollBuffer(SftpAckData ack) throws IOException {
        Buffer buf = client.receive(ack.id);
        int length = buf.getInt();
        int type = buf.getUByte();
        int id = buf.getInt();
        client.validateIncomingResponse(SshConstants.SSH_MSG_CHANNEL_DATA, id, type, length, buf);
        if (type == SftpConstants.SSH_FXP_DATA) {
            int dlen = buf.getInt();
            int rpos = buf.rpos();
            buf.rpos(rpos + dlen);
            Boolean b = SftpHelper.getEndOfFileIndicatorValue(buf, client.getVersion());
            eofIndicator = (b != null) && b.booleanValue();
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
        if (isOpen()) {
            try {
                try {
                    while (!pendingReads.isEmpty()) {
                        SftpAckData ack = pendingReads.removeFirst();
                        pollBuffer(ack);
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
