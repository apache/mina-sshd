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
package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.SftpClient.OpenMode;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.InputStreamWithChannel;

/**
 * Implements an input stream for reading from a remote file
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpInputStreamWithChannel extends InputStreamWithChannel {
    private final SftpClient client;
    private final String path;
    private byte[] bb;
    private byte[] buffer;
    private int index;
    private int available;
    private CloseableHandle handle;
    private long offset;

    public SftpInputStreamWithChannel(SftpClient client, int bufferSize, String path, Collection<OpenMode> mode) throws IOException {
        this.client = ValidateUtils.checkNotNull(client, "No SFTP client instance");
        this.path = path;
        bb = new byte[1];
        buffer = new byte[bufferSize];
        handle = client.open(path, mode);
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote file
     */
    public final SftpClient getClient() {
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

    @Override
    public boolean isOpen() {
        return (handle != null) && handle.isOpen();
    }

    @Override
    public int read() throws IOException {
        int read = read(bb, 0, 1);
        if (read > 0) {
            return bb[0];
        }

        return read;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (!isOpen()) {
            throw new IOException("read(" + getPath() + ") stream closed");
        }

        int idx = off;
        while (len > 0) {
            if (index >= available) {
                available = client.read(handle, offset, buffer, 0, buffer.length);
                if (available < 0) {
                    if (idx == off) {
                        return -1;
                    } else {
                        break;
                    }
                }
                offset += available;
                index = 0;
            }
            if (index >= available) {
                break;
            }
            int nb = Math.min(len, available - index);
            System.arraycopy(buffer, index, b, idx, nb);
            index += nb;
            idx += nb;
            len -= nb;
        }
        return idx - off;
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            try {
                handle.close();
            } finally {
                handle = null;
            }
        }
    }
}