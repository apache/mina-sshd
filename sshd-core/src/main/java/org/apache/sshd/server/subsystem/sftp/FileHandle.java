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
package org.apache.sshd.server.subsystem.sftp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.subsystem.sftp.SftpConstants;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileHandle extends Handle {

    private final int access;
    private final FileChannel fileChannel;
    private long pos;
    private final List<FileLock> locks = new ArrayList<>();

    public FileHandle(SftpSubsystem sftpSubsystem, Path file, int flags, int access, Map<String, Object> attrs) throws IOException {
        super(file);
        this.access = access;

        Set<OpenOption> options = new HashSet<>();
        if (((access & SftpConstants.ACE4_READ_DATA) != 0) || ((access & SftpConstants.ACE4_READ_ATTRIBUTES) != 0)) {
            options.add(StandardOpenOption.READ);
        }
        if (((access & SftpConstants.ACE4_WRITE_DATA) != 0) || ((access & SftpConstants.ACE4_WRITE_ATTRIBUTES) != 0)) {
            options.add(StandardOpenOption.WRITE);
        }
        switch (flags & SftpConstants.SSH_FXF_ACCESS_DISPOSITION) {
            case SftpConstants.SSH_FXF_CREATE_NEW:
                options.add(StandardOpenOption.CREATE_NEW);
                break;
            case SftpConstants.SSH_FXF_CREATE_TRUNCATE:
                options.add(StandardOpenOption.CREATE);
                options.add(StandardOpenOption.TRUNCATE_EXISTING);
                break;
            case SftpConstants.SSH_FXF_OPEN_EXISTING:
                break;
            case SftpConstants.SSH_FXF_OPEN_OR_CREATE:
                options.add(StandardOpenOption.CREATE);
                break;
            case SftpConstants.SSH_FXF_TRUNCATE_EXISTING:
                options.add(StandardOpenOption.TRUNCATE_EXISTING);
                break;
            default:    // ignored
        }
        if ((flags & SftpConstants.SSH_FXF_APPEND_DATA) != 0) {
            options.add(StandardOpenOption.APPEND);
        }
        FileAttribute<?>[] attributes = new FileAttribute<?>[attrs.size()];
        int index = 0;
        for (Map.Entry<String, Object> attr : attrs.entrySet()) {
            final String key = attr.getKey();
            final Object val = attr.getValue();
            attributes[index++] = new FileAttribute<Object>() {
                @Override
                public String name() {
                    return key;
                }

                @Override
                public Object value() {
                    return val;
                }
            };
        }
        FileChannel channel;
        try {
            channel = FileChannel.open(file, options, attributes);
        } catch (UnsupportedOperationException e) {
            channel = FileChannel.open(file, options);
            sftpSubsystem.doSetAttributes(file, attrs);
        }
        this.fileChannel = channel;
        this.pos = 0;
    }

    public final FileChannel getFileChannel() {
        return fileChannel;
    }

    public int getAccessMask() {
        return access;
    }

    public boolean isOpenAppend() {
        return SftpConstants.ACE4_APPEND_DATA == (getAccessMask() & SftpConstants.ACE4_APPEND_DATA);
    }

    public int read(byte[] data, long offset) throws IOException {
        return read(data, 0, data.length, offset);
    }

    public int read(byte[] data, int doff, int length, long offset) throws IOException {
        FileChannel channel = getFileChannel();
        if (pos != offset) {
            channel.position(offset);
            pos = offset;
        }
        int read = channel.read(ByteBuffer.wrap(data, doff, length));
        pos += read;
        return read;
    }

    public void append(byte[] data) throws IOException {
        append(data, 0, data.length);
    }

    public void append(byte[] data, int doff, int length) throws IOException {
        FileChannel channel = getFileChannel();
        write(data, doff, length, channel.size());
    }

    public void write(byte[] data, long offset) throws IOException {
        write(data, 0, data.length, offset);
    }

    public void write(byte[] data, int doff, int length, long offset) throws IOException {
        FileChannel channel = getFileChannel();
        if (pos != offset) {
            channel.position(offset);
            pos = offset;
        }

        channel.write(ByteBuffer.wrap(data, doff, length));
        pos += length;
    }

    @Override
    public void close() throws IOException {
        super.close();

        FileChannel channel = getFileChannel();
        if (channel.isOpen()) {
            channel.close();
        }
    }

    public void lock(long offset, long length, int mask) throws IOException {
        FileChannel channel = getFileChannel();
        long size = (length == 0L) ? channel.size() - offset : length;
        FileLock lock = channel.tryLock(offset, size, false);
        synchronized (locks) {
            locks.add(lock);
        }
    }

    public boolean unlock(long offset, long length) throws IOException {
        FileChannel channel = getFileChannel();
        long size = (length == 0) ? channel.size() - offset : length;
        FileLock lock = null;
        for (Iterator<FileLock> iterator = locks.iterator(); iterator.hasNext();) {
            FileLock l = iterator.next();
            if (l.position() == offset && l.size() == size) {
                iterator.remove();
                lock = l;
                break;
            }
        }
        if (lock != null) {
            lock.release();
            return true;
        }
        return false;
    }
}
