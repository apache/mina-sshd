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
package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileLock;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileHandle extends Handle {
    private final int access;
    private final SeekableByteChannel fileChannel;
    private final List<FileLock> locks = new ArrayList<>();
    private final Set<StandardOpenOption> openOptions;
    private final Collection<FileAttribute<?>> fileAttributes;

    public FileHandle(
                      SftpSubsystem subsystem, Path file, String handle, int flags, int access, Map<String, Object> attrs)
                                                                                                                           throws IOException {
        super(subsystem, file, handle);

        this.access = access;
        this.openOptions = Collections.unmodifiableSet(getOpenOptions(flags, access));
        this.fileAttributes = Collections.unmodifiableCollection(toFileAttributes(attrs));
        signalHandleOpening();

        FileAttribute<?>[] fileAttrs = GenericUtils.isEmpty(fileAttributes)
                ? IoUtils.EMPTY_FILE_ATTRIBUTES
                : fileAttributes.toArray(new FileAttribute<?>[fileAttributes.size()]);

        SftpFileSystemAccessor accessor = subsystem.getFileSystemAccessor();
        ServerSession session = subsystem.getServerSession();
        SeekableByteChannel channel;
        try {
            channel = accessor.openFile(
                    session, subsystem, this, file, handle, openOptions, fileAttrs);
        } catch (UnsupportedOperationException e) {
            channel = accessor.openFile(
                    session, subsystem, this, file, handle, openOptions, IoUtils.EMPTY_FILE_ATTRIBUTES);
            subsystem.doSetAttributes(file, attrs, false);
        }
        this.fileChannel = channel;

        try {
            signalHandleOpen();
        } catch (IOException e) {
            close();
            throw e;
        }
    }

    public final Set<StandardOpenOption> getOpenOptions() {
        return openOptions;
    }

    public final Collection<FileAttribute<?>> getFileAttributes() {
        return fileAttributes;
    }

    public SeekableByteChannel getFileChannel() {
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

    @SuppressWarnings("resource")
    public int read(byte[] data, int doff, int length, long offset) throws IOException {
        SeekableByteChannel channel = getFileChannel();
        channel = channel.position(offset);
        return channel.read(ByteBuffer.wrap(data, doff, length));
    }

    public void append(byte[] data) throws IOException {
        append(data, 0, data.length);
    }

    public void append(byte[] data, int doff, int length) throws IOException {
        SeekableByteChannel channel = getFileChannel();
        write(data, doff, length, channel.size());
    }

    public void write(byte[] data, long offset) throws IOException {
        write(data, 0, data.length, offset);
    }

    public void write(byte[] data, int doff, int length, long offset) throws IOException {
        SeekableByteChannel channel = getFileChannel();
        channel = channel.position(offset);
        channel.write(ByteBuffer.wrap(data, doff, length));
    }

    @Override
    public void close() throws IOException {
        super.close();

        SftpSubsystem subsystem = getSubsystem();
        SftpFileSystemAccessor accessor = subsystem.getFileSystemAccessor();
        ServerSession session = subsystem.getServerSession();
        accessor.closeFile(session, subsystem, this, getFile(), getFileHandle(), getFileChannel(), getOpenOptions());
    }

    public void lock(long offset, long length, int mask) throws IOException {
        SeekableByteChannel channel = getFileChannel();
        long size = (length == 0L) ? channel.size() - offset : length;
        SftpSubsystem subsystem = getSubsystem();
        SftpFileSystemAccessor accessor = subsystem.getFileSystemAccessor();
        ServerSession session = subsystem.getServerSession();
        FileLock lock = accessor.tryLock(
                session, subsystem, this, getFile(), getFileHandle(), channel, offset, size, false);
        if (lock == null) {
            throw new SftpException(
                    SftpConstants.SSH_FX_BYTE_RANGE_LOCK_REFUSED,
                    "Overlapping lock held by another program on range [" + offset + "-" + (offset + length));
        }

        synchronized (locks) {
            locks.add(lock);
        }
    }

    public void unlock(long offset, long length) throws IOException {
        SeekableByteChannel channel = getFileChannel();
        long size = (length == 0L) ? channel.size() - offset : length;
        FileLock lock = null;
        for (Iterator<FileLock> iterator = locks.iterator(); iterator.hasNext();) {
            FileLock l = iterator.next();
            if ((l.position() == offset) && (l.size() == size)) {
                iterator.remove();
                lock = l;
                break;
            }
        }
        if (lock == null) {
            throw new SftpException(
                    SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK,
                    "No matching lock found on range [" + offset + "-" + (offset + length));
        }

        lock.release();
    }

    public static Collection<FileAttribute<?>> toFileAttributes(Map<String, ?> attrs) {
        if (GenericUtils.isEmpty(attrs)) {
            return Collections.emptyList();
        }

        Collection<FileAttribute<?>> attributes = null;
        // Cannot use forEach because the referenced attributes variable is not effectively final
        for (Map.Entry<String, ?> attr : attrs.entrySet()) {
            FileAttribute<?> fileAttr = toFileAttribute(attr.getKey(), attr.getValue());
            if (fileAttr == null) {
                continue;
            }
            if (attributes == null) {
                attributes = new LinkedList<>();
            }
            attributes.add(fileAttr);
        }

        return (attributes == null) ? Collections.emptyList() : attributes;
    }

    public static FileAttribute<?> toFileAttribute(String key, Object val) {
        // Some ignored attributes sent by the SFTP client
        if ("isOther".equals(key)) {
            if ((Boolean) val) {
                throw new IllegalArgumentException("Not allowed to use " + key + "=" + val);
            }
            return null;
        } else if ("isRegular".equals(key)) {
            if (!(Boolean) val) {
                throw new IllegalArgumentException("Not allowed to use " + key + "=" + val);
            }
            return null;
        }

        return new FileAttribute<Object>() {
            private final String s = key + "=" + val;

            @Override
            public String name() {
                return key;
            }

            @Override
            public Object value() {
                return val;
            }

            @Override
            public String toString() {
                return s;
            }
        };
    }

    public static Set<StandardOpenOption> getOpenOptions(int flags, int access) {
        Set<StandardOpenOption> options = EnumSet.noneOf(StandardOpenOption.class);
        if (((access & SftpConstants.ACE4_READ_DATA) != 0) || ((access & SftpConstants.ACE4_READ_ATTRIBUTES) != 0)) {
            options.add(StandardOpenOption.READ);
        }
        if (((access & SftpConstants.ACE4_WRITE_DATA) != 0) || ((access & SftpConstants.ACE4_WRITE_ATTRIBUTES) != 0)) {
            options.add(StandardOpenOption.WRITE);
        }

        int accessDisposition = flags & SftpConstants.SSH_FXF_ACCESS_DISPOSITION;
        switch (accessDisposition) {
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
            default: // ignored
        }
        if ((flags & SftpConstants.SSH_FXF_APPEND_DATA) != 0) {
            options.add(StandardOpenOption.APPEND);
        }

        return options;
    }
}
