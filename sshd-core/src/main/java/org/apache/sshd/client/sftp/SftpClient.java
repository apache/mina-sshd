/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.sftp;

import static org.apache.sshd.common.sftp.SftpConstants.S_IFDIR;
import static org.apache.sshd.common.sftp.SftpConstants.S_IFLNK;
import static org.apache.sshd.common.sftp.SftpConstants.S_IFMT;
import static org.apache.sshd.common.sftp.SftpConstants.S_IFREG;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channel;
import java.nio.file.attribute.FileTime;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface SftpClient extends Closeable {

    enum OpenMode {
        Read,
        Write,
        Append,
        Create,
        Truncate,
        Exclusive
    }

    enum CopyMode {
        Atomic,
        Overwrite
    }

    enum Attribute {
        Size,
        UidGid,
        Perms,
        AcModTime,
        OwnerGroup,
        AccessTime,
        ModifyTime,
        CreateTime,
    }

    public static class Handle {
        public final String id;
        public Handle(String id) {
            this.id = ValidateUtils.checkNotNullAndNotEmpty(id, "No handle ID", GenericUtils.EMPTY_OBJECT_ARRAY);
        }
        
        @Override
        public String toString() {
            return id;
        }
    }

    public static abstract class CloseableHandle extends Handle implements Channel, Closeable {
        protected CloseableHandle(String id) {
            super(id);
        }
    }

    public static class Attributes {
        public final Set<Attribute> flags = EnumSet.noneOf(Attribute.class);
        public long size;
        public byte type;
        public int uid;
        public int gid;
        public int perms;
        public int atime;
        public int ctime;
        public int mtime;
        public String owner;
        public String group;
        public FileTime accessTime;
        public FileTime createTime;
        public FileTime modifyTime;

        @Override
        public String toString() {
            return "type=" + type
                 + ";size=" + size
                 + ";uid=" + uid
                 + ";gid=" + gid
                 + ";perms=0x" + Integer.toHexString(perms)
                 + ";flags=" + flags
                 + ";owner=" + owner
                 + ";group=" + group
                 + ";aTime=(" + atime + ")[" + accessTime + "]"
                 + ";cTime=(" + ctime + ")[" + createTime + "]"
                 + ";mTime=(" + mtime + ")[" + modifyTime + "]"
                 ;
        }

        public Attributes size(long size) {
            flags.add(Attribute.Size);
            this.size = size;
            return this;
        }
        public Attributes owner(String owner) {
            flags.add(Attribute.OwnerGroup);
            this.owner = owner;
            if (GenericUtils.isEmpty(group)) {
                group = "GROUP@";
            }
            return this;
        }
        public Attributes group(String group) {
            flags.add(Attribute.OwnerGroup);
            this.group = group;
            if (GenericUtils.isEmpty(owner)) {
                owner = "OWNER@";
            }
            return this;
        }
        public Attributes owner(int uid, int gid) {
            flags.add(Attribute.UidGid);
            this.uid = uid;
            this.gid = gid;
            return this;
        }
        public Attributes perms(int perms) {
            flags.add(Attribute.Perms);
            this.perms = perms;
            return this;
        }
        public Attributes atime(int atime) {
            flags.add(Attribute.AccessTime);
            this.atime = atime;
            this.accessTime = FileTime.from(atime, TimeUnit.SECONDS);
            return this;
        }
        public Attributes ctime(int ctime) {
            flags.add(Attribute.CreateTime);
            this.ctime = ctime;
            this.createTime = FileTime.from(atime, TimeUnit.SECONDS);
            return this;
        }
        public Attributes mtime(int mtime) {
            flags.add(Attribute.ModifyTime);
            this.mtime = mtime;
            this.modifyTime = FileTime.from(atime, TimeUnit.SECONDS);
            return this;
        }
        public Attributes time(int atime, int mtime) {
            flags.add(Attribute.AcModTime);
            this.atime = atime;
            this.mtime = mtime;
            return this;
        }
        public Attributes accessTime(FileTime atime) {
            flags.add(Attribute.AccessTime);
            this.atime = (int) atime.to(TimeUnit.SECONDS);
            this.accessTime = atime;
            return this;
        }
        public Attributes createTime(FileTime ctime) {
            flags.add(Attribute.CreateTime);
            this.ctime = (int) ctime.to(TimeUnit.SECONDS);
            this.createTime = ctime;
            return this;
        }
        public Attributes modifyTime(FileTime mtime) {
            flags.add(Attribute.ModifyTime);
            this.mtime = (int) mtime.to(TimeUnit.SECONDS);
            this.modifyTime = mtime;
            return this;
        }
        public boolean isRegularFile() {
            return (perms & S_IFMT) == S_IFREG;
        }
        public boolean isDirectory() {
            return (perms & S_IFMT) == S_IFDIR;
        }
        public boolean isSymbolicLink() {
            return (perms & S_IFMT) == S_IFLNK;
        }
        public boolean isOther() {
            return !isRegularFile() && !isDirectory() && !isSymbolicLink();
        }
    }

    public static class DirEntry {
        public String filename;
        public String longFilename;
        public Attributes attributes;
        public DirEntry(String filename, String longFilename, Attributes attributes) {
            this.filename = filename;
            this.longFilename = longFilename;
            this.attributes = attributes;
        }
    }

    int getVersion();

    boolean isClosing();

    //
    // Low level API
    //

    CloseableHandle open(String path) throws IOException;
    CloseableHandle open(String path, OpenMode ... options) throws IOException;
    CloseableHandle open(String path, Collection<OpenMode> options) throws IOException;

    void close(Handle handle) throws IOException;

    void remove(String path) throws IOException;

    void rename(String oldPath, String newPath) throws IOException;
    void rename(String oldPath, String newPath, CopyMode... options) throws IOException;
    void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException;

    int read(Handle handle, long fileOffset, byte[] dst) throws IOException;
    int read(Handle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException;

    void write(Handle handle, long fileOffset, byte[] src) throws IOException;
    void write(Handle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException;

    void mkdir(String path) throws IOException;

    void rmdir(String path) throws IOException;

    CloseableHandle openDir(String path) throws IOException;

    DirEntry[] readDir(Handle handle) throws IOException;

    String canonicalPath(String canonical) throws IOException;

    Attributes stat(String path) throws IOException;

    Attributes lstat(String path) throws IOException;

    Attributes stat(Handle handle) throws IOException;

    void setStat(String path, Attributes attributes) throws IOException;

    void setStat(Handle handle, Attributes attributes) throws IOException;

    String readLink(String path) throws IOException;

    void symLink(String linkPath, String targetPath) throws IOException;

    void link(String linkPath, String targetPath, boolean symbolic) throws IOException;

    void lock(Handle handle, long offset, long length, int mask) throws IOException;

    void unlock(Handle handle, long offset, long length) throws IOException;

    //
    // High level API
    //

    Iterable<DirEntry> readDir(String path) throws IOException;

    // default values used if none specified
    int MIN_BUFFER_SIZE=Byte.MAX_VALUE, MIN_READ_BUFFER_SIZE=MIN_BUFFER_SIZE, MIN_WRITE_BUFFER_SIZE=MIN_BUFFER_SIZE;
    int IO_BUFFER_SIZE=32 * 1024, DEFAULT_READ_BUFFER_SIZE=IO_BUFFER_SIZE, DEFAULT_WRITE_BUFFER_SIZE=IO_BUFFER_SIZE;
    long DEFAULT_WAIT_TIMEOUT=TimeUnit.SECONDS.toMillis(30L);

    /**
     * Property that can be used on the {@link org.apache.sshd.common.FactoryManager}
     * to control the internal timeout used by the client to open a channel.
     * If not specified then {@link #DEFAULT_CHANNEL_OPEN_TIMEOUT} value
     * is used
     */
    String SFTP_CHANNEL_OPEN_TIMEOUT = "sftp-channel-open-timeout";
        long DEFAULT_CHANNEL_OPEN_TIMEOUT = DEFAULT_WAIT_TIMEOUT;

    InputStream read(String path) throws IOException;
    InputStream read(String path, int bufferSize) throws IOException;
    InputStream read(String path, OpenMode ... mode) throws IOException;
    InputStream read(String path, int bufferSize, OpenMode ... mode) throws IOException;
    InputStream read(String path, Collection<OpenMode> mode) throws IOException;
    InputStream read(String path, int bufferSize, Collection<OpenMode> mode) throws IOException;

    OutputStream write(String path) throws IOException;
    OutputStream write(String path, int bufferSize) throws IOException;
    OutputStream write(String path, OpenMode ... mode) throws IOException;
    OutputStream write(String path, int bufferSize, OpenMode ... mode) throws IOException;
    OutputStream write(String path, Collection<OpenMode> mode) throws IOException;
    OutputStream write(String path, int bufferSize, Collection<OpenMode> mode) throws IOException;

}
