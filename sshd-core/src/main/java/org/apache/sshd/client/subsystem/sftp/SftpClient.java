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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channel;
import java.nio.file.attribute.FileTime;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.subsystem.SubsystemClient;
import org.apache.sshd.client.subsystem.sftp.extensions.SftpClientExtension;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.bouncycastle.util.Arrays;

import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFLNK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFMT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFREG;

/**
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface SftpClient extends SubsystemClient {

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
        OwnerGroup,
        AccessTime,
        ModifyTime,
        CreateTime
    }

    class Handle {
        private final byte[] id;

        Handle(byte[] id) {
            // clone the original so the handle is immutable
            this.id = ValidateUtils.checkNotNullAndNotEmpty(id, "No handle ID").clone();
        }

        public int length() {
            return id.length;
        }

        /**
         * @return A <U>cloned</U> instance of the identifier in order to
         * avoid inadvertent modifications to the handle contents
         */
        public byte[] getIdentifier() {
            return id.clone();
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(id);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }

            if (obj == this) {
                return true;
            }

            // we do not ask getClass() == obj.getClass() in order to allow for derived classes equality
            if (!(obj instanceof Handle)) {
                return false;
            }

            return Arrays.areEqual(id, ((Handle) obj).id);
        }

        @Override
        public String toString() {
            return BufferUtils.printHex(BufferUtils.EMPTY_HEX_SEPARATOR, id);
        }
    }

    // CHECKSTYLE:OFF
    abstract class CloseableHandle extends Handle implements Channel, Closeable {
        protected CloseableHandle(byte[] id) {
            super(id);
        }
    }
    // CHECKSTYLE:ON

    class Attributes {
        // CHECKSTYLE:OFF
        public final Set<Attribute> flags = EnumSet.noneOf(Attribute.class);
        public int type;
        // CHECKSTYLE:ON

        private int perms;
        private int uid;
        private int gid;
        private String owner;
        private String group;
        private long size;
        private FileTime accessTime;
        private FileTime createTime;
        private FileTime modifyTime;

        public Attributes() {
            super();
        }

        @Override
        public String toString() {
            return "type=" + type
                 + ";size=" + getSize()
                 + ";uid=" + getUserId()
                 + ";gid=" + getGroupId()
                 + ";perms=0x" + Integer.toHexString(getPermissions())
                 + ";flags=" + flags
                 + ";owner=" + getOwner()
                 + ";group=" + getGroup()
                 + ";aTime=" + getAccessTime()
                 + ";cTime=" + getCreateTime()
                 + ";mTime=" + getModifyTime();
        }

        public long getSize() {
            return size;
        }

        public Attributes size(long size) {
            setSize(size);
            return this;
        }

        public void setSize(long size) {
            flags.add(Attribute.Size);
            this.size = size;
        }

        public String getOwner() {
            return owner;
        }

        public Attributes owner(String owner) {
            setOwner(owner);
            return this;
        }

        public void setOwner(String owner) {
            flags.add(Attribute.OwnerGroup);
            this.owner = owner;
            if (GenericUtils.isEmpty(group)) {
                group = "GROUP@";
            }
        }

        public String getGroup() {
            return group;
        }

        public Attributes group(String group) {
            setGroup(group);
            return this;
        }

        public void setGroup(String group) {
            flags.add(Attribute.OwnerGroup);
            this.group = group;
            if (GenericUtils.isEmpty(owner)) {
                owner = "OWNER@";
            }
        }

        public int getUserId() {
            return uid;
        }

        public int getGroupId() {
            return gid;
        }

        public Attributes owner(int uid, int gid) {
            flags.add(Attribute.UidGid);
            this.uid = uid;
            this.gid = gid;
            return this;
        }

        public int getPermissions() {
            return perms;
        }

        public Attributes perms(int perms) {
            setPermissions(perms);
            return this;
        }

        public void setPermissions(int perms) {
            flags.add(Attribute.Perms);
            this.perms = perms;
        }

        public FileTime getAccessTime() {
            return accessTime;
        }

        public Attributes accessTime(long atime) {
            return accessTime(atime, TimeUnit.SECONDS);
        }

        public Attributes accessTime(long atime, TimeUnit unit) {
            return accessTime(FileTime.from(atime, unit));
        }

        public Attributes accessTime(FileTime atime) {
            setAccessTime(atime);
            return this;
        }

        public void setAccessTime(FileTime atime) {
            flags.add(Attribute.AccessTime);
            accessTime = ValidateUtils.checkNotNull(atime, "No access time");
        }

        public FileTime getCreateTime() {
            return createTime;
        }

        public Attributes createTime(long ctime) {
            return createTime(ctime, TimeUnit.SECONDS);
        }

        public Attributes createTime(long ctime, TimeUnit unit) {
            return createTime(FileTime.from(ctime, unit));
        }

        public Attributes createTime(FileTime ctime) {
            setCreateTime(ctime);
            return this;
        }

        public void setCreateTime(FileTime ctime) {
            flags.add(Attribute.CreateTime);
            createTime = ValidateUtils.checkNotNull(ctime, "No create time");
        }

        public FileTime getModifyTime() {
            return modifyTime;
        }

        public Attributes modifyTime(long mtime) {
            return modifyTime(mtime, TimeUnit.SECONDS);
        }

        public Attributes modifyTime(long mtime, TimeUnit unit) {
            return modifyTime(FileTime.from(mtime, unit));
        }

        public Attributes modifyTime(FileTime mtime) {
            setModifyTime(mtime);
            return this;
        }

        public void setModifyTime(FileTime mtime) {
            flags.add(Attribute.ModifyTime);
            modifyTime = ValidateUtils.checkNotNull(mtime, "No modify time");
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

    class DirEntry {
        // CHECKSTYLE:OFF
        public String filename;
        public String longFilename;
        public Attributes attributes;
        // CHECKSTYLE:ON

        DirEntry(String filename, String longFilename, Attributes attributes) {
            this.filename = filename;
            this.longFilename = longFilename;
            this.attributes = attributes;
        }
    }

    // default values used if none specified
    int MIN_BUFFER_SIZE = Byte.MAX_VALUE;
    int MIN_READ_BUFFER_SIZE = MIN_BUFFER_SIZE;
    int MIN_WRITE_BUFFER_SIZE = MIN_BUFFER_SIZE;
    int IO_BUFFER_SIZE = 32 * 1024;
    int DEFAULT_READ_BUFFER_SIZE = IO_BUFFER_SIZE;
    int DEFAULT_WRITE_BUFFER_SIZE = IO_BUFFER_SIZE;
    long DEFAULT_WAIT_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    /**
     * Property that can be used on the {@link org.apache.sshd.common.FactoryManager}
     * to control the internal timeout used by the client to open a channel.
     * If not specified then {@link #DEFAULT_CHANNEL_OPEN_TIMEOUT} value
     * is used
     */
    String SFTP_CHANNEL_OPEN_TIMEOUT = "sftp-channel-open-timeout";
    long DEFAULT_CHANNEL_OPEN_TIMEOUT = DEFAULT_WAIT_TIMEOUT;

    int getVersion();

    /**
     * @return An (unmodifiable) {@link Map} of the reported server extensions.
     */
    Map<String, byte[]> getServerExtensions();

    boolean isClosing();

    //
    // Low level API
    //

    /**
     * Opens a remote file for read
     *
     * @param path The remote path
     * @return The file's {@link CloseableHandle}
     * @throws IOException If failed to open the remote file
     */
    CloseableHandle open(String path) throws IOException;

    /**
     * Opens a remote file with the specified mode(s)
     *
     * @param path    The remote path
     * @param options The desired mode - if none specified
     *                then {@link OpenMode#Read} is assumed
     * @return The file's {@link CloseableHandle}
     * @throws IOException If failed to open the remote file
     */
    CloseableHandle open(String path, OpenMode... options) throws IOException;

    /**
     * Opens a remote file with the specified mode(s)
     *
     * @param path    The remote path
     * @param options The desired mode - if none specified
     *                then {@link OpenMode#Read} is assumed
     * @return The file's {@link CloseableHandle}
     * @throws IOException If failed to open the remote file
     */
    CloseableHandle open(String path, Collection<OpenMode> options) throws IOException;

    void close(Handle handle) throws IOException;

    void remove(String path) throws IOException;

    void rename(String oldPath, String newPath) throws IOException;

    void rename(String oldPath, String newPath, CopyMode... options) throws IOException;

    void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException;

    int read(Handle handle, long fileOffset, byte[] dst) throws IOException;

    int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len) throws IOException;

    void write(Handle handle, long fileOffset, byte[] src) throws IOException;

    void write(Handle handle, long fileOffset, byte[] src, int srcOffset, int len) throws IOException;

    void mkdir(String path) throws IOException;

    void rmdir(String path) throws IOException;

    CloseableHandle openDir(String path) throws IOException;

    /**
     * @param handle Directory {@link Handle} to read from
     * @return A {@link List} of entries - {@code null} to indicate no more entries
     * <B>Note:</B> the list may be <U>incomplete</U> since the client and
     * server have some internal imposed limit on the number of entries they
     * can process. Therefore several calls to this method may be required
     * (until {@code null}). In order to iterate over all the entries use
     * {@link #readDir(String)}
     * @throws IOException If failed to access the remote site
     */
    List<DirEntry> readDir(Handle handle) throws IOException;

    String canonicalPath(String path) throws IOException;

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

    /**
     * @param path The remote directory path
     * @return An {@link Iterable} that can be used to iterate over all the
     * directory entries (unlike {@link #readDir(Handle)})
     * @throws IOException If failed to access the remote site
     * @see #readDir(Handle)
     */
    Iterable<DirEntry> readDir(String path) throws IOException;

    InputStream read(String path) throws IOException;

    InputStream read(String path, int bufferSize) throws IOException;

    InputStream read(String path, OpenMode... mode) throws IOException;

    InputStream read(String path, int bufferSize, OpenMode... mode) throws IOException;

    InputStream read(String path, Collection<OpenMode> mode) throws IOException;

    InputStream read(String path, int bufferSize, Collection<OpenMode> mode) throws IOException;

    OutputStream write(String path) throws IOException;

    OutputStream write(String path, int bufferSize) throws IOException;

    OutputStream write(String path, OpenMode... mode) throws IOException;

    OutputStream write(String path, int bufferSize, OpenMode... mode) throws IOException;

    OutputStream write(String path, Collection<OpenMode> mode) throws IOException;

    OutputStream write(String path, int bufferSize, Collection<OpenMode> mode) throws IOException;

    /**
     * @param <E>           The generic extension type
     * @param extensionType The extension type
     * @return The extension instance - <B>Note:</B> it is up to the caller
     * to invoke {@link SftpClientExtension#isSupported()} - {@code null} if
     * this extension type is not implemented by the client
     * @see #getServerExtensions()
     */
    <E extends SftpClientExtension> E getExtension(Class<? extends E> extensionType);

    /**
     * @param extensionName The extension name
     * @return The extension instance - <B>Note:</B> it is up to the caller
     * to invoke {@link SftpClientExtension#isSupported()} - {@code null} if
     * this extension type is not implemented by the client
     * @see #getServerExtensions()
     */
    SftpClientExtension getExtension(String extensionName);
}
