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
package org.apache.sshd.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;

/**
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public interface SftpClient {

    //
    // Permission flags
    //
    int S_IFMT =   0170000;  // bitmask for the file type bitfields
    int S_IFSOCK = 0140000;  // socket
    int S_IFLNK =  0120000;  // symbolic link
    int S_IFREG =  0100000;  // regular file
    int S_IFBLK =  0060000;  // block device
    int S_IFDIR =  0040000;  // directory
    int S_IFCHR =  0020000;  // character device
    int S_IFIFO =  0010000;  // fifo
    int S_ISUID =  0004000;  // set UID bit
    int S_ISGID =  0002000;  // set GID bit
    int S_ISVTX =  0001000;  // sticky bit
    int S_IRUSR =  0000400;
    int S_IWUSR =  0000200;
    int S_IXUSR =  0000100;
    int S_IRGRP =  0000040;
    int S_IWGRP =  0000020;
    int S_IXGRP =  0000010;
    int S_IROTH =  0000004;
    int S_IWOTH =  0000002;
    int S_IXOTH =  0000001;

    enum OpenMode {
        Read,
        Write,
        Append,
        Create,
        Truncate,
        Exclusive
    }

    enum Attribute {
        Size,
        UidGid,
        Perms,
        AcModTime
    }

    public static class Handle {
        public final String id;
        public Handle(String id) {
            this.id = id;
        }
    }

    public static class Attributes {
        public EnumSet<Attribute> flags = EnumSet.noneOf(Attribute.class);
        public long size;
        public int uid;
        public int gid;
        public int perms;
        public int atime;
        public int mtime;
        public Attributes size(long size) {
            flags.add(Attribute.Size);
            this.size = size;
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
        public Attributes time(int atime, int mtime) {
            flags.add(Attribute.AcModTime);
            this.atime = atime;
            this.mtime = mtime;
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

    /**
     * Close the client.
     */
    void close() throws IOException;

    //
    // Low level API
    //

    Handle open(String path, EnumSet<OpenMode> options) throws IOException;

    void close(Handle handle) throws IOException;

    void remove(String path) throws IOException;

    void rename(String oldPath, String newPath) throws IOException;

    int read(Handle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException;

    void write(Handle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException;

    void mkdir(String path) throws IOException;

    void rmdir(String path) throws IOException;

    Handle openDir(String path) throws IOException;

    DirEntry[] readDir(Handle handle) throws IOException;

    String canonicalPath(String canonical) throws IOException;

    Attributes stat(String path) throws IOException;

    Attributes lstat(String path) throws IOException;

    Attributes stat(Handle handle) throws IOException;

    void setStat(String path, Attributes attributes) throws IOException;

    void setStat(Handle handle, Attributes attributes) throws IOException;

    String readLink(String path) throws IOException;

    void symLink(String linkPath, String targetPath) throws IOException;

    //
    // High level API
    //

    Iterable<DirEntry> readDir(String path) throws IOException;

    InputStream read(String path) throws IOException;

    InputStream read(String path, EnumSet<OpenMode> mode) throws IOException;

    OutputStream write(String path) throws IOException;

    OutputStream write(String path, EnumSet<OpenMode> mode) throws IOException;

}
