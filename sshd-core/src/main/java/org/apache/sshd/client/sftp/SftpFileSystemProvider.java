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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.ClientSession;
import org.apache.sshd.SshBuilder;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.SftpException;

public class SftpFileSystemProvider extends FileSystemProvider {

    public static final int SSH_FX_NO_SUCH_FILE =         2;
    public static final int SSH_FX_FILE_ALREADY_EXISTS = 11;

    final SshClient client;
    final Map<String, SftpFileSystem> fileSystems = new HashMap<String, SftpFileSystem>();

    public SftpFileSystemProvider() {
        this(null);
    }

    public SftpFileSystemProvider(SshClient client) {
        if (client == null) {
            // TODO: make this configurable using system properties
            client = SshBuilder.client().build();
        }
        this.client = client;
        this.client.start();
    }

    @Override
    public String getScheme() {
        return "sftp";
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        synchronized (fileSystems) {
            String authority = uri.getAuthority();
            SftpFileSystem fileSystem = fileSystems.get(authority);
            if (fileSystem != null) {
                throw new FileSystemAlreadyExistsException(authority);
            }
            String host = uri.getHost();
            String userInfo = uri.getUserInfo();
            if (host == null) {
                throw new IllegalArgumentException("Host not provided");
            }
            if (userInfo == null) {
                throw new IllegalArgumentException("UserInfo not provided");
            }
            String[] ui = userInfo.split(":");
            ClientSession session;
            try {
                session = client.connect(ui[0], host, uri.getPort() > 0 ? uri.getPort() : 22)
                        .await().getSession();
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            }
            session.addPasswordIdentity(ui[1]);
            session.auth().verify();
            fileSystem = new SftpFileSystem(this, session);
            fileSystems.put(authority, fileSystem);
            return fileSystem;
        }
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        synchronized (fileSystems) {
            String authority = uri.getAuthority();
            SftpFileSystem fileSystem = fileSystems.get(authority);
            if (fileSystem == null) {
                throw new FileSystemNotFoundException(authority);
            }
            return fileSystem;
        }
    }

    @Override
    public Path getPath(URI uri) {
        return getFileSystem(uri).getPath(uri.getPath());
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        final SftpPath p = toSftpPath(path);
        final EnumSet<SftpClient.OpenMode> modes = EnumSet.noneOf(SftpClient.OpenMode.class);
        for (OpenOption option : options) {
            if (option == StandardOpenOption.READ) {
                modes.add(SftpClient.OpenMode.Read);
            } else if (option == StandardOpenOption.APPEND) {
                modes.add(SftpClient.OpenMode.Append);
            } else if (option == StandardOpenOption.CREATE) {
                modes.add(SftpClient.OpenMode.Create);
            } else if (option == StandardOpenOption.TRUNCATE_EXISTING) {
                modes.add(SftpClient.OpenMode.Truncate);
            } else if (option == StandardOpenOption.WRITE) {
                modes.add(SftpClient.OpenMode.Write);
            } else if (option == StandardOpenOption.CREATE_NEW) {
                modes.add(SftpClient.OpenMode.Create);
                modes.add(SftpClient.OpenMode.Exclusive);
            } else {
                throw new IllegalArgumentException("Unsupported open option " + option);
            }
        }
        if (modes.isEmpty()) {
            modes.add(SftpClient.OpenMode.Read);
        }
        return new SeekableByteChannel() {
            final SftpClient sftp = p.getFileSystem().getClient();
            final SftpClient.Handle handle = sftp.open(p.toString(), modes);
            long pos = 0;
            @Override
            public int read(ByteBuffer dst) throws IOException {
                if (dst.hasArray()) {
                    int read = sftp.read(handle, pos, dst.array(), dst.arrayOffset() + dst.position(), dst.remaining());
                    if (read > 0) {
                        dst.position(dst.position() + read);
                        pos += read;
                    }
                    return read;
                } else {
                    int remaining = Math.min(8192, dst.remaining());
                    byte[] buf = new byte[remaining];
                    int read = sftp.read(handle, pos, buf, 0, remaining);
                    if (read > 0) {
                        dst.put(buf, 0, read);
                        pos += read;
                    }
                    return read;
                }
            }

            @Override
            public int write(ByteBuffer src) throws IOException {
                if (src.hasArray()) {
                    int rem = src.remaining();
                    sftp.write(handle, pos, src.array(), src.arrayOffset() + src.position(), rem);
                    src.position(src.position() + rem);
                    pos += rem;
                    return rem;
                } else {
                    byte[] buf = new byte[Math.min(8192, src.remaining())];
                    src.get(buf);
                    sftp.write(handle, pos, buf, 0, buf.length);
                    pos += buf.length;
                    return buf.length;
                }
            }

            @Override
            public long position() throws IOException {
                if (pos < 0) {
                    throw new ClosedChannelException();
                }
                return pos;
            }

            @Override
            public SeekableByteChannel position(long newPosition) throws IOException {
                if (newPosition < 0) {
                    throw new IllegalArgumentException();
                }
                pos = newPosition;
                return this;
            }

            @Override
            public long size() throws IOException {
                return sftp.stat(handle).size;
            }

            @Override
            public SeekableByteChannel truncate(long size) throws IOException {
                sftp.setStat(handle, new SftpClient.Attributes().size(size));
                return this;
            }

            @Override
            public boolean isOpen() {
                return pos >= 0;
            }

            @Override
            public void close() throws IOException {
                if (pos >= 0) {
                    sftp.close(handle);
                    sftp.close();
                    pos = -1;
                }
            }
        };
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        final SftpPath p = toSftpPath(dir);
        return new DirectoryStream<Path>() {
            final SftpClient sftp = p.getFileSystem().getClient();
            final Iterable<SftpClient.DirEntry> iter = sftp.readDir(p.toString());
            @Override
            public Iterator<Path> iterator() {
                return new Iterator<Path>() {
                    final Iterator<SftpClient.DirEntry> it = iter.iterator();
                    @Override
                    public boolean hasNext() {
                        return it.hasNext();
                    }

                    @Override
                    public Path next() {
                        SftpClient.DirEntry entry = it.next();
                        return p.resolve(entry.filename);
                    }

                    @Override
                    public void remove() {
                        throw new UnsupportedOperationException();
                    }
                };
            }

            @Override
            public void close() throws IOException {
                sftp.close();
            }
        };
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        SftpPath p = toSftpPath(dir);
        try (SftpClient sftp = p.getFileSystem().getClient()) {
            // TODO: handle attributes
            try {
                sftp.mkdir(dir.toString());
            } catch (SftpException e) {
                if (e.getStatus() == SSH_FX_FILE_ALREADY_EXISTS) {
                    throw new FileAlreadyExistsException(p.toString());
                }
                throw e;
            }
        }
    }

    @Override
    public void delete(Path path) throws IOException {
        SftpPath p = toSftpPath(path);
        checkAccess(p, AccessMode.WRITE);
        try (SftpClient sftp = p.getFileSystem().getClient()) {
            BasicFileAttributes attributes = readAttributes(path, BasicFileAttributes.class);
            if (attributes.isDirectory()) {
                sftp.rmdir(path.toString());
            } else {
                sftp.remove(path.toString());
            }
        }
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        // TODO
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        // TODO

    }

    @Override
    public boolean isSameFile(Path path1, Path path2) throws IOException {
        SftpPath p1 = toSftpPath(path1);
        SftpPath p2 = toSftpPath(path2);
        checkAccess(p1);
        checkAccess(p2);
        return p1.equals(p2);
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        return false;
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        SftpPath l = toSftpPath(link);
        SftpPath t = toSftpPath(target);
        if (l.getFileSystem() != t.getFileSystem()) {
            throw new ProviderMismatchException();
        }
        try (SftpClient client = l.getFileSystem().getClient()) {
            client.symLink(l.toString(), t.toString());
        }
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        SftpPath l = toSftpPath(link);
        try (SftpClient client = l.getFileSystem().getClient()) {
            return l.getFileSystem().getPath(client.readLink(l.toString()));
        }
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        SftpPath p = toSftpPath(path);
        boolean w = false;
        boolean x = false;
        for (AccessMode mode : modes) {
            switch (mode) {
            case READ:
                break;
            case WRITE:
                w = true;
                break;
            case EXECUTE:
                x = true;
                break;
            default:
                throw new UnsupportedOperationException();
            }
        }
        BasicFileAttributes attrs = getFileAttributeView(p, BasicFileAttributeView.class).readAttributes();
        if (attrs == null && !(p.isAbsolute() && p.getNameCount() == 0)) {
            throw new NoSuchFileException(toString());
        }
        if (x || w && p.getFileSystem().isReadOnly()) {
            throw new AccessDeniedException(toString());
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <V extends FileAttributeView> V getFileAttributeView(final Path path, Class<V> type, final LinkOption... options) {
        if (type.isAssignableFrom(PosixFileAttributeView.class)) {
            return (V) new PosixFileAttributeView() {
                @Override
                public String name() {
                    return "view";
                }

                @Override
                public PosixFileAttributes readAttributes() throws IOException {
                    SftpPath p = toSftpPath(path);
                    final SftpClient.Attributes attributes;
                    try (SftpClient client = p.getFileSystem().getClient()) {
                        try {
                            if (followLinks(options)) {
                                attributes = client.stat(p.toString());
                            } else {
                                attributes = client.lstat(p.toString());
                            }
                        } catch (SftpException e) {
                            if (e.getStatus() == SSH_FX_NO_SUCH_FILE) {
                                throw new NoSuchFileException(p.toString());
                            }
                            throw e;
                        }
                    }
                    return new PosixFileAttributes() {
                        @Override
                        public UserPrincipal owner() {
                            // TODO
                            return null;
                        }

                        @Override
                        public GroupPrincipal group() {
                            // TODO
                            return null;
                        }

                        @Override
                        public Set<PosixFilePermission> permissions() {
                            // TODO
                            return null;
                        }

                        @Override
                        public FileTime lastModifiedTime() {
                            return FileTime.from(attributes.mtime, TimeUnit.SECONDS);
                        }

                        @Override
                        public FileTime lastAccessTime() {
                            return FileTime.from(attributes.atime, TimeUnit.SECONDS);
                        }

                        @Override
                        public FileTime creationTime() {
                            // TODO
                            return null;
                        }

                        @Override
                        public boolean isRegularFile() {
                            return attributes.isRegularFile();
                        }

                        @Override
                        public boolean isDirectory() {
                            return attributes.isDirectory();
                        }

                        @Override
                        public boolean isSymbolicLink() {
                            return attributes.isSymbolicLink();
                        }

                        @Override
                        public boolean isOther() {
                            return attributes.isOther();
                        }

                        @Override
                        public long size() {
                            return attributes.size;
                        }

                        @Override
                        public Object fileKey() {
                            // TODO
                            return null;
                        }
                    };
                }

                @Override
                public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
                    if (lastModifiedTime != null) {
                        setAttribute(path, "lastModifiedTime", lastModifiedTime, options);
                    }
                    if (lastAccessTime != null) {
                        setAttribute(path, "lastAccessTime", lastAccessTime, options);
                    }
                    if (createTime != null) {
                        setAttribute(path, "createTime", createTime, options);
                    }
                }

                @Override
                public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
                    setAttribute(path, "permissions", perms, options);
                }

                @Override
                public void setGroup(GroupPrincipal group) throws IOException {
                    setAttribute(path, "group", group, options);
                }

                @Override
                public UserPrincipal getOwner() throws IOException {
                    return readAttributes().owner();
                }

                @Override
                public void setOwner(UserPrincipal owner) throws IOException {
                    setAttribute(path, "owner", owner, options);
                }
            };
        } else {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options) throws IOException {
        if (type.isAssignableFrom(PosixFileAttributes.class)) {
            return (A) getFileAttributeView(path, PosixFileAttributeView.class, options).readAttributes();
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        String view;
        String attrs;
        int i = attributes.indexOf(':');
        if (i == -1) {
            view = "basic";
            attrs = attributes;
        } else {
            view = attributes.substring(0, i++);
            attrs = attributes.substring(i);
        }
        SftpPath p = toSftpPath(path);
        if (!p.getFileSystem().supportedFileAttributeViews().contains(view)) {
            throw new UnsupportedOperationException();
        }
        PosixFileAttributes v = readAttributes(path, PosixFileAttributes.class, options);
        if ("*".equals(attrs)) {
            attrs = "lastModifiedTime,lastAccessTime,creationTime,size,isRegularFile,isDirectory,isSymbolicLink,isOther,fileKey,owner,permissions,group";
        }
        Map<String, Object> map = new HashMap<>();
        for (String attr : attrs.split(",")) {
            switch (attr) {
            case "lastModifiedTime":
                map.put(attr, v.lastModifiedTime());
                break;
            case "lastAccessTime":
                map.put(attr, v.lastAccessTime());
                break;
            case "creationTime":
                map.put(attr, v.creationTime());
                break;
            case "size":
                map.put(attr, v.size());
                break;
            case "isRegularFile":
                map.put(attr, v.isRegularFile());
                break;
            case "isDirectory":
                map.put(attr, v.isDirectory());
                break;
            case "isSymbolicLink":
                map.put(attr, v.isSymbolicLink());
                break;
            case "isOther":
                map.put(attr, v.isOther());
                break;
            case "fileKey":
                map.put(attr, v.fileKey());
                break;
            case "owner":
                map.put(attr, v.owner());
                break;
            case "permissions":
                map.put(attr, v.permissions());
                break;
            case "group":
                map.put(attr, v.group());
                break;
            }
        }
        return map;
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        String view;
        String attr;
        int i = attribute.indexOf(':');
        if (i == -1) {
            view = "basic";
            attr = attribute;
        } else {
            view = attribute.substring(0, i++);
            attr = attribute.substring(i);
        }
        SftpPath p = toSftpPath(path);
        if (!p.getFileSystem().supportedFileAttributeViews().contains(view)) {
            throw new UnsupportedOperationException();
        }
        SftpClient.Attributes attributes = new SftpClient.Attributes();
        switch (attr) {
        case "lastModifiedTime":
            attributes.mtime = (int) ((FileTime) value).to(TimeUnit.SECONDS);
            break;
        case "lastAccessTime":
            attributes.atime = (int) ((FileTime) value).to(TimeUnit.SECONDS);
            break;
        case "size":
            attributes.size = (long) value;
            break;
        case "owner":
        case "permissions":
        case "group":
            // TODO: handle those
            throw new IllegalArgumentException(attr);
        case "creationTime":
        case "isRegularFile":
        case "isDirectory":
        case "isSymbolicLink":
        case "isOther":
        case "fileKey":
            throw new IllegalArgumentException(attr);
        }
        try (SftpClient client = p.getFileSystem().getClient()) {
            client.setStat(p.toString(), attributes);
        }
    }

    private SftpPath toSftpPath(Path path) {
        if (path == null) {
            throw new NullPointerException();
        }
        if (!(path instanceof SftpPath)) {
            throw new ProviderMismatchException();
        }
        return (SftpPath) path;
    }

    static boolean followLinks(LinkOption... paramVarArgs)
    {
        boolean bool = true;
        for (LinkOption localLinkOption : paramVarArgs) {
            if (localLinkOption == LinkOption.NOFOLLOW_LINKS) {
                bool = false;
            }
        }
        return bool;
    }

}
