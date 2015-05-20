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

import static org.apache.sshd.common.sftp.SftpConstants.SFTP_V3;
import static org.apache.sshd.common.sftp.SftpConstants.S_IRGRP;
import static org.apache.sshd.common.sftp.SftpConstants.S_IROTH;
import static org.apache.sshd.common.sftp.SftpConstants.S_IRUSR;
import static org.apache.sshd.common.sftp.SftpConstants.S_IWGRP;
import static org.apache.sshd.common.sftp.SftpConstants.S_IWOTH;
import static org.apache.sshd.common.sftp.SftpConstants.S_IWUSR;
import static org.apache.sshd.common.sftp.SftpConstants.S_IXGRP;
import static org.apache.sshd.common.sftp.SftpConstants.S_IXOTH;
import static org.apache.sshd.common.sftp.SftpConstants.S_IXUSR;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.channels.FileChannel;
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
import java.nio.file.StandardCopyOption;
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
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.ClientSession;
import org.apache.sshd.SshBuilder;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.SftpClient.Attributes;
import org.apache.sshd.client.SftpException;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SftpFileSystemProvider extends FileSystemProvider {
    private final SshClient client;
    private final Map<String, SftpFileSystem> fileSystems = new HashMap<String, SftpFileSystem>();
    protected final Logger log;

    public SftpFileSystemProvider() {
        this(null);
    }

    public SftpFileSystemProvider(SshClient client) {
        this.log = LoggerFactory.getLogger(getClass());
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
                session = client.connect(ui[0], host, uri.getPort() > 0 ? uri.getPort() : SshConfigFileReader.DEFAULT_PORT)
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
        return newFileChannel(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
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
            modes.add(SftpClient.OpenMode.Write);
        }
        // TODO: attrs
        return new SftpFileChannel(p, modes);
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
            try {
                sftp.mkdir(dir.toString());
            } catch (SftpException e) {
                int sftpStatus=e.getStatus();
                if ((sftp.getVersion() == SFTP_V3) && (sftpStatus == SftpConstants.SSH_FX_FAILURE)) {
                    try {
                        Attributes attributes = sftp.stat(dir.toString());
                        if (attributes != null) {
                            throw new FileAlreadyExistsException(p.toString());
                        }
                    } catch (SshException e2) {
                        e.addSuppressed(e2);
                    }
                }
                if (sftpStatus == SftpConstants.SSH_FX_FILE_ALREADY_EXISTS) {
                    throw new FileAlreadyExistsException(p.toString());
                }
                throw e;
            }
            for (FileAttribute<?> attr : attrs) {
                setAttribute(p, attr.name(), attr.value());
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
        SftpPath src = toSftpPath(source);
        SftpPath dst = toSftpPath(target);
        if (src.getFileSystem() != dst.getFileSystem()) {
            throw new ProviderMismatchException("Mismatched file system providers");
        }
        checkAccess(src);

        boolean replaceExisting = false;
        boolean copyAttributes = false;
        boolean noFollowLinks = false;
        for (CopyOption opt : options) {
            replaceExisting |= opt == StandardCopyOption.REPLACE_EXISTING;
            copyAttributes |= opt == StandardCopyOption.COPY_ATTRIBUTES;
            noFollowLinks |= opt == LinkOption.NOFOLLOW_LINKS;
        }
        LinkOption[] linkOptions = IoUtils.getLinkOptions(!noFollowLinks);

        // attributes of source file
        BasicFileAttributes attrs = readAttributes(source,
                BasicFileAttributes.class,
                linkOptions);
        if (attrs.isSymbolicLink())
            throw new IOException("Copying of symbolic links not supported");

        // delete target if it exists and REPLACE_EXISTING is specified
        Boolean status=IoUtils.checkFileExists(target, linkOptions);
        if (status == null) {
            throw new AccessDeniedException("Existence cannot be determined for copy target: " + target);
        }

        if (replaceExisting) {
            deleteIfExists(target);
        } else {
            if (status.booleanValue()) {
                throw new FileAlreadyExistsException(target.toString());
            }
        }

        // create directory or copy file
        if (attrs.isDirectory()) {
            createDirectory(target);
        } else {
            try (InputStream in = newInputStream(source);
                 OutputStream os = newOutputStream(target)) {
                IoUtils.copy(in, os);
            }
        }

        // copy basic attributes to target
        if (copyAttributes) {
            BasicFileAttributeView view = getFileAttributeView(target, BasicFileAttributeView.class, linkOptions);
            try {
                view.setTimes(attrs.lastModifiedTime(),
                        attrs.lastAccessTime(),
                        attrs.creationTime());
            } catch (Throwable x) {
                // rollback
                try {
                    delete(target);
                } catch (Throwable suppressed) {
                    x.addSuppressed(suppressed);
                }
                throw x;
            }
        }
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        SftpPath src = toSftpPath(source);
        SftpPath dst = toSftpPath(target);
        if (src.getFileSystem() != dst.getFileSystem()) {
            throw new ProviderMismatchException();
        }
        checkAccess(src);

        boolean replaceExisting = false;
        boolean copyAttributes = false;
        boolean noFollowLinks = false;
        for (CopyOption opt : options) {
            replaceExisting |= opt == StandardCopyOption.REPLACE_EXISTING;
            copyAttributes |= opt == StandardCopyOption.COPY_ATTRIBUTES;
            noFollowLinks |= opt == LinkOption.NOFOLLOW_LINKS;
        }
        LinkOption[] linkOptions = IoUtils.getLinkOptions(noFollowLinks);

        // attributes of source file
        BasicFileAttributes attrs = readAttributes(source,
                BasicFileAttributes.class,
                linkOptions);
        if (attrs.isSymbolicLink())
            throw new IOException("Copying of symbolic links not supported");

        // delete target if it exists and REPLACE_EXISTING is specified
        Boolean status=IoUtils.checkFileExists(target, linkOptions);
        if (status == null) {
            throw new AccessDeniedException("Existence cannot be determined for move target " + target);
        }

        if (replaceExisting) {
            deleteIfExists(target);
        } else if (status.booleanValue())
            throw new FileAlreadyExistsException(target.toString());

        try (SftpClient sftp = src.getFileSystem().getClient()) {
            sftp.rename(src.toString(), dst.toString());
        }

        // copy basic attributes to target
        if (copyAttributes) {
            BasicFileAttributeView view = getFileAttributeView(target, BasicFileAttributeView.class, linkOptions);
            try {
                view.setTimes(attrs.lastModifiedTime(),
                        attrs.lastAccessTime(),
                        attrs.creationTime());
            } catch (Throwable x) {
                // rollback
                try {
                    delete(target);
                } catch (Throwable suppressed) {
                    x.addSuppressed(suppressed);
                }
                throw x;
            }
        }
    }

    @Override
    public boolean isSameFile(Path path1, Path path2) throws IOException {
        SftpPath p1 = toSftpPath(path1);
        SftpPath p2 = toSftpPath(path2);
        if (p1.getFileSystem() != p2.getFileSystem()) {
            throw new ProviderMismatchException();
        }
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
                    throw new UnsupportedOperationException("Unsupported mode: " + mode);
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

                @SuppressWarnings("synthetic-access")
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
                            if (e.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                                throw new NoSuchFileException(p.toString());
                            }
                            throw e;
                        }
                    }
                    return new PosixFileAttributes() {
                        @Override
                        public UserPrincipal owner() {
                            return attributes.owner != null ? new SftpFileSystem.DefaultGroupPrincipal(attributes.owner) : null;
                        }

                        @Override
                        public GroupPrincipal group() {
                            return attributes.group != null ? new SftpFileSystem.DefaultGroupPrincipal(attributes.group) : null;
                        }

                        @Override
                        public Set<PosixFilePermission> permissions() {
                            return permissionsToAttributes(attributes.perms);
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
                            return FileTime.from(attributes.ctime, TimeUnit.SECONDS);
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
            return type.cast(getFileAttributeView(path, PosixFileAttributeView.class, options).readAttributes());
        }

        throw new UnsupportedOperationException("readAttributes(" + path + ")[" + type.getSimpleName() + "] N/A");
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
                    map.put(attr, Long.valueOf(v.size()));
                    break;
                case "isRegularFile":
                    map.put(attr, Boolean.valueOf(v.isRegularFile()));
                    break;
                case "isDirectory":
                    map.put(attr, Boolean.valueOf(v.isDirectory()));
                    break;
                case "isSymbolicLink":
                    map.put(attr, Boolean.valueOf(v.isSymbolicLink()));
                    break;
                case "isOther":
                    map.put(attr, Boolean.valueOf(v.isOther()));
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
                default:
                    if (log.isTraceEnabled()) {
                        log.trace("readAttributes({})[{}] ignored {}={}", path, attributes, attr, v);
                    }
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
                attributes.mtime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "lastAccessTime":
                attributes.atime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "creationTime":
                attributes.ctime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "size":
                attributes.size(((Number) value).longValue());
                break;
            case "permissions": {
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission>    attrSet = (Set<PosixFilePermission>) value;
                attributes.perms(attributesToPermissions(path, attrSet));
                }
                break;
            case "owner":
                attributes.owner(((UserPrincipal) value).getName());
                break;
            case "group":
                attributes.group(((GroupPrincipal) value).getName());
                break;
            case "isRegularFile":
            case "isDirectory":
            case "isSymbolicLink":
            case "isOther":
            case "fileKey":
                throw new UnsupportedOperationException("setAttribute(" + path + ")[" + attribute + "] unknown view attribute: " + attr);
            default:
                if (log.isTraceEnabled()) {
                    log.trace("setAttribute({})[{}] ignore {}={}", path, attribute, attr, value);
                }
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

    static boolean followLinks(LinkOption... paramVarArgs) {
        boolean bool = true;
        for (LinkOption localLinkOption : paramVarArgs) {
            if (localLinkOption == LinkOption.NOFOLLOW_LINKS) {
                bool = false;
            }
        }
        return bool;
    }

    private Set<PosixFilePermission> permissionsToAttributes(int perms) {
        Set<PosixFilePermission> p = new HashSet<>();
        if ((perms & S_IRUSR) != 0) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }
        return p;
    }

    protected int attributesToPermissions(Path path, Collection<PosixFilePermission> perms) {
        if (GenericUtils.isEmpty(perms)) {
            return 0;
        }

        int pf = 0;
        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                    pf |= S_IRUSR;
                    break;
                case OWNER_WRITE:
                    pf |= S_IWUSR;
                    break;
                case OWNER_EXECUTE:
                    pf |= S_IXUSR;
                    break;
                case GROUP_READ:
                    pf |= S_IRGRP;
                    break;
                case GROUP_WRITE:
                    pf |= S_IWGRP;
                    break;
                case GROUP_EXECUTE:
                    pf |= S_IXGRP;
                    break;
                case OTHERS_READ:
                    pf |= S_IROTH;
                    break;
                case OTHERS_WRITE:
                    pf |= S_IWOTH;
                    break;
                case OTHERS_EXECUTE:
                    pf |= S_IXOTH;
                    break;
                default:
                    if (log.isTraceEnabled()) {
                        log.trace("attributesToPermissions(" + path + ") ignored " + p);
                    }
            }
        }

        return pf;
    }

}
