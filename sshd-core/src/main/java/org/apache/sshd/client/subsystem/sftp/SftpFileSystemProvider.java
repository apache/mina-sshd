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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
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
import java.nio.file.FileSystemException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.SftpClient.Attributes;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SftpFileSystemProvider extends FileSystemProvider {
    public static final String READ_BUFFER_PROP_NAME = "sftp-fs-read-buffer-size";
    public static final int DEFAULT_READ_BUFFER_SIZE = SftpClient.DEFAULT_READ_BUFFER_SIZE;
    public static final String WRITE_BUFFER_PROP_NAME = "sftp-fs-write-buffer-size";
    public static final int DEFAULT_WRITE_BUFFER_SIZE = SftpClient.DEFAULT_WRITE_BUFFER_SIZE;
    public static final String CONNECT_TIME_PROP_NAME = "sftp-fs-connect-time";
    public static final long DEFAULT_CONNECT_TIME = SftpClient.DEFAULT_WAIT_TIMEOUT;
    public static final String AUTH_TIME_PROP_NAME = "sftp-fs-auth-time";
    public static final long DEFAULT_AUTH_TIME = SftpClient.DEFAULT_WAIT_TIMEOUT;
    /**
     * <P>
     * URI parameter that can be used to specify a special version selection. Options are:
     * </P>
     * <UL>
     *      <LI>{@code max} - select maximum available version for the client</LI>
     *      <LI>{@code min} - select minimum available version for the client</LI>
     *      <LI>{@code current} - whatever version is reported by the server</LI>
     *      <LI>{@code nnn} - select <U>only</U> the specified version</LI>
     *      <LI>{@code a,b,c} - select one of the specified versions (if available) in preference order</LI>
     * </UL>
     */
    public static final String VERSION_PARAM = "version";

    public static final Set<Class<? extends FileAttributeView>> UNIVERSAL_SUPPORTED_VIEWS =
            Collections.unmodifiableSet(new HashSet<Class<? extends FileAttributeView>>() {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    add(PosixFileAttributeView.class);
                    add(FileOwnerAttributeView.class);
                    add(BasicFileAttributeView.class);
                }
            });
    protected final Logger log;

    private final SshClient client;
    private final SftpVersionSelector selector;
    private final Map<String, SftpFileSystem> fileSystems = new HashMap<String, SftpFileSystem>();

    public SftpFileSystemProvider() {
        this((SshClient) null);
    }

    public SftpFileSystemProvider(SftpVersionSelector selector) {
        this(null, selector);
    }

    /**
     * @param client The {@link SshClient} to use - if {@code null} then a
     *               default one will be setup and started. Otherwise, it is assumed that
     *               the client has already been started
     * @see SshClient#setUpDefaultClient()
     */
    public SftpFileSystemProvider(SshClient client) {
        this(client, SftpVersionSelector.CURRENT);
    }

    public SftpFileSystemProvider(SshClient client, SftpVersionSelector selector) {
        this.log = LoggerFactory.getLogger(getClass());
        this.selector = selector;
        if (client == null) {
            // TODO: make this configurable using system properties
            client = SshClient.setUpDefaultClient();
            client.start();
        }
        this.client = client;
    }

    @Override
    public String getScheme() {
        return SftpConstants.SFTP_SUBSYSTEM_NAME;
    }

    public final SftpVersionSelector getSftpVersionSelector() {
        return selector;
    }

    @Override // NOTE: co-variant return
    public SftpFileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        String host = ValidateUtils.checkNotNullAndNotEmpty(uri.getHost(), "Host not provided");
        int port = uri.getPort();
        if (port <= 0) {
            port = SshConfigFileReader.DEFAULT_PORT;
        }

        String userInfo = ValidateUtils.checkNotNullAndNotEmpty(uri.getUserInfo(), "UserInfo not provided");
        String[] ui = GenericUtils.split(userInfo, ':');
        ValidateUtils.checkTrue(GenericUtils.length(ui) == 2, "Invalid user info: %s", userInfo);

        String username = ui[0];
        String password = ui[1];
        String id = getFileSystemIdentifier(host, port, username);
        Map<String, Object> params = resolveFileSystemParameters(env, parseURIParameters(uri));
        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(params);
        SftpVersionSelector selector = resolveSftpVersionSelector(uri, getSftpVersionSelector(), resolver);

        SftpFileSystem fileSystem;
        synchronized (fileSystems) {
            if (fileSystems.containsKey(id)) {
                throw new FileSystemAlreadyExistsException(id);
            }

            // TODO try and find a way to avoid doing this while locking the file systems cache
            ClientSession session = null;
            try {
                session = client.connect(username, host, port)
                        .verify(PropertyResolverUtils.getLongProperty(resolver, CONNECT_TIME_PROP_NAME, DEFAULT_CONNECT_TIME))
                        .getSession();
                if (GenericUtils.size(params) > 0) {
                    for (Map.Entry<String, ?> pe : params.entrySet()) {
                        String key = pe.getKey();
                        Object value = pe.getValue();
                        if (VERSION_PARAM.equalsIgnoreCase(key)) {
                            continue;
                        }

                        PropertyResolverUtils.updateProperty(session, key, value);
                    }
                }
                session.addPasswordIdentity(password);
                session.auth().verify(PropertyResolverUtils.getLongProperty(resolver, AUTH_TIME_PROP_NAME, DEFAULT_AUTH_TIME));

                fileSystem = new SftpFileSystem(this, id, session, selector);
                fileSystems.put(id, fileSystem);
            } catch (Exception e) {
                if (session != null) {
                    try {
                        session.close();
                    } catch (IOException t) {
                        if (log.isDebugEnabled()) {
                            log.debug("Failed (" + t.getClass().getSimpleName() + ")"
                                    + " to close session for new file system on " + host + ":" + port
                                    + " due to " + e.getClass().getSimpleName() + "[" + e.getMessage() + "]"
                                    + ": " + t.getMessage());
                        }
                    }
                }

                if (e instanceof IOException) {
                    throw (IOException) e;
                } else if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new IOException(e);
                }
            }
        }

        fileSystem.setReadBufferSize(PropertyResolverUtils.getIntProperty(resolver, READ_BUFFER_PROP_NAME, DEFAULT_READ_BUFFER_SIZE));
        fileSystem.setWriteBufferSize(PropertyResolverUtils.getIntProperty(resolver, WRITE_BUFFER_PROP_NAME, DEFAULT_WRITE_BUFFER_SIZE));
        if (log.isDebugEnabled()) {
            log.debug("newFileSystem({}): {}", uri.toASCIIString(), fileSystem);
        }
        return fileSystem;
    }

    protected SftpVersionSelector resolveSftpVersionSelector(URI uri, SftpVersionSelector defaultSelector, PropertyResolver resolver) {
        String preference = PropertyResolverUtils.getString(resolver, VERSION_PARAM);
        if (GenericUtils.isEmpty(preference)) {
            return defaultSelector;
        }

        if (log.isDebugEnabled()) {
            log.debug("resolveSftpVersionSelector({}) preference={}", uri, preference);
        }

        if ("max".equalsIgnoreCase(preference)) {
            return SftpVersionSelector.MAXIMUM;
        } else if ("min".equalsIgnoreCase(preference)) {
            return SftpVersionSelector.MINIMUM;
        } else if ("current".equalsIgnoreCase(preference)) {
            return SftpVersionSelector.CURRENT;
        }

        String[] values = GenericUtils.split(preference, ',');
        if (values.length == 1) {
            return SftpVersionSelector.Utils.fixedVersionSelector(Integer.parseInt(values[0]));
        }

        int[] preferred = new int[values.length];
        for (int index = 0; index < values.length; index++) {
            preferred[index] = Integer.parseInt(values[index]);
        }

        return SftpVersionSelector.Utils.preferredVersionSelector(preferred);
    }

    // NOTE: URI parameters override environment ones
    public static Map<String, Object> resolveFileSystemParameters(Map<String, ?> env, Map<String, Object> uriParams) {
        if (GenericUtils.isEmpty(env)) {
            return GenericUtils.isEmpty(uriParams) ? Collections.<String, Object>emptyMap() : uriParams;
        } else if (GenericUtils.isEmpty(uriParams)) {
            return Collections.unmodifiableMap(env);
        }

        Map<String, Object> resolved = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        resolved.putAll(env);
        resolved.putAll(uriParams);
        return resolved;
    }

    public static Map<String, Object> parseURIParameters(URI uri) {
        return parseURIParameters((uri == null) ? "" : uri.getQuery());
    }

    public static Map<String, Object> parseURIParameters(String params) {
        if (GenericUtils.isEmpty(params)) {
            return Collections.emptyMap();
        }

        if (params.charAt(0) == '?') {
            if (params.length() == 1) {
                return Collections.emptyMap();
            }
            params = params.substring(1);
        }

        String[] pairs = GenericUtils.split(params, '&');
        Map<String, Object> map = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        for (String p : pairs) {
            int pos = p.indexOf('=');
            if (pos < 0) {
                map.put(p, Boolean.TRUE);
                continue;
            }

            String key = p.substring(0, pos);
            String value = p.substring(pos + 1);
            if (NumberUtils.isIntegerNumber(value)) {
                map.put(key, Long.parseLong(value));
            } else {
                map.put(key, value);
            }
        }

        return map;
    }

    public SftpFileSystem newFileSystem(ClientSession session) throws IOException {
        String id = getFileSystemIdentifier(session);
        SftpFileSystem fileSystem;
        synchronized (fileSystems) {
            if (fileSystems.containsKey(id)) {
                throw new FileSystemAlreadyExistsException(id);
            }
            fileSystem = new SftpFileSystem(this, id, session, getSftpVersionSelector());
            fileSystems.put(id, fileSystem);
        }

        fileSystem.setReadBufferSize(PropertyResolverUtils.getIntProperty(session, READ_BUFFER_PROP_NAME, DEFAULT_READ_BUFFER_SIZE));
        fileSystem.setWriteBufferSize(PropertyResolverUtils.getIntProperty(session, WRITE_BUFFER_PROP_NAME, DEFAULT_WRITE_BUFFER_SIZE));
        if (log.isDebugEnabled()) {
            log.debug("newFileSystem: {}", fileSystem);
        }

        return fileSystem;
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        String id = getFileSystemIdentifier(uri);
        SftpFileSystem fs = getFileSystem(id);
        if (fs == null) {
            throw new FileSystemNotFoundException(id);
        }
        return fs;
    }

    /**
     * @param id File system identifier - ignored if {@code null}/empty
     * @return The removed {@link SftpFileSystem} - {@code null} if no match
     */
    public SftpFileSystem removeFileSystem(String id) {
        if (GenericUtils.isEmpty(id)) {
            return null;
        }

        SftpFileSystem removed;
        synchronized (fileSystems) {
            removed = fileSystems.remove(id);
        }

        if (log.isDebugEnabled()) {
            log.debug("removeFileSystem({}): {}", id, removed);
        }
        return removed;
    }

    /**
     * @param id File system identifier - ignored if {@code null}/empty
     * @return The cached {@link SftpFileSystem} - {@code null} if no match
     */
    public SftpFileSystem getFileSystem(String id) {
        if (GenericUtils.isEmpty(id)) {
            return null;
        }

        synchronized (fileSystems) {
            return fileSystems.get(id);
        }
    }

    @Override
    public Path getPath(URI uri) {
        FileSystem fs = getFileSystem(uri);
        return fs.getPath(uri.getPath());
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        return newFileChannel(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Collection<SftpClient.OpenMode> modes = EnumSet.noneOf(SftpClient.OpenMode.class);
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
            } else if (option == StandardOpenOption.SPARSE) {
                /*
                 * As per the Javadoc:
                 *
                 *      The option is ignored when the file system does not
                 *  support the creation of sparse files
                 */
                continue;
            } else {
                throw new IllegalArgumentException("newFileChannel(" + path + ") unsupported open option: " + option);
            }
        }
        if (modes.isEmpty()) {
            modes.add(SftpClient.OpenMode.Read);
            modes.add(SftpClient.OpenMode.Write);
        }
        // TODO: attrs
        return new SftpFileChannel(toSftpPath(path), modes);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        final SftpPath p = toSftpPath(dir);
        return new SftpDirectoryStream(p);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        SftpPath p = toSftpPath(dir);
        SftpFileSystem fs = p.getFileSystem();
        if (log.isDebugEnabled()) {
            log.debug("createDirectory({}) {} ({})", fs, dir, Arrays.asList(attrs));
        }
        try (SftpClient sftp = fs.getClient()) {
            try {
                sftp.mkdir(dir.toString());
            } catch (SftpException e) {
                int sftpStatus = e.getStatus();
                if ((sftp.getVersion() == SftpConstants.SFTP_V3) && (sftpStatus == SftpConstants.SSH_FX_FAILURE)) {
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

        SftpFileSystem fs = p.getFileSystem();
        if (log.isDebugEnabled()) {
            log.debug("delete({}) {}", fs, path);
        }

        try (SftpClient sftp = fs.getClient()) {
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
            throw new ProviderMismatchException("Mismatched file system providers for " + src + " vs. " + dst);
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
        BasicFileAttributes attrs = readAttributes(source, BasicFileAttributes.class, linkOptions);
        if (attrs.isSymbolicLink()) {
            throw new IOException("Copying of symbolic links not supported");
        }

        // delete target if it exists and REPLACE_EXISTING is specified
        Boolean status = IoUtils.checkFileExists(target, linkOptions);
        if (status == null) {
            throw new AccessDeniedException("Existence cannot be determined for copy target: " + target);
        }

        if (log.isDebugEnabled()) {
            log.debug("copy({})[{}] {} => {}", src.getFileSystem(), Arrays.asList(options), src, dst);
        }

        if (replaceExisting) {
            deleteIfExists(target);
        } else {
            if (status) {
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
                view.setTimes(attrs.lastModifiedTime(), attrs.lastAccessTime(), attrs.creationTime());
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
        SftpFileSystem fsSrc = src.getFileSystem();
        SftpPath dst = toSftpPath(target);

        if (src.getFileSystem() != dst.getFileSystem()) {
            throw new ProviderMismatchException("Mismatched file system providers for " + src + " vs. " + dst);
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
        BasicFileAttributes attrs = readAttributes(source, BasicFileAttributes.class, linkOptions);
        if (attrs.isSymbolicLink()) {
            throw new IOException("Moving of source symbolic link (" + source + ") to " + target + " not supported");
        }

        // delete target if it exists and REPLACE_EXISTING is specified
        Boolean status = IoUtils.checkFileExists(target, linkOptions);
        if (status == null) {
            throw new AccessDeniedException("Existence cannot be determined for move target " + target);
        }

        if (log.isDebugEnabled()) {
            log.debug("move({})[{}] {} => {}", src.getFileSystem(), Arrays.asList(options), src, dst);
        }

        if (replaceExisting) {
            deleteIfExists(target);
        } else if (status) {
            throw new FileAlreadyExistsException(target.toString());
        }

        try (SftpClient sftp = fsSrc.getClient()) {
            sftp.rename(src.toString(), dst.toString());
        }

        // copy basic attributes to target
        if (copyAttributes) {
            BasicFileAttributeView view = getFileAttributeView(target, BasicFileAttributeView.class, linkOptions);
            try {
                view.setTimes(attrs.lastModifiedTime(), attrs.lastAccessTime(), attrs.creationTime());
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
            throw new ProviderMismatchException("Mismatched file system providers for " + p1 + " vs. " + p2);
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
        FileSystem fs = path.getFileSystem();
        if (!(fs instanceof SftpFileSystem)) {
            throw new FileSystemException(path.toString(), path.toString(), "getFileStore(" + path + ") path not attached to an SFTP file system");
        }

        SftpFileSystem sftpFs = (SftpFileSystem) fs;
        String id = sftpFs.getId();
        SftpFileSystem cached = getFileSystem(id);
        if (cached != sftpFs) {
            throw new FileSystemException(path.toString(), path.toString(), "Mismatched file system instance for id=" + id);
        }

        return sftpFs.getFileStores().get(0);
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        SftpPath l = toSftpPath(link);
        SftpFileSystem fsLink = l.getFileSystem();
        SftpPath t = toSftpPath(target);
        if (fsLink != t.getFileSystem()) {
            throw new ProviderMismatchException("Mismatched file system providers for " + l + " vs. " + t);
        }

        if (log.isDebugEnabled()) {
            log.debug("createSymbolicLink({})[{}] {} => {}", fsLink, Arrays.asList(attrs), link, target);
        }

        try (SftpClient client = fsLink.getClient()) {
            client.symLink(l.toString(), t.toString());
        }
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        SftpPath l = toSftpPath(link);
        SftpFileSystem fsLink = l.getFileSystem();
        try (SftpClient client = fsLink.getClient()) {
            String linkPath = client.readLink(l.toString());
            if (log.isDebugEnabled()) {
                log.debug("readSymbolicLink({})[{}] {} => {}", fsLink, link, linkPath);
            }

            return fsLink.getPath(linkPath);
        }
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        SftpPath p = toSftpPath(path);
        boolean w = false;
        boolean x = false;
        if (GenericUtils.length(modes) > 0) {
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
        }

        BasicFileAttributes attrs = getFileAttributeView(p, BasicFileAttributeView.class).readAttributes();
        if ((attrs == null) && !(p.isAbsolute() && p.getNameCount() == 0)) {
            throw new NoSuchFileException(path.toString());
        }

        SftpFileSystem fs = p.getFileSystem();
        if (x || (w && fs.isReadOnly())) {
            throw new AccessDeniedException("Filesystem is read-only: " + path.toString());
        }
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, final LinkOption... options) {
        if (isSupportedFileAttributeView(path, type)) {
            if (AclFileAttributeView.class.isAssignableFrom(type)) {
                return type.cast(new SftpAclFileAttributeView(this, path, options));
            } else if (BasicFileAttributeView.class.isAssignableFrom(type)) {
                return type.cast(new SftpPosixFileAttributeView(this, path, options));
            }
        }

        throw new UnsupportedOperationException("getFileAttributeView(" + path + ") view not supported: " + type.getSimpleName());
    }

    public boolean isSupportedFileAttributeView(Path path, Class<? extends FileAttributeView> type) {
        return isSupportedFileAttributeView(toSftpPath(path).getFileSystem(), type);
    }

    public boolean isSupportedFileAttributeView(SftpFileSystem fs, Class<? extends FileAttributeView> type) {
        Collection<String> views = fs.supportedFileAttributeViews();
        if ((type == null) || GenericUtils.isEmpty(views)) {
            return false;
        } else if (PosixFileAttributeView.class.isAssignableFrom(type)) {
            return views.contains("posix");
        } else if (AclFileAttributeView.class.isAssignableFrom(type)) {
            return views.contains("acl");   // must come before owner view
        } else if (FileOwnerAttributeView.class.isAssignableFrom(type)) {
            return views.contains("owner");
        } else if (BasicFileAttributeView.class.isAssignableFrom(type)) {
            return views.contains("basic"); // must be last
        } else {
            return false;
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

        return readAttributes(path, view, attrs, options);
    }

    public Map<String, Object> readAttributes(Path path, String view, String attrs, LinkOption... options) throws IOException {
        SftpPath p = toSftpPath(path);
        SftpFileSystem fs = p.getFileSystem();
        Collection<String> views = fs.supportedFileAttributeViews();
        if (GenericUtils.isEmpty(views) || (!views.contains(view))) {
            throw new UnsupportedOperationException("readAttributes(" + path + ")[" + view + ":" + attrs + "] view not supported: " + views);
        }

        if ("basic".equalsIgnoreCase(view) || "posix".equalsIgnoreCase(view) || "owner".equalsIgnoreCase(view)) {
            return readPosixViewAttributes(p, view, attrs, options);
        } else if ("acl".equalsIgnoreCase(view)) {
            return readAclViewAttributes(p, view, attrs, options);
        } else  {
            return readCustomViewAttributes(p, view, attrs, options);
        }
    }

    protected Map<String, Object> readCustomViewAttributes(SftpPath path, String view, String attrs, LinkOption... options) throws IOException {
        throw new UnsupportedOperationException("readCustomViewAttributes(" + path + ")[" + view + ":" + attrs + "] view not supported");
    }

    protected Map<String, Object> readAclViewAttributes(SftpPath path, String view, String attrs, LinkOption... options) throws IOException {
        if ("*".equals(attrs)) {
            attrs = "acl,owner";
        }

        SftpFileSystem fs = path.getFileSystem();
        SftpClient.Attributes attributes;
        try (SftpClient client = fs.getClient()) {
            attributes = readRemoteAttributes(path, options);
        }

        Map<String, Object> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String attr : attrs.split(",")) {
            switch (attr) {
                case "acl":
                    List<AclEntry> acl = attributes.getAcl();
                    if (acl != null) {
                        map.put(attr, acl);
                    }
                    break;
                case "owner":
                    String owner = attributes.getOwner();
                    if (GenericUtils.length(owner) > 0) {
                        map.put(attr, new SftpFileSystem.DefaultUserPrincipal(owner));
                    }
                    break;
                default:
                    if (log.isTraceEnabled()) {
                        log.trace("readAclViewAttributes({})[{}] unknown attribute: {}", fs, attrs, attr);
                    }
            }
        }

        return map;
    }

    protected SftpClient.Attributes readRemoteAttributes(SftpPath path, LinkOption... options) throws IOException {
        SftpFileSystem fs = path.getFileSystem();
        try (SftpClient client = fs.getClient()) {
            try {
                SftpClient.Attributes attrs;
                if (IoUtils.followLinks(options)) {
                    attrs = client.stat(path.toString());
                } else {
                    attrs = client.lstat(path.toString());
                }
                if (log.isTraceEnabled()) {
                    log.trace("readRemoteAttributes({})[{}]: {}", fs, path, attrs);
                }
                return attrs;
            } catch (SftpException e) {
                if (e.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                    throw new NoSuchFileException(path.toString());
                }
                throw e;
            }
        }
    }

    protected Map<String, Object> readPosixViewAttributes(SftpPath path, String view, String attrs, LinkOption... options) throws IOException {
        PosixFileAttributes v = readAttributes(path, PosixFileAttributes.class, options);
        if ("*".equals(attrs)) {
            attrs = "lastModifiedTime,lastAccessTime,creationTime,size,isRegularFile,isDirectory,isSymbolicLink,isOther,fileKey,owner,permissions,group";
        }

        Map<String, Object> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
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
                default:
                    if (log.isTraceEnabled()) {
                        log.trace("readPosixViewAttributes({})[{}:{}] ignored for {}", path, view, attr, attrs);
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

        setAttribute(path, view, attr, value, options);
    }

    public void setAttribute(Path path, String view, String attr, Object value, LinkOption... options) throws IOException {
        SftpPath p = toSftpPath(path);
        SftpFileSystem fs = p.getFileSystem();
        Collection<String> views = fs.supportedFileAttributeViews();
        if (GenericUtils.isEmpty(views) || (!views.contains(view))) {
            throw new UnsupportedOperationException("setAttribute(" + path + ")[" + view + ":" + attr + "=" + value + "] view " + view + " not supported: " + views);
        }

        SftpClient.Attributes attributes = new SftpClient.Attributes();
        switch (attr) {
            case "lastModifiedTime":
                attributes.modifyTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "lastAccessTime":
                attributes.accessTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "creationTime":
                attributes.createTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case "size":
                attributes.size(((Number) value).longValue());
                break;
            case "permissions":
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission> attrSet = (Set<PosixFilePermission>) value;
                attributes.perms(attributesToPermissions(path, attrSet));
                break;
            case "owner":
                attributes.owner(((UserPrincipal) value).getName());
                break;
            case "group":
                attributes.group(((GroupPrincipal) value).getName());
                break;
            case "acl":
                ValidateUtils.checkTrue("acl".equalsIgnoreCase(view), "ACL cannot be set via view=%s", view);
                @SuppressWarnings("unchecked")
                List<AclEntry> acl = (List<AclEntry>) value;
                attributes.acl(acl);
                break;
            case "isRegularFile":
            case "isDirectory":
            case "isSymbolicLink":
            case "isOther":
            case "fileKey":
                throw new UnsupportedOperationException("setAttribute(" + path + ")[" + view + ":" + attr + "=" + value + "] modification N/A");
            default:
                if (log.isTraceEnabled()) {
                    log.trace("setAttribute({})[{}] ignore {}:{}={}", fs, path, view, attr, value);
                }
        }

        if (log.isDebugEnabled()) {
            log.debug("setAttribute({}) {}: {}", fs, path, attributes);
        }

        try (SftpClient client = fs.getClient()) {
            client.setStat(p.toString(), attributes);
        }
    }

    public SftpPath toSftpPath(Path path) {
        ValidateUtils.checkNotNull(path, "No path provided");
        if (!(path instanceof SftpPath)) {
            throw new ProviderMismatchException("Path is not SFTP: " + path);
        }
        return (SftpPath) path;
    }

    protected int attributesToPermissions(Path path, Collection<PosixFilePermission> perms) {
        if (GenericUtils.isEmpty(perms)) {
            return 0;
        }

        int pf = 0;
        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                    pf |= SftpConstants.S_IRUSR;
                    break;
                case OWNER_WRITE:
                    pf |= SftpConstants.S_IWUSR;
                    break;
                case OWNER_EXECUTE:
                    pf |= SftpConstants.S_IXUSR;
                    break;
                case GROUP_READ:
                    pf |= SftpConstants.S_IRGRP;
                    break;
                case GROUP_WRITE:
                    pf |= SftpConstants.S_IWGRP;
                    break;
                case GROUP_EXECUTE:
                    pf |= SftpConstants.S_IXGRP;
                    break;
                case OTHERS_READ:
                    pf |= SftpConstants.S_IROTH;
                    break;
                case OTHERS_WRITE:
                    pf |= SftpConstants.S_IWOTH;
                    break;
                case OTHERS_EXECUTE:
                    pf |= SftpConstants.S_IXOTH;
                    break;
                default:
                    if (log.isTraceEnabled()) {
                        log.trace("attributesToPermissions(" + path + ") ignored " + p);
                    }
            }
        }

        return pf;
    }

    public static String getRWXPermissions(int perms) {
        StringBuilder sb = new StringBuilder(10 /* 3 * rwx + (d)irectory */);
        if ((perms & SftpConstants.S_IFLNK) == SftpConstants.S_IFLNK) {
            sb.append('l');
        } else if ((perms & SftpConstants.S_IFDIR) == SftpConstants.S_IFDIR) {
            sb.append('d');
        } else {
            sb.append('-');
        }

        if ((perms & SftpConstants.S_IRUSR) == SftpConstants.S_IRUSR) {
            sb.append('r');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IWUSR) == SftpConstants.S_IWUSR) {
            sb.append('w');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IXUSR) == SftpConstants.S_IXUSR) {
            sb.append('x');
        } else {
            sb.append('-');
        }

        if ((perms & SftpConstants.S_IRGRP) == SftpConstants.S_IRGRP) {
            sb.append('r');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IWGRP) == SftpConstants.S_IWGRP) {
            sb.append('w');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IXGRP) == SftpConstants.S_IXGRP) {
            sb.append('x');
        } else {
            sb.append('-');
        }

        if ((perms & SftpConstants.S_IROTH) == SftpConstants.S_IROTH) {
            sb.append('r');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IWOTH) == SftpConstants.S_IWOTH) {
            sb.append('w');
        } else {
            sb.append('-');
        }
        if ((perms & SftpConstants.S_IXOTH) == SftpConstants.S_IXOTH) {
            sb.append('x');
        } else {
            sb.append('-');
        }

        return sb.toString();
    }

    public static String getOctalPermissions(int perms) {
        return getOctalPermissions(permissionsToAttributes(perms));
    }

    public static Set<PosixFilePermission> permissionsToAttributes(int perms) {
        Set<PosixFilePermission> p = new HashSet<>();
        if ((perms & SftpConstants.S_IRUSR) == SftpConstants.S_IRUSR) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & SftpConstants.S_IWUSR) == SftpConstants.S_IWUSR) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & SftpConstants.S_IXUSR) == SftpConstants.S_IXUSR) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & SftpConstants.S_IRGRP) == SftpConstants.S_IRGRP) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & SftpConstants.S_IWGRP) == SftpConstants.S_IWGRP) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & SftpConstants.S_IXGRP) == SftpConstants.S_IXGRP) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & SftpConstants.S_IROTH) == SftpConstants.S_IROTH) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & SftpConstants.S_IWOTH) == SftpConstants.S_IWOTH) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & SftpConstants.S_IXOTH) == SftpConstants.S_IXOTH) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }
        return p;
    }

    public static String getOctalPermissions(Collection<PosixFilePermission> perms) {
        int pf = 0;

        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                    pf |= SftpConstants.S_IRUSR;
                    break;
                case OWNER_WRITE:
                    pf |= SftpConstants.S_IWUSR;
                    break;
                case OWNER_EXECUTE:
                    pf |= SftpConstants.S_IXUSR;
                    break;
                case GROUP_READ:
                    pf |= SftpConstants.S_IRGRP;
                    break;
                case GROUP_WRITE:
                    pf |= SftpConstants.S_IWGRP;
                    break;
                case GROUP_EXECUTE:
                    pf |= SftpConstants.S_IXGRP;
                    break;
                case OTHERS_READ:
                    pf |= SftpConstants.S_IROTH;
                    break;
                case OTHERS_WRITE:
                    pf |= SftpConstants.S_IWOTH;
                    break;
                case OTHERS_EXECUTE:
                    pf |= SftpConstants.S_IXOTH;
                    break;
                default:    // ignored
            }
        }

        return String.format("%04o", pf);
    }

    /**
     * Uses the host, port and username to create a unique identifier
     *
     * @param uri The {@link URI} - <B>Note:</B> not checked to make sure
     *            that the scheme is {@code sftp://}
     * @return The unique identifier
     * @see #getFileSystemIdentifier(String, int, String)
     */
    public static String getFileSystemIdentifier(URI uri) {
        String userInfo = ValidateUtils.checkNotNullAndNotEmpty(uri.getUserInfo(), "UserInfo not provided");
        String[] ui = GenericUtils.split(userInfo, ':');
        ValidateUtils.checkTrue(GenericUtils.length(ui) == 2, "Invalid user info: %s", userInfo);
        return getFileSystemIdentifier(uri.getHost(), uri.getPort(), ui[0]);
    }

    /**
     * Uses the remote host address, port and current username to create a unique identifier
     *
     * @param session The {@link ClientSession}
     * @return The unique identifier
     * @see #getFileSystemIdentifier(String, int, String)
     */
    public static String getFileSystemIdentifier(ClientSession session) {
        IoSession ioSession = session.getIoSession();
        SocketAddress addr = ioSession.getRemoteAddress();
        String username = session.getUsername();
        if (addr instanceof InetSocketAddress) {
            InetSocketAddress inetAddr = (InetSocketAddress) addr;
            return getFileSystemIdentifier(inetAddr.getHostString(), inetAddr.getPort(), username);
        } else {
            return getFileSystemIdentifier(addr.toString(), SshConfigFileReader.DEFAULT_PORT, username);
        }
    }

    public static String getFileSystemIdentifier(String host, int port, String username) {
        return GenericUtils.trimToEmpty(host) + ':'
                + ((port <= 0) ? SshConfigFileReader.DEFAULT_PORT : port) + ':'
                + GenericUtils.trimToEmpty(username);
    }

    public static URI createFileSystemURI(String host, int port, String username, String password) {
        return createFileSystemURI(host, port, username, password, Collections.<String, Object>emptyMap());
    }

    public static URI createFileSystemURI(String host, int port, String username, String password, Map<String, ?> params) {
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
        sb.append(SftpConstants.SFTP_SUBSYSTEM_NAME)
            .append("://").append(username).append(':').append(password)
            .append('@').append(host).append(':').append(port)
            .append('/');
        if (GenericUtils.size(params) > 0) {
            boolean firstParam = true;
            for (Map.Entry<String, ?> pe : params.entrySet()) {
                String key = pe.getKey();
                Object value = pe.getValue();
                sb.append(firstParam ? '?' : '&').append(key).append('=').append(Objects.toString(value, null));
                firstParam = false;
            }
        }

        return URI.create(sb.toString());
    }
}
