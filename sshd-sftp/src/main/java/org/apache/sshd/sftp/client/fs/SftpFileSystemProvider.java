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

package org.apache.sshd.sftp.client.fs;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
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
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.BasicCredentialsImpl;
import org.apache.sshd.common.auth.BasicCredentialsProvider;
import org.apache.sshd.common.auth.MutableBasicCredentials;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpErrorDataHandler;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.client.extensions.CopyFileExtension;
import org.apache.sshd.sftp.client.impl.SftpRemotePathChannel;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A registered {@link FileSystemProvider} that registers the &quot;sftp://&quot; scheme so that URLs with this protocol
 * are handled as remote SFTP {@link Path}-s - e.g., &quot;{@code sftp://user:password@host/remote/file/path}&quot;
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpFileSystemProvider extends FileSystemProvider {

    /**
     * <P>
     * URI parameter that can be used to specify a special version selection. Options are:
     * </P>
     * <UL>
     * <LI>{@code max} - select maximum available version for the client</LI>
     * <LI>{@code min} - select minimum available version for the client</LI>
     * <LI>{@code current} - whatever version is reported by the server</LI>
     * <LI>{@code nnn} - select <U>only</U> the specified version</LI>
     * <LI>{@code a,b,c} - select one of the specified versions (if available) in preference order</LI>
     * </UL>
     */
    public static final String VERSION_PARAM = "version";

    public static final Set<Class<? extends FileAttributeView>> UNIVERSAL_SUPPORTED_VIEWS = Collections.unmodifiableSet(
            GenericUtils.asSet(
                    PosixFileAttributeView.class,
                    FileOwnerAttributeView.class,
                    BasicFileAttributeView.class));

    protected final Logger log;

    private final SshClient clientInstance;
    private final SftpClientFactory factory;
    private final SftpVersionSelector versionSelector;
    private final SftpErrorDataHandler errorDataHandler;
    private final NavigableMap<String, SftpFileSystem> fileSystems = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private SftpFileSystemClientSessionInitializer fsSessionInitializer = SftpFileSystemClientSessionInitializer.DEFAULT;

    public SftpFileSystemProvider() {
        this((SshClient) null);
    }

    public SftpFileSystemProvider(SftpVersionSelector selector) {
        this(null, selector);
    }

    public SftpFileSystemProvider(SshClient client) {
        this(client, SftpVersionSelector.CURRENT);
    }

    public SftpFileSystemProvider(SshClient client, SftpVersionSelector selector) {
        this(client, selector, SftpErrorDataHandler.EMPTY);
    }

    public SftpFileSystemProvider(SshClient client, SftpVersionSelector selector, SftpErrorDataHandler errorDataHandler) {
        this(client, null, selector, errorDataHandler);

    }

    public SftpFileSystemProvider(SshClient client, SftpClientFactory factory, SftpVersionSelector selector) {
        this(client, factory, selector, SftpErrorDataHandler.EMPTY);
    }

    /**
     * @param client           The {@link SshClient} to use - if {@code null} then a default one will be setup and
     *                         started. Otherwise, it is assumed that the client has already been started
     * @param factory          The {@link SftpClientFactory} to use to generate SFTP client instances
     * @param selector         The {@link SftpVersionSelector} to use in order to negotiate the SFTP version
     * @param errorDataHandler The {@link SftpErrorDataHandler} to handle incoming data through the error stream - if
     *                         {@code null} the data is silently ignored
     * @see                    SshClient#setUpDefaultClient()
     */
    public SftpFileSystemProvider(SshClient client, SftpClientFactory factory,
                                  SftpVersionSelector selector, SftpErrorDataHandler errorDataHandler) {
        this.log = LoggerFactory.getLogger(getClass());
        this.factory = factory;
        this.versionSelector = selector;
        this.errorDataHandler = errorDataHandler;
        if (client == null) {
            // TODO: make this configurable using system properties
            client = SshClient.setUpDefaultClient();
            client.start();
        }
        this.clientInstance = client;
    }

    @Override
    public String getScheme() {
        return SftpConstants.SFTP_SUBSYSTEM_NAME;
    }

    public final SftpVersionSelector getSftpVersionSelector() {
        return versionSelector;
    }

    public SftpErrorDataHandler getSftpErrorDataHandler() {
        return errorDataHandler;
    }

    public final SshClient getClientInstance() {
        return clientInstance;
    }

    public SftpClientFactory getSftpClientFactory() {
        return factory;
    }

    public SftpFileSystemClientSessionInitializer getSftpFileSystemClientSessionInitializer() {
        return fsSessionInitializer;
    }

    public void setSftpFileSystemClientSessionInitializer(SftpFileSystemClientSessionInitializer initializer) {
        fsSessionInitializer = Objects.requireNonNull(initializer, "No initializer provided");
    }

    @Override // NOTE: co-variant return
    public SftpFileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        String host = ValidateUtils.checkNotNullAndNotEmpty(uri.getHost(), "Host not provided");
        int port = uri.getPort();
        if (port <= 0) {
            port = SshConstants.DEFAULT_PORT;
        }

        BasicCredentialsProvider credentials = parseCredentials(uri);
        ValidateUtils.checkState(credentials != null, "No credentials provided");

        String username = credentials.getUsername();
        String id = getFileSystemIdentifier(host, port, username);
        SftpFileSystemInitializationContext context = new SftpFileSystemInitializationContext(id, uri, env);
        context.setHost(host);
        context.setPort(port);
        context.setCredentials(credentials);

        Map<String, Object> params = resolveFileSystemParameters(env, parseURIParameters(uri));
        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(params);
        context.setPropertyResolver(resolver);
        context.setMaxConnectTime(SftpModuleProperties.CONNECT_TIME.getRequired(resolver));
        context.setMaxAuthTime(SftpModuleProperties.AUTH_TIME.getRequired(resolver));

        SftpVersionSelector selector = resolveSftpVersionSelector(uri, getSftpVersionSelector(), resolver);
        SftpErrorDataHandler errorHandler = resolveSftpErrorDataHandler(uri, getSftpErrorDataHandler(), resolver);
        Charset decodingCharset = SftpModuleProperties.NAME_DECODER_CHARSET.getRequired(resolver);

        SftpFileSystemClientSessionInitializer initializer = getSftpFileSystemClientSessionInitializer();
        SftpFileSystem fileSystem = null;
        synchronized (fileSystems) {
            if (fileSystems.containsKey(id)) {
                throw new FileSystemAlreadyExistsException(id);
            }

            SessionProvider sessionProvider = new SessionProvider(context, params, decodingCharset);
            try {
                fileSystem = initializer.createSftpFileSystem(this, context, sessionProvider, selector, errorHandler);
                fileSystems.put(id, fileSystem);
            } catch (Exception e) {
                if (fileSystem != null) {
                    try {
                        fileSystem.close();
                    } catch (IOException t) {
                        e.addSuppressed(t);
                        LoggingUtils.debug(log,
                                "Failed ({}) to close new failed file system on {}}:{} due to {}[{}]: {}",
                                t.getClass().getSimpleName(), host, port, e.getClass().getSimpleName(), e.getMessage(),
                                t.getMessage(),
                                t);
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

        Integer bs = SftpModuleProperties.READ_BUFFER_SIZE.getOrNull(resolver);
        if (bs != null) {
            fileSystem.setReadBufferSize(bs);
        }
        bs = SftpModuleProperties.WRITE_BUFFER_SIZE.getOrNull(resolver);
        if (bs != null) {
            fileSystem.setWriteBufferSize(bs);
        }
        if (log.isDebugEnabled()) {
            log.debug("newFileSystem({}): {}", uri.toASCIIString(), fileSystem);
        }
        return fileSystem;
    }

    /**
     * A session provider that automatically creates a new session if the current one is no longer open (or if there
     * isn't one yet). It returns fully authenticated sessions.
     */
    private class SessionProvider implements IOFunction<Boolean, ClientSession> {

        private final SftpFileSystemInitializationContext context;

        private final Map<String, ?> params;

        private final Charset decodingCharset;

        private AtomicReference<ClientSession> currentSession = new AtomicReference<>();

        SessionProvider(SftpFileSystemInitializationContext context, Map<String, ?> params, Charset decodingCharset) {
            this.context = Objects.requireNonNull(context);
            this.params = Objects.requireNonNull(params);
            this.decodingCharset = Objects.requireNonNull(decodingCharset);
        }

        /**
         * Retrieves the current {@link ClientSession} and optionally creates a new one if there is no current session
         * yet, or if it is not open.
         *
         * @param create {@link Boolean#TRUE} to create a new session if needed, otherwise just query the current
         *               session.
         */
        @Override
        public ClientSession apply(Boolean create) throws IOException {
            synchronized (this) {
                ClientSession session = currentSession.get();
                if ((session == null || !session.isOpen()) && Boolean.TRUE.equals(create)) {
                    session = create();
                    currentSession.set(session);
                }
                return session;
            }
        }

        private ClientSession create() throws IOException {
            SftpFileSystemClientSessionInitializer initializer = getSftpFileSystemClientSessionInitializer();
            ClientSession session = null;
            try {
                session = initializer.createClientSession(SftpFileSystemProvider.this, context);
                ClientSession mySelf = session;

                // Make any extra configuration parameters available to the session
                params.forEach((key, value) -> {
                    if (!VERSION_PARAM.equalsIgnoreCase(key)) {
                        PropertyResolverUtils.updateProperty(mySelf, key, value);
                    }
                });
                SftpModuleProperties.NAME_DECODING_CHARSET.set(session, decodingCharset);

                initializer.authenticateClientSession(SftpFileSystemProvider.this, context, session);

                session.setAttribute(SftpFileSystem.OWNED_SESSION, Boolean.TRUE);
                session.addSessionListener(new SessionListener() {

                    @Override
                    public void sessionClosed(Session s) {
                        if (mySelf == s) {
                            currentSession.compareAndSet(mySelf, null);
                        }
                    }
                });
                return session;
            } catch (Exception e) {
                if (session != null) {
                    try {
                        session.close();
                    } catch (IOException t) {
                        e.addSuppressed(t);
                        LoggingUtils.debug(log, "Failed ({}) to close session for new file system on {}}:{} due to {}[{}]: {}",
                                t.getClass().getSimpleName(), context.getHost(), context.getPort(),
                                e.getClass().getSimpleName(), e.getMessage(), t.getMessage(), t);
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

    }

    protected SftpVersionSelector resolveSftpVersionSelector(
            URI uri, SftpVersionSelector defaultSelector, PropertyResolver resolver) {
        String preference = resolver.getString(VERSION_PARAM);
        if (GenericUtils.isEmpty(preference)) {
            return defaultSelector;
        }

        if (log.isDebugEnabled()) {
            log.debug("resolveSftpVersionSelector({}) preference={}", uri, preference);
        }

        // These are aliases for shorter parameters specification
        if ("max".equalsIgnoreCase(preference)) {
            return SftpVersionSelector.MAXIMUM;
        } else if ("min".equalsIgnoreCase(preference)) {
            return SftpVersionSelector.MINIMUM;
        } else {
            return SftpVersionSelector.resolveVersionSelector(preference);
        }
    }

    protected SftpErrorDataHandler resolveSftpErrorDataHandler(
            URI uri, SftpErrorDataHandler errorHandler, PropertyResolver resolver) {
        return errorHandler;
    }

    // NOTE: URI parameters override environment ones
    public static Map<String, Object> resolveFileSystemParameters(Map<String, ?> env, Map<String, Object> uriParams) {
        if (MapEntryUtils.isEmpty(env)) {
            return MapEntryUtils.isEmpty(uriParams) ? Collections.emptyMap() : uriParams;
        } else if (MapEntryUtils.isEmpty(uriParams)) {
            return Collections.unmodifiableMap(env);
        }

        Map<String, Object> resolved = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        resolved.putAll(env);
        resolved.putAll(uriParams);
        return resolved;
    }

    /**
     * Attempts to parse the user information from the URI
     *
     * @param  uri The {@link URI} value - ignored if {@code null} or does not contain any {@link URI#getUserInfo() user
     *             info}.
     * @return     The parsed credentials - {@code null} if none available
     */
    public static MutableBasicCredentials parseCredentials(URI uri) {
        return parseCredentials((uri == null) ? "" : uri.getUserInfo());
    }

    public static MutableBasicCredentials parseCredentials(String userInfo) {
        if (GenericUtils.isEmpty(userInfo)) {
            return null;
        }

        int pos = userInfo.indexOf(':');
        if (pos < 0) {
            return new BasicCredentialsImpl(userInfo, null); // assume password-less login
        }

        return new BasicCredentialsImpl(userInfo.substring(0, pos), userInfo.substring(pos + 1));
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
        Map<String, Object> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String p : pairs) {
            int pos = p.indexOf('=');
            if (pos < 0) {
                map.put(p, Boolean.TRUE);
                continue;
            }

            String key = p.substring(0, pos);
            String value = p.substring(pos + 1);
            if (NumberUtils.isIntegerNumber(value)) {
                map.put(key, Long.valueOf(value));
            } else if ("true".equals(value) || "false".equals("value")) {
                map.put(key, Boolean.valueOf(value));
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
            fileSystem = new SftpFileSystem(this, id, session, factory, getSftpVersionSelector(), getSftpErrorDataHandler());
            fileSystems.put(id, fileSystem);
        }

        Integer rbs = session.getInteger(SftpModuleProperties.READ_BUFFER_SIZE.getName());
        if (rbs != null) {
            fileSystem.setReadBufferSize(rbs);
        }
        Integer wbs = session.getInteger(SftpModuleProperties.WRITE_BUFFER_SIZE.getName());
        if (wbs != null) {
            fileSystem.setWriteBufferSize(wbs);
        }
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
     * @param  id File system identifier - ignored if {@code null}/empty
     * @return    The removed {@link SftpFileSystem} - {@code null} if no match
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
     * @param  id File system identifier - ignored if {@code null}/empty
     * @return    The cached {@link SftpFileSystem} - {@code null} if no match
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
    public FileChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        return newFileChannel(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        Set<OpenMode> modes = OpenMode.fromOpenOptions(options);
        boolean readable = modes.contains(OpenMode.Read);
        boolean writable = modes.contains(OpenMode.Write) || modes.contains(OpenMode.Append);
        if (!readable && !writable) {
            // As per {@link FileChannel#open(Path,Set,FileAttribute[])}: Read is default unless Write or Append are
            // given. Other flags do imply write access, but Java does not supply write access by default for them.
            modes.add(OpenMode.Read);
        } else if (modes.contains(OpenMode.Append)) {
            // As per {@link FileChannel#open(Path,Set,FileAttribute[])}: Append + Truncate or Append + Read are not
            // allowed.
            if (modes.contains(OpenMode.Truncate)) {
                throw new IllegalArgumentException("APPEND + TRUNCATE_EXISTING not allowed");
            } else if (modes.contains(OpenMode.Read)) {
                throw new IllegalArgumentException("APPEND + READ not allowed");
            }
        }
        if (!writable) {
            // As per {@link FileChannel#open(Path,Set,FileAttribute[])}: Truncate, Create, and Create_New are ignored
            // if opening read-only.
            modes.remove(OpenMode.Truncate);
            modes.remove(OpenMode.Create);
            modes.remove(OpenMode.Exclusive);
        }
        // TODO: process file attributes
        SftpPath p = toSftpPath(path);
        return new SftpRemotePathChannel(p.toString(), p.getFileSystem().getClient(), true, modes);
    }

    @Override
    public InputStream newInputStream(Path path, OpenOption... options) throws IOException {
        Set<OpenMode> modes = OpenMode.fromOpenOptions(Arrays.asList(options));
        if (modes.contains(OpenMode.Write) || modes.contains(OpenMode.Append)) {
            throw new IllegalArgumentException("WRITE or APPEND not allowed");
        }
        // As per {@link FileChannel#open(Path,Set,FileAttribute[])}: Truncate, Create, and Create_New are ignored
        // if opening read-only. Which leaves only Read.
        modes = EnumSet.of(OpenMode.Read);
        SftpPath p = toSftpPath(path);
        SftpClient client = p.getFileSystem().getClient();
        try {
            SftpClient inner = client;
            InputStream result = new FilterInputStream(client.read(p.toString(), modes)) {
                @Override
                public void close() throws IOException {
                    try {
                        super.close();
                    } finally {
                        inner.close();
                    }
                }
            };
            client = null; // Prevent closing in finally
            return result;
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Override
    public OutputStream newOutputStream(Path path, OpenOption... options) throws IOException {
        Set<OpenMode> modes = OpenMode.fromOpenOptions(Arrays.asList(options));
        if (modes.contains(OpenMode.Read)) {
            throw new IllegalArgumentException("READ not allowed");
        }
        if (modes.isEmpty()) {
            modes = EnumSet.of(OpenMode.Create, OpenMode.Truncate, OpenMode.Write);
        } else {
            // As per {@link FileChannel#open(Path,Set,FileAttribute[])}: Append + Truncate is not allowed.
            if (modes.contains(OpenMode.Append)) {
                if (modes.contains(OpenMode.Truncate)) {
                    throw new IllegalArgumentException("APPEND + TRUNCATE_EXISTING not allowed");
                }
            } else {
                modes.add(OpenMode.Write);
            }
        }
        SftpPath p = toSftpPath(path);
        SftpClient client = p.getFileSystem().getClient();
        try {
            SftpClient inner = client;
            OutputStream result = new FilterOutputStream(client.write(p.toString(), modes)) {

                @Override
                public void close() throws IOException {
                    try {
                        super.close();
                    } finally {
                        inner.close();
                    }
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    out.write(b, off, len);
                }
            };
            client = null; // Prevent closing in finally
            return result;
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        final SftpPath p = toSftpPath(dir);
        return new SftpDirectoryStream(p, filter);
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

        SftpFileSystem fs = p.getFileSystem();
        if (log.isDebugEnabled()) {
            log.debug("delete({}) {}", fs, path);
        }
        if (fs.isReadOnly()) {
            throw new AccessDeniedException("Filesystem is read-only: " + path.toString());
        }
        BasicFileAttributes attributes = readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        try (SftpClient sftp = fs.getClient()) {
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
        Boolean status = IoUtils.checkFileExistsAnySymlinks(target, noFollowLinks);
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
            try (SftpClient client = src.getFileSystem().getClient()) {
                CopyFileExtension copyFile = client.getExtension(CopyFileExtension.class);
                if (copyFile.isSupported()) {
                    copyFile.copyFile(source.toString(), target.toString(), false);
                } else {
                    try (InputStream in = newInputStream(source);
                         OutputStream os = newOutputStream(target)) {
                        IoUtils.copy(in, os);
                    }
                }
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
        Boolean status = IoUtils.checkFileExistsAnySymlinks(target, noFollowLinks);
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
            throw new FileSystemException(path.toString(), path.toString(),
                    "getFileStore(" + path + ") path not attached to an SFTP file system");
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
                log.debug("readSymbolicLink({}) {} => {}", fsLink, link, linkPath);
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

        throw new UnsupportedOperationException(
                "getFileAttributeView(" + path + ") view not supported: " + type.getSimpleName());
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
            return views.contains("acl"); // must come before owner view
        } else if (FileOwnerAttributeView.class.isAssignableFrom(type)) {
            return views.contains("owner");
        } else if (BasicFileAttributeView.class.isAssignableFrom(type)) {
            return views.contains("basic"); // must be last
        } else {
            return false;
        }
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options)
            throws IOException {
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
            throw new UnsupportedOperationException(
                    "readAttributes(" + path + ")[" + view + ":" + attrs + "] view not supported: " + views);
        }

        if ("basic".equalsIgnoreCase(view) || "posix".equalsIgnoreCase(view) || "owner".equalsIgnoreCase(view)) {
            return readPosixViewAttributes(p, view, attrs, options);
        } else if ("acl".equalsIgnoreCase(view)) {
            return readAclViewAttributes(p, view, attrs, options);
        } else {
            return readCustomViewAttributes(p, view, attrs, options);
        }
    }

    protected Map<String, Object> readCustomViewAttributes(SftpPath path, String view, String attrs, LinkOption... options)
            throws IOException {
        throw new UnsupportedOperationException(
                "readCustomViewAttributes(" + path + ")[" + view + ":" + attrs + "] view not supported");
    }

    protected NavigableMap<String, Object> readAclViewAttributes(
            SftpPath path, String view, String attrs, LinkOption... options)
            throws IOException {
        if ("*".equals(attrs)) {
            attrs = "acl,owner";
        }

        SftpFileSystem fs = path.getFileSystem();
        SftpClient.Attributes attributes;
        try (SftpClient client = fs.getClient()) {
            attributes = readRemoteAttributes(path, options);
        }

        NavigableMap<String, Object> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        String[] attrValues = GenericUtils.split(attrs, ',');
        boolean traceEnabled = log.isTraceEnabled();
        for (String attr : attrValues) {
            switch (attr) {
                case IoUtils.ACL_VIEW_ATTR: {
                    List<AclEntry> acl = attributes.getAcl();
                    if (acl != null) {
                        map.put(attr, acl);
                    }
                    break;
                }
                case IoUtils.OWNER_VIEW_ATTR: {
                    String owner = attributes.getOwner();
                    if (GenericUtils.length(owner) > 0) {
                        map.put(attr, new SftpFileSystem.DefaultUserPrincipal(owner));
                    }
                    break;
                }
                default:
                    if (traceEnabled) {
                        log.trace("readAclViewAttributes({})[{}] unknown attribute: {}", fs, attrs, attr);
                    }
            }
        }

        return map;
    }

    public SftpClient.Attributes readRemoteAttributes(SftpPath path, LinkOption... options) throws IOException {
        // Use the cache here. The cache scope clears cached attributes at the beginning and at the end of the outermost
        // SftpPathImpl.withAttributeCache() invocation. So we ensure here that if we are already within a caching
        // scope, we do use the cached attributes, but if we are not, we clear any possibly cached attributes and
        // do actually read them from the remote.
        return WithFileAttributeCache.withAttributeCache(path, p -> resolveRemoteFileAttributes(path, options));
    }

    protected SftpClient.Attributes resolveRemoteFileAttributes(SftpPath path, LinkOption... options) throws IOException {
        SftpClient.Attributes attributes = path.getAttributes();
        if (attributes != null) {
            return attributes;
        }
        SftpFileSystem fs = path.getFileSystem();
        try (SftpClient client = fs.getClient()) {
            SftpClient.Attributes attrs;
            if (IoUtils.followLinks(options)) {
                attrs = client.stat(path.toString());
            } else {
                attrs = client.lstat(path.toString());
            }
            if (log.isTraceEnabled()) {
                log.trace("resolveRemoteFileAttributes({})[{}]: {}", fs, path, attrs);
            }
            if (path instanceof WithFileAttributeCache) {
                ((WithFileAttributeCache) path).setAttributes(attrs);
            }
            return attrs;
        } catch (SftpException e) {
            if (e.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                NoSuchFileException toThrow = new NoSuchFileException(path.toString());
                toThrow.initCause(e);
                throw toThrow;
            }
            throw e;
        }
    }

    protected NavigableMap<String, Object> readPosixViewAttributes(
            SftpPath path, String view, String attrs, LinkOption... options)
            throws IOException {
        PosixFileAttributes v = readAttributes(path, PosixFileAttributes.class, options);
        if ("*".equals(attrs)) {
            attrs = IoUtils.LASTMOD_TIME_VIEW_ATTR
                    + "," + IoUtils.LASTACC_TIME_VIEW_ATTR
                    + "," + IoUtils.CREATE_TIME_VIEW_ATTR
                    + "," + IoUtils.SIZE_VIEW_ATTR
                    + "," + IoUtils.REGFILE_VIEW_ATTR
                    + "," + IoUtils.DIRECTORY_VIEW_ATTR
                    + "," + IoUtils.SYMLINK_VIEW_ATTR
                    + "," + IoUtils.OTHERFILE_VIEW_ATTR
                    + "," + IoUtils.FILEKEY_VIEW_ATTR
                    + "," + IoUtils.OWNER_VIEW_ATTR
                    + "," + IoUtils.GROUP_VIEW_ATTR
                    + "," + IoUtils.PERMISSIONS_VIEW_ATTR
                    + "," + IoUtils.FILEKEY_VIEW_ATTR;
        }

        NavigableMap<String, Object> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        boolean traceEnabled = log.isTraceEnabled();
        String[] attrValues = GenericUtils.split(attrs, ',');
        for (String attr : attrValues) {
            switch (attr) {
                case IoUtils.LASTMOD_TIME_VIEW_ATTR:
                    map.put(attr, v.lastModifiedTime());
                    break;
                case IoUtils.LASTACC_TIME_VIEW_ATTR:
                    map.put(attr, v.lastAccessTime());
                    break;
                case IoUtils.CREATE_TIME_VIEW_ATTR:
                    map.put(attr, v.creationTime());
                    break;
                case IoUtils.SIZE_VIEW_ATTR:
                    map.put(attr, v.size());
                    break;
                case IoUtils.REGFILE_VIEW_ATTR:
                    map.put(attr, v.isRegularFile());
                    break;
                case IoUtils.DIRECTORY_VIEW_ATTR:
                    map.put(attr, v.isDirectory());
                    break;
                case IoUtils.SYMLINK_VIEW_ATTR:
                    map.put(attr, v.isSymbolicLink());
                    break;
                case IoUtils.OTHERFILE_VIEW_ATTR:
                    map.put(attr, v.isOther());
                    break;
                case IoUtils.FILEKEY_VIEW_ATTR:
                    map.put(attr, v.fileKey());
                    break;
                case IoUtils.OWNER_VIEW_ATTR:
                    map.put(attr, v.owner());
                    break;
                case IoUtils.PERMISSIONS_VIEW_ATTR:
                    map.put(attr, v.permissions());
                    break;
                case IoUtils.GROUP_VIEW_ATTR:
                    map.put(attr, v.group());
                    break;
                default:
                    if (traceEnabled) {
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
            throw new UnsupportedOperationException(
                    "setAttribute(" + path + ")[" + view + ":" + attr + "=" + value + "] view " + view + " not supported: "
                                                    + views);
        }

        SftpClient.Attributes attributes = new SftpClient.Attributes();
        switch (attr) {
            case IoUtils.LASTMOD_TIME_VIEW_ATTR:
                attributes.modifyTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case IoUtils.LASTACC_TIME_VIEW_ATTR:
                attributes.accessTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case IoUtils.CREATE_TIME_VIEW_ATTR:
                attributes.createTime((int) ((FileTime) value).to(TimeUnit.SECONDS));
                break;
            case IoUtils.SIZE_VIEW_ATTR:
                attributes.size(((Number) value).longValue());
                break;
            case IoUtils.PERMISSIONS_VIEW_ATTR: {
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission> attrSet = (Set<PosixFilePermission>) value;
                attributes.perms(attributesToPermissions(path, attrSet));
                break;
            }
            case IoUtils.OWNER_VIEW_ATTR:
                attributes.owner(((UserPrincipal) value).getName());
                break;
            case IoUtils.GROUP_VIEW_ATTR:
                attributes.group(((GroupPrincipal) value).getName());
                break;
            case IoUtils.ACL_VIEW_ATTR: {
                ValidateUtils.checkTrue("acl".equalsIgnoreCase(view), "ACL cannot be set via view=%s", view);
                @SuppressWarnings("unchecked")
                List<AclEntry> acl = (List<AclEntry>) value;
                attributes.acl(acl);
                break;
            }
            case IoUtils.REGFILE_VIEW_ATTR:
            case IoUtils.DIRECTORY_VIEW_ATTR:
            case IoUtils.SYMLINK_VIEW_ATTR:
            case IoUtils.OTHERFILE_VIEW_ATTR:
            case IoUtils.FILEKEY_VIEW_ATTR:
                throw new UnsupportedOperationException(
                        "setAttribute(" + path + ")[" + view + ":" + attr + "=" + value + "] modification N/A");
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
        Objects.requireNonNull(path, "No path provided");
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
        boolean traceEnabled = log.isTraceEnabled();
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
                    if (traceEnabled) {
                        log.trace("attributesToPermissions({}) ignored {}", path, p);
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
        Collection<PosixFilePermission> attrs = permissionsToAttributes(perms);
        return getOctalPermissions(attrs);
    }

    public static Set<PosixFilePermission> permissionsToAttributes(int perms) {
        Set<PosixFilePermission> p = EnumSet.noneOf(PosixFilePermission.class);
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
                default: // ignored
            }
        }

        return String.format("%04o", pf);
    }

    /**
     * Uses the host, port and username to create a unique identifier
     *
     * @param  uri The {@link URI} - <B>Note:</B> not checked to make sure that the scheme is {@code sftp://}
     * @return     The unique identifier
     * @see        #getFileSystemIdentifier(String, int, String)
     */
    public static String getFileSystemIdentifier(URI uri) {
        String host = ValidateUtils.checkNotNullAndNotEmpty(uri.getHost(), "Host not provided");
        BasicCredentialsProvider credentials = ValidateUtils.checkNotNull(parseCredentials(uri), "UserInfo not provided");
        return getFileSystemIdentifier(host, uri.getPort(), credentials.getUsername());
    }

    /**
     * Uses the remote host address, port and current username to create a unique identifier
     *
     * @param  session The {@link ClientSession}
     * @return         The unique identifier
     * @see            #getFileSystemIdentifier(String, int, String)
     */
    public static String getFileSystemIdentifier(ClientSession session) {
        IoSession ioSession = session.getIoSession();
        SocketAddress addr = ioSession.getRemoteAddress();
        String username = session.getUsername();
        if (addr instanceof InetSocketAddress) {
            InetSocketAddress inetAddr = (InetSocketAddress) addr;
            return getFileSystemIdentifier(inetAddr.getHostString(), inetAddr.getPort(), username);
        } else {
            return getFileSystemIdentifier(addr.toString(), SshConstants.DEFAULT_PORT, username);
        }
    }

    public static String getFileSystemIdentifier(String host, int port, String username) {
        return GenericUtils.trimToEmpty(host) + ':'
               + SshConstants.TO_EFFECTIVE_PORT.applyAsInt(port) + ':'
               + GenericUtils.trimToEmpty(username);
    }

    public static URI createFileSystemURI(String host, int port, String username, String password) {
        return createFileSystemURI(host, port, username, password, Collections.emptyMap());
    }

    public static URI createFileSystemURI(String host, int port, String username, String password, Map<String, ?> params) {
        ValidateUtils.checkNotNullAndNotEmpty(host, "No host provided");

        String queryPart = null;
        int numParams = MapEntryUtils.size(params);
        if (numParams > 0) {
            StringBuilder sb = new StringBuilder(numParams * Short.SIZE);
            for (Map.Entry<String, ?> pe : params.entrySet()) {
                String key = pe.getKey();
                Object value = pe.getValue();
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(key);
                if (value != null) {
                    sb.append('=').append(Objects.toString(value, null));
                }
            }

            queryPart = sb.toString();
        }

        try {
            String userAuth = encodeCredentials(username, password);
            return new URI(SftpConstants.SFTP_SUBSYSTEM_NAME, userAuth, host, port, "/", queryPart, null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Failed (" + e.getClass().getSimpleName() + ")"
                                               + " to create access URI: " + e.getMessage(),
                    e);
        }
    }

    public static String encodeCredentials(String username, String password) {
        ValidateUtils.hasContent(username, "No username provided");

        /*
         * There is no way to properly encode/decode credentials that already contain colon. See also
         * https://tools.ietf.org/html/rfc3986#section-3.2.1:
         *
         *
         * Use of the format "user:password" in the userinfo field is deprecated. Applications should not render as
         * clear text any data after the first colon (":") character found within a userinfo subcomponent unless the
         * data after the colon is the empty string (indicating no password). Applications may choose to ignore or
         * reject such data when it is received as part of a reference and should reject the storage of such data in
         * unencrypted form.
         */
        ValidateUtils.checkTrue((username.indexOf(':') < 0) && ((password == null) || (password.indexOf(':') < 0)),
                "Reserved character used in credentials");
        if (password == null) {
            return username; // assume password-less login required
        } else {
            return username + ":" + password;
        }
    }
}
