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

import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemLoopException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.VersionProperties;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.subsystem.sftp.SftpHelper;
import org.apache.sshd.common.subsystem.sftp.extensions.AclSupportedParser;
import org.apache.sshd.common.subsystem.sftp.extensions.SpaceAvailableExtensionInfo;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.HardLinkExtensionParser;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.FileInfoExtractor;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem
        extends AbstractLoggingBean
        implements Command, Runnable, SessionAware, FileSystemAware, ServerSessionHolder, SftpEventListenerManager {

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final String MAX_OPEN_HANDLES_PER_SESSION = "max-open-handles-per-session";
    public static final int DEFAULT_MAX_OPEN_HANDLES = Integer.MAX_VALUE;

    /**
     * Size in bytes of the opaque handle value
     *
     * @see #DEFAULT_FILE_HANDLE_SIZE
     */
    public static final String FILE_HANDLE_SIZE = "sftp-handle-size";
    public static final int MIN_FILE_HANDLE_SIZE = 4;  // ~uint32
    public static final int DEFAULT_FILE_HANDLE_SIZE = 16;
    public static final int MAX_FILE_HANDLE_SIZE = 64;  // ~sha512

    /**
     * Max. rounds to attempt to create a unique file handle - if all handles
     * already in use after these many rounds, then an exception is thrown
     *
     * @see #generateFileHandle(Path)
     * @see #DEFAULT_FILE_HANDLE_ROUNDS
     */
    public static final String MAX_FILE_HANDLE_RAND_ROUNDS = "sftp-handle-rand-max-rounds";
    public static final int MIN_FILE_HANDLE_ROUNDS = 1;
    public static final int DEFAULT_FILE_HANDLE_ROUNDS = MIN_FILE_HANDLE_SIZE;
    public static final int MAX_FILE_HANDLE_ROUNDS = MAX_FILE_HANDLE_SIZE;

    /**
     * Force the use of a given sftp version
     */
    public static final String SFTP_VERSION = "sftp-version";

    public static final int LOWER_SFTP_IMPL = SftpConstants.SFTP_V3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = SftpConstants.SFTP_V6; //  .. up to and including
    public static final String ALL_SFTP_IMPL;

    /**
     * Force the use of a max. packet length - especially for {@link #doReadDir(Buffer, int)}
     * and {@link #doRead(Buffer, int)} methods
     *
     * @see #DEFAULT_MAX_PACKET_LENGTH
     */
    public static final String MAX_PACKET_LENGTH_PROP = "sftp-max-packet-length";
    public static final int DEFAULT_MAX_PACKET_LENGTH = 1024 * 16;

    /**
     * Allows controlling reports of which client extensions are supported
     * (and reported via &quot;support&quot; and &quot;support2&quot; server
     * extensions) as a comma-separate list of names. <B>Note:</B> requires
     * overriding the {@link #executeExtendedCommand(Buffer, int, String)}
     * command accordingly. If empty string is set then no server extensions
     * are reported
     *
     * @see #DEFAULT_SUPPORTED_CLIENT_EXTENSIONS
     */
    public static final String CLIENT_EXTENSIONS_PROP = "sftp-client-extensions";
    /**
     * The default reported supported client extensions
     */
    public static final Map<String, OptionalFeature> DEFAULT_SUPPORTED_CLIENT_EXTENSIONS =
            // TODO text-seek - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-13.txt
            // TODO home-directory - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
            Collections.unmodifiableMap(
                    new LinkedHashMap<String, OptionalFeature>() {
                        private static final long serialVersionUID = 1L;    // we're not serializing it

                        private final OptionalFeature anyDigests = OptionalFeature.Utils.any(BuiltinDigests.VALUES);
                        {
                            put(SftpConstants.EXT_VERSION_SELECT, OptionalFeature.TRUE);
                            put(SftpConstants.EXT_COPY_FILE, OptionalFeature.TRUE);
                            put(SftpConstants.EXT_MD5_HASH, BuiltinDigests.md5);
                            put(SftpConstants.EXT_MD5_HASH_HANDLE, BuiltinDigests.md5);
                            put(SftpConstants.EXT_CHECK_FILE_HANDLE, anyDigests);
                            put(SftpConstants.EXT_CHECK_FILE_NAME, anyDigests);
                            put(SftpConstants.EXT_COPY_DATA, OptionalFeature.TRUE);
                            put(SftpConstants.EXT_SPACE_AVAILABLE, OptionalFeature.TRUE);
                        }
                    });

    /**
     * Comma-separated list of which {@code OpenSSH} extensions are reported and
     * what version is reported for each - format: {@code name=version}. If empty
     * value set, then no such extensions are reported. Otherwise, the
     * {@link #DEFAULT_OPEN_SSH_EXTENSIONS} are used
     */
    public static final String OPENSSH_EXTENSIONS_PROP = "sftp-openssh-extensions";
    public static final List<OpenSSHExtension> DEFAULT_OPEN_SSH_EXTENSIONS =
            Collections.unmodifiableList(
                    Arrays.asList(
                            new OpenSSHExtension(FsyncExtensionParser.NAME, "1"),
                            new OpenSSHExtension(HardLinkExtensionParser.NAME, "1")
                    ));

    public static final List<String> DEFAULT_OPEN_SSH_EXTENSIONS_NAMES =
            Collections.unmodifiableList(new ArrayList<String>(DEFAULT_OPEN_SSH_EXTENSIONS.size()) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    for (OpenSSHExtension ext : DEFAULT_OPEN_SSH_EXTENSIONS) {
                        add(ext.getName());
                    }
                }

            });

    public static final List<String> DEFAULT_UNIX_VIEW = Collections.singletonList("unix:*");

    /**
     * Comma separate list of {@code SSH_ACL_CAP_xxx} names - where name can be without
     * the prefix. If not defined then {@link #DEFAULT_ACL_SUPPORTED_MASK} is used
     */
    public static final String ACL_SUPPORTED_MASK_PROP = "sftp-acl-supported-mask";
    public static final Set<Integer> DEFAULT_ACL_SUPPORTED_MASK =
            Collections.unmodifiableSet(
                    new HashSet<Integer>(Arrays.asList(
                            SftpConstants.SSH_ACL_CAP_ALLOW,
                            SftpConstants.SSH_ACL_CAP_DENY,
                            SftpConstants.SSH_ACL_CAP_AUDIT,
                            SftpConstants.SSH_ACL_CAP_ALARM)));

    /**
     * Property that can be used to set the reported NL value.
     * If not set, then {@link IoUtils#EOL} is used
     */
    public static final String NEWLINE_VALUE = "sftp-newline";

    /**
     * A {@link Map} of {@link FileInfoExtractor}s to be used to complete
     * attributes that are deemed important enough to warrant an extra
     * effort if not accessible via the file system attributes views
     */
    public static final Map<String, FileInfoExtractor<?>> FILEATTRS_RESOLVERS =
            Collections.unmodifiableMap(new TreeMap<String, FileInfoExtractor<?>>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    put("isRegularFile", FileInfoExtractor.ISREG);
                    put("isDirectory", FileInfoExtractor.ISDIR);
                    put("isSymbolicLink", FileInfoExtractor.ISSYMLINK);
                    put("permissions", FileInfoExtractor.PERMISSIONS);
                    put("size", FileInfoExtractor.SIZE);
                    put("lastModifiedTime", FileInfoExtractor.LASTMODIFIED);
                }
            });

    static {
        StringBuilder sb = new StringBuilder(2 * (1 + (HIGHER_SFTP_IMPL - LOWER_SFTP_IMPL)));
        for (int v = LOWER_SFTP_IMPL; v <= HIGHER_SFTP_IMPL; v++) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(v);
        }
        ALL_SFTP_IMPL = sb.toString();
    }

    protected ExitCallback callback;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected Environment env;
    protected Random randomizer;
    protected int fileHandleSize = DEFAULT_FILE_HANDLE_SIZE;
    protected int maxFileHandleRounds = DEFAULT_FILE_HANDLE_ROUNDS;
    protected ExecutorService executors;
    protected boolean shutdownExecutor;
    protected Future<?> pendingFuture;
    protected byte[] workBuf = new byte[Math.max(DEFAULT_FILE_HANDLE_SIZE, Integer.SIZE / Byte.SIZE)]; // TODO in JDK-8 use Integer.BYTES
    protected FileSystem fileSystem = FileSystems.getDefault();
    protected Path defaultDir = fileSystem.getPath(System.getProperty("user.dir"));
    protected long requestsCount;
    protected int version;
    protected final Map<String, byte[]> extensions = new HashMap<>();
    protected final Map<String, Handle> handles = new HashMap<>();
    protected final UnsupportedAttributePolicy unsupportedAttributePolicy;

    private ServerSession serverSession;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Collection<SftpEventListener> sftpEventListeners = new CopyOnWriteArraySet<>();
    private final SftpEventListener sftpEventListenerProxy;

    /**
     * @param executorService The {@link ExecutorService} to be used by
     *                        the {@link SftpSubsystem} command when starting execution. If
     *                        {@code null} then a single-threaded ad-hoc service is used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when subsystem terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @param policy          The {@link UnsupportedAttributePolicy} to use if failed to access
     *                        some local file attributes
     * @see ThreadUtils#newSingleThreadExecutor(String)
     */
    public SftpSubsystem(ExecutorService executorService, boolean shutdownOnExit, UnsupportedAttributePolicy policy) {
        if (executorService == null) {
            executors = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
            shutdownExecutor = true;    // we always close the ad-hoc executor service
        } else {
            executors = executorService;
            shutdownExecutor = shutdownOnExit;
        }

        unsupportedAttributePolicy = ValidateUtils.checkNotNull(policy, "No policy provided");
        sftpEventListenerProxy = EventListenerUtils.proxyWrapper(SftpEventListener.class, getClass().getClassLoader(), sftpEventListeners);
    }

    public int getVersion() {
        return version;
    }

    public final UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return unsupportedAttributePolicy;
    }

    @Override
    public SftpEventListener getSftpEventListenerProxy() {
        return sftpEventListenerProxy;
    }

    @Override
    public boolean addSftpEventListener(SftpEventListener listener) {
        return sftpEventListeners.add(ValidateUtils.checkNotNull(listener, "No listener"));
    }

    @Override
    public boolean removeSftpEventListener(SftpEventListener listener) {
        return sftpEventListeners.remove(listener);
    }

    @Override
    public void setSession(ServerSession session) {
        this.serverSession = ValidateUtils.checkNotNull(session, "No session");

        FactoryManager manager = session.getFactoryManager();
        Factory<? extends Random> factory = manager.getRandomFactory();
        this.randomizer = factory.create();

        this.fileHandleSize = PropertyResolverUtils.getIntProperty(session, FILE_HANDLE_SIZE, DEFAULT_FILE_HANDLE_SIZE);
        ValidateUtils.checkTrue(this.fileHandleSize >= MIN_FILE_HANDLE_SIZE, "File handle size too small: %d", this.fileHandleSize);
        ValidateUtils.checkTrue(this.fileHandleSize <= MAX_FILE_HANDLE_SIZE, "File handle size too big: %d", this.fileHandleSize);

        this.maxFileHandleRounds = PropertyResolverUtils.getIntProperty(session, MAX_FILE_HANDLE_RAND_ROUNDS, DEFAULT_FILE_HANDLE_ROUNDS);
        ValidateUtils.checkTrue(this.maxFileHandleRounds >= MIN_FILE_HANDLE_ROUNDS, "File handle rounds too small: %d", this.maxFileHandleRounds);
        ValidateUtils.checkTrue(this.maxFileHandleRounds <= MAX_FILE_HANDLE_ROUNDS, "File handle rounds too big: %d", this.maxFileHandleRounds);

        if (workBuf.length < this.fileHandleSize) {
            workBuf = new byte[this.fileHandleSize];
        }
    }

    @Override
    public ServerSession getServerSession() {
        return serverSession;
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        if (fileSystem != this.fileSystem) {
            this.fileSystem = fileSystem;

            Iterable<Path> roots = ValidateUtils.checkNotNull(fileSystem.getRootDirectories(), "No root directories");
            Iterator<Path> available = ValidateUtils.checkNotNull(roots.iterator(), "No roots iterator");
            ValidateUtils.checkTrue(available.hasNext(), "No available root");
            this.defaultDir = available.next();
        }
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void setInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    @Override
    public void start(Environment env) throws IOException {
        this.env = env;
        try {
            pendingFuture = executors.submit(this);
        } catch (RuntimeException e) {    // e.g., RejectedExecutionException
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start command: " + e.toString(), e);
            throw new IOException(e);
        }
    }

    @Override
    public void run() {
        try {
            for (long count = 1L;; count++) {
                int length = BufferUtils.readInt(in, workBuf, 0, workBuf.length);
                ValidateUtils.checkTrue(length >= ((Integer.SIZE / Byte.SIZE) + 1 /* command */), "Bad length to read: %d", length);

                Buffer buffer = new ByteArrayBuffer(length + (Integer.SIZE / Byte.SIZE) + Long.SIZE /* a bit extra */, false);
                buffer.putInt(length);
                for (int remainLen = length; remainLen > 0;) {
                    int l = in.read(buffer.array(), buffer.wpos(), remainLen);
                    if (l < 0) {
                        throw new IllegalArgumentException("Premature EOF at buffer #" + count + " while read length=" + length + " and remain=" + remainLen);
                    }
                    buffer.wpos(buffer.wpos() + l);
                    remainLen -= l;
                }

                process(buffer);
            }
        } catch (Throwable t) {
            if ((!closed.get()) && (!(t instanceof EOFException))) { // Ignore
                log.error("run({}) {} caught in SFTP subsystem: {}",
                          getServerSession(), t.getClass().getSimpleName(), t.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("run(" + getServerSession() + ") caught exception details", t);
                }
            }
        } finally {
            for (Map.Entry<String, Handle> entry : handles.entrySet()) {
                String id = entry.getKey();
                Handle handle = entry.getValue();
                try {
                    handle.close();
                    if (log.isDebugEnabled()) {
                        log.debug("run({}) closed pending handle {} [{}]",
                                  getServerSession(), id, handle);
                    }
                } catch (IOException ioe) {
                    log.error("run({}) failed ({}) to close handle={}[{}]: {}",
                              getServerSession(), ioe.getClass().getSimpleName(), id, handle, ioe.getMessage());
                }
            }

            callback.onExit(0);
        }
    }

    protected void process(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("process({})[length={}, type={}, id={}] processing",
                      getServerSession(), length, SftpConstants.getCommandMessageName(type), id);
        }

        switch (type) {
            case SftpConstants.SSH_FXP_INIT:
                doInit(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPEN:
                doOpen(buffer, id);
                break;
            case SftpConstants.SSH_FXP_CLOSE:
                doClose(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READ:
                doRead(buffer, id);
                break;
            case SftpConstants.SSH_FXP_WRITE:
                doWrite(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LSTAT:
                doLStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_FSTAT:
                doFStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SETSTAT:
                doSetStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_FSETSTAT:
                doFSetStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPENDIR:
                doOpenDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READDIR:
                doReadDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REMOVE:
                doRemove(buffer, id);
                break;
            case SftpConstants.SSH_FXP_MKDIR:
                doMakeDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RMDIR:
                doRemoveDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REALPATH:
                doRealPath(buffer, id);
                break;
            case SftpConstants.SSH_FXP_STAT:
                doStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RENAME:
                doRename(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READLINK:
                doReadLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SYMLINK:
                doSymLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LINK:
                doLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_BLOCK:
                doBlock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_UNBLOCK:
                doUnblock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_EXTENDED:
                doExtended(buffer, id);
                break;
            default:
            {
                String name = SftpConstants.getCommandMessageName(type);
                log.warn("process({})[length={}, type={}, id={}] unknown command",
                         getServerSession(), length, name, id);
                sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Command " + name + " is unsupported or not implemented");
            }
        }

        if (type != SftpConstants.SSH_FXP_INIT) {
            requestsCount++;
        }
    }

    protected void doExtended(Buffer buffer, int id) throws IOException {
        executeExtendedCommand(buffer, id, buffer.getString());
    }

    /**
     * @param buffer    The command {@link Buffer}
     * @param id        The request id
     * @param extension The extension name
     * @throws IOException If failed to execute the extension
     */
    protected void executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
        switch (extension) {
            case SftpConstants.EXT_TEXT_SEEK:
                doTextSeek(buffer, id);
                break;
            case SftpConstants.EXT_VERSION_SELECT:
                doVersionSelect(buffer, id);
                break;
            case SftpConstants.EXT_COPY_FILE:
                doCopyFile(buffer, id);
                break;
            case SftpConstants.EXT_COPY_DATA:
                doCopyData(buffer, id);
                break;
            case SftpConstants.EXT_MD5_HASH:
            case SftpConstants.EXT_MD5_HASH_HANDLE:
                doMD5Hash(buffer, id, extension);
                break;
            case SftpConstants.EXT_CHECK_FILE_HANDLE:
            case SftpConstants.EXT_CHECK_FILE_NAME:
                doCheckFileHash(buffer, id, extension);
                break;
            case FsyncExtensionParser.NAME:
                doOpenSSHFsync(buffer, id);
                break;
            case SftpConstants.EXT_SPACE_AVAILABLE:
                doSpaceAvailable(buffer, id);
                break;
            case HardLinkExtensionParser.NAME:
                doOpenSSHHardLink(buffer, id);
                break;
            default:
                if (log.isDebugEnabled()) {
                    log.debug("executeExtendedCommand({}) received unsupported SSH_FXP_EXTENDED({})", getServerSession(), extension);
                }
                sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_EXTENDED(" + extension + ") is unsupported or not implemented");
                break;
        }
    }

    // see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL section 10
    protected void doOpenSSHHardLink(Buffer buffer, int id) throws IOException {
        String srcFile = buffer.getString();
        String dstFile = buffer.getString();

        try {
            doOpenSSHHardLink(id, srcFile, dstFile);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doOpenSSHHardLink(int id, String srcFile, String dstFile) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doOpenSSHHardLink({})[id={}] SSH_FXP_EXTENDED[{}] (src={}, dst={})",
                      getServerSession(), id, HardLinkExtensionParser.NAME, srcFile, dstFile);
        }

        createLink(id, srcFile, dstFile, false);
    }

    protected void doSpaceAvailable(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        SpaceAvailableExtensionInfo info;
        try {
            info = doSpaceAvailable(id, path);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        buffer.clear();
        buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
        buffer.putInt(id);
        SpaceAvailableExtensionInfo.encode(buffer, info);
        send(buffer);
    }

    protected SpaceAvailableExtensionInfo doSpaceAvailable(int id, String path) throws IOException {
        Path nrm = resolveNormalizedLocation(path);
        if (log.isDebugEnabled()) {
            log.debug("doSpaceAvailable({})[id={}] path={}[{}]", getServerSession(), id, path, nrm);
        }

        FileStore store = Files.getFileStore(nrm);
        if (log.isTraceEnabled()) {
            log.trace("doSpaceAvailable({})[id={}] path={}[{}] - {}[{}]",
                      getServerSession(), id, path, nrm, store.name(), store.type());
        }

        return new SpaceAvailableExtensionInfo(store);
    }

    protected void doTextSeek(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long line = buffer.getLong();
        try {
            // TODO : implement text-seek - see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-03#section-6.3
            doTextSeek(id, handle, line);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doTextSeek(int id, String handle, long line) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doTextSeek({})[id={}] SSH_FXP_EXTENDED(text-seek) (handle={}[{}], line={})",
                      getServerSession(), id, handle, h, line);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        throw new UnsupportedOperationException("doTextSeek(" + fileHandle + ")");
    }

    // see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL section 10
    protected void doOpenSSHFsync(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        try {
            doOpenSSHFsync(id, handle);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doOpenSSHFsync(int id, String handle) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doOpenSSHFsync({})[id={}] {}[{}]", getServerSession(), id, handle, h);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        FileChannel channel = fileHandle.getFileChannel();
        channel.force(false);
    }

    protected void doCheckFileHash(Buffer buffer, int id, String targetType) throws IOException {
        String target = buffer.getString();
        String algList = buffer.getString();
        String[] algos = GenericUtils.split(algList, ',');
        long startOffset = buffer.getLong();
        long length = buffer.getLong();
        int blockSize = buffer.getInt();
        try {
            buffer.clear();
            buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
            buffer.putInt(id);
            buffer.putString(SftpConstants.EXT_CHECK_FILE);
            doCheckFileHash(id, targetType, target, Arrays.asList(algos), startOffset, length, blockSize, buffer);
        } catch (Exception e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        send(buffer);
    }

    protected void doCheckFileHash(int id, String targetType, String target, Collection<String> algos,
                                   long startOffset, long length, int blockSize, Buffer buffer)
            throws Exception {
        Path path;
        if (SftpConstants.EXT_CHECK_FILE_HANDLE.equalsIgnoreCase(targetType)) {
            Handle h = handles.get(target);
            FileHandle fileHandle = validateHandle(target, h, FileHandle.class);
            path = fileHandle.getFile();

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.2:
             *
             *       If ACE4_READ_DATA was not included when the file was opened,
             *       the server MUST return STATUS_PERMISSION_DENIED.
             */
            int access = fileHandle.getAccessMask();
            if ((access & SftpConstants.ACE4_READ_DATA) == 0) {
                throw new AccessDeniedException("File not opened for read: " + path);
            }
        } else {
            path = resolveFile(target);

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.2:
             *
             *      If 'check-file-name' refers to a SSH_FILEXFER_TYPE_SYMLINK, the
             *      target should be opened.
             */
            for (int index = 0; Files.isSymbolicLink(path) && (index < Byte.MAX_VALUE /* TODO make this configurable */); index++) {
                path = Files.readSymbolicLink(path);
            }

            if (Files.isSymbolicLink(path)) {
                throw new FileSystemLoopException(target + " yields a circular or too long chain of symlinks");
            }

            if (Files.isDirectory(path, IoUtils.getLinkOptions(false))) {
                throw new NotDirectoryException(path.toString());
            }
        }

        ValidateUtils.checkNotNullAndNotEmpty(algos, "No hash algorithms specified");

        DigestFactory factory = null;
        for (String a : algos) {
            factory = BuiltinDigests.fromFactoryName(a);
            if ((factory != null) && factory.isSupported()) {
                break;
            }
        }
        ValidateUtils.checkNotNull(factory, "No matching digest factory found for %s", algos);

        doCheckFileHash(id, path, factory, startOffset, length, blockSize, buffer);
    }

    protected void doCheckFileHash(int id, Path file, NamedFactory<? extends Digest> factory,
                                   long startOffset, long length, int blockSize, Buffer buffer)
            throws Exception {
        ValidateUtils.checkTrue(startOffset >= 0L, "Invalid start offset: %d", startOffset);
        ValidateUtils.checkTrue(length >= 0L, "Invalid length: %d", length);
        ValidateUtils.checkTrue((blockSize == 0) || (blockSize >= SftpConstants.MIN_CHKFILE_BLOCKSIZE), "Invalid block size: %d", blockSize);
        ValidateUtils.checkNotNull(factory, "No digest factory provided");
        buffer.putString(factory.getName());

        long effectiveLength = length;
        long totalLength = Files.size(file);
        if (effectiveLength == 0L) {
            effectiveLength = totalLength - startOffset;
        } else {
            long maxRead = startOffset + length;
            if (maxRead > totalLength) {
                effectiveLength = totalLength - startOffset;
            }
        }
        ValidateUtils.checkTrue(effectiveLength > 0L, "Non-positive effective hash data length: %d", effectiveLength);

        byte[] digestBuf = (blockSize == 0)
                ? new byte[Math.min((int) effectiveLength, IoUtils.DEFAULT_COPY_SIZE)]
                : new byte[Math.min((int) effectiveLength, blockSize)];
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        try (FileChannel channel = FileChannel.open(file, IoUtils.EMPTY_OPEN_OPTIONS)) {
            channel.position(startOffset);

            Digest digest = factory.create();
            digest.init();

            if (blockSize == 0) {
                while (effectiveLength > 0L) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break;
                    }

                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);
                }

                byte[] hashValue = digest.digest();
                if (log.isTraceEnabled()) {
                    log.trace("doCheckFileHash({})[{}] offset={}, length={} - algo={}, hash={}",
                              getServerSession(), file, startOffset, length,
                              digest.getAlgorithm(), BufferUtils.toHex(':', hashValue));
                }
                buffer.putBytes(hashValue);
            } else {
                for (int count = 0; effectiveLength > 0L; count++) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break;
                    }

                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);

                    byte[] hashValue = digest.digest(); // NOTE: this also resets the hash for the next read
                    if (log.isTraceEnabled()) {
                        log.trace("doCheckFileHash({})({})[{}] offset={}, length={} - algo={}, hash={}",
                                  getServerSession(), file, count, startOffset, length,
                                  digest.getAlgorithm(), BufferUtils.toHex(':', hashValue));
                    }
                    buffer.putBytes(hashValue);
                }
            }
        }
    }

    protected void doMD5Hash(Buffer buffer, int id, String targetType) throws IOException {
        String target = buffer.getString();
        long startOffset = buffer.getLong();
        long length = buffer.getLong();
        byte[] quickCheckHash = buffer.getBytes();
        byte[] hashValue;

        try {
            hashValue = doMD5Hash(id, targetType, target, startOffset, length, quickCheckHash);
            if (log.isTraceEnabled()) {
                log.trace("doMD5Hash({})({})[{}] offset={}, length={}, quick-hash={} - hash={}",
                          getServerSession(), targetType, target, startOffset, length,
                          BufferUtils.toHex(':', quickCheckHash),
                          BufferUtils.toHex(':', hashValue));
            }

        } catch (Exception e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        buffer.clear();
        buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
        buffer.putInt(id);
        buffer.putString(targetType);
        buffer.putBytes(hashValue);
        send(buffer);
    }

    protected byte[] doMD5Hash(int id, String targetType, String target, long startOffset, long length, byte[] quickCheckHash) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("doMD5Hash({})({})[{}] offset={}, length={}, quick-hash={}",
                      getServerSession(), targetType, target, startOffset, length,
                      BufferUtils.toHex(':', quickCheckHash));
        }

        Path path;
        if (SftpConstants.EXT_MD5_HASH_HANDLE.equalsIgnoreCase(targetType)) {
            Handle h = handles.get(target);
            FileHandle fileHandle = validateHandle(target, h, FileHandle.class);
            path = fileHandle.getFile();

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.1:
             *
             *      The handle MUST be a file handle, and ACE4_READ_DATA MUST
             *      have been included in the desired-access when the file
             *      was opened
             */
            int access = fileHandle.getAccessMask();
            if ((access & SftpConstants.ACE4_READ_DATA) == 0) {
                throw new AccessDeniedException("File not opened for read: " + path);
            }
        } else {
            path = resolveFile(target);
            if (Files.isDirectory(path, IoUtils.getLinkOptions(false))) {
                throw new NotDirectoryException(path.toString());
            }
        }

        /*
         * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.1:
         *
         *      If both start-offset and length are zero, the entire file should be included
         */
        long effectiveLength = length;
        long totalSize = Files.size(path);
        if ((startOffset == 0L) && (length == 0L)) {
            effectiveLength = totalSize;
        } else {
            long maxRead = startOffset + effectiveLength;
            if (maxRead > totalSize) {
                effectiveLength = totalSize - startOffset;
            }
        }

        return doMD5Hash(id, path, startOffset, effectiveLength, quickCheckHash);
    }

    protected byte[] doMD5Hash(int id, Path path, long startOffset, long length, byte[] quickCheckHash) throws Exception {
        ValidateUtils.checkTrue(startOffset >= 0L, "Invalid start offset: %d", startOffset);
        ValidateUtils.checkTrue(length > 0L, "Invalid length: %d", length);
        if (!BuiltinDigests.md5.isSupported()) {
            throw new UnsupportedOperationException(BuiltinDigests.md5.getAlgorithm() + " hash not supported");
        }

        Digest digest = BuiltinDigests.md5.create();
        digest.init();

        long effectiveLength = length;
        byte[] digestBuf = new byte[(int) Math.min(effectiveLength, SftpConstants.MD5_QUICK_HASH_SIZE)];
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        boolean hashMatches = false;
        byte[] hashValue = null;

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            channel.position(startOffset);

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.1:
             *
             *      If this is a zero length string, the client does not have the
             *      data, and is requesting the hash for reasons other than comparing
             *      with a local file.  The server MAY return SSH_FX_OP_UNSUPPORTED in
             *      this case.
             */
            if (NumberUtils.length(quickCheckHash) <= 0) {
                // TODO consider limiting it - e.g., if the requested effective length is <= than some (configurable) threshold
                hashMatches = true;
            } else {
                int readLen = channel.read(wb);
                if (readLen < 0) {
                    throw new EOFException("EOF while read initial buffer from " + path);
                }
                effectiveLength -= readLen;
                digest.update(digestBuf, 0, readLen);

                hashValue = digest.digest();
                hashMatches = Arrays.equals(quickCheckHash, hashValue);
                if (hashMatches) {
                    /*
                     * Need to re-initialize the digester due to the Javadoc:
                     *
                     *      "The digest method can be called once for a given number
                     *       of updates. After digest has been called, the MessageDigest
                     *       object is reset to its initialized state."
                     */
                    if (effectiveLength > 0L) {
                        digest = BuiltinDigests.md5.create();
                        digest.init();
                        digest.update(digestBuf, 0, readLen);
                        hashValue = null;   // start again
                    }
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("doMD5Hash({})({}) offset={}, length={} - quick-hash mismatched expected={}, actual={}",
                                  getServerSession(), path, startOffset, length,
                                  BufferUtils.toHex(':', quickCheckHash),
                                  BufferUtils.toHex(':', hashValue));
                    }
                }
            }

            if (hashMatches) {
                while (effectiveLength > 0L) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break;  // user may have specified more than we have available
                    }
                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);
                }

                if (hashValue == null) {    // check if did any more iterations after the quick hash
                    hashValue = digest.digest();
                }
            } else {
                hashValue = GenericUtils.EMPTY_BYTE_ARRAY;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("doMD5Hash({})({}) offset={}, length={} - matches={}, quick={} hash={}",
                      getServerSession(), path, startOffset, length, hashMatches,
                      BufferUtils.toHex(':', quickCheckHash),
                      BufferUtils.toHex(':', hashValue));
        }

        return hashValue;
    }

    protected void doVersionSelect(Buffer buffer, int id) throws IOException {
        String proposed = buffer.getString();
        ServerSession session = getServerSession();
        /*
         * The 'version-select' MUST be the first request from the client to the
         * server; if it is not, the server MUST fail the request and close the
         * channel.
         */
        if (requestsCount > 0L) {
            sendStatus(BufferUtils.clear(buffer), id,
                       SftpConstants.SSH_FX_FAILURE,
                       "Version selection not the 1st request for proposal = " + proposed);
            session.close(true);
            return;
        }

        Boolean result = validateProposedVersion(buffer, id, proposed);
        /*
         * "MUST then close the channel without processing any further requests"
         */
        if (result == null) {   // response sent internally
            session.close(true);
            return;
        }
        if (result) {
            version = Integer.parseInt(proposed);
            sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
        } else {
            sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_FAILURE, "Unsupported version " + proposed);
            session.close(true);
        }
    }

    /**
     * @param buffer   The {@link Buffer} holding the request
     * @param id       The request id
     * @param proposed The proposed value
     * @return A {@link Boolean} indicating whether to accept/reject the proposal.
     * If {@code null} then rejection response has been sent, otherwise and
     * appropriate response is generated
     * @throws IOException If failed send an independent rejection response
     */
    protected Boolean validateProposedVersion(Buffer buffer, int id, String proposed) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("validateProposedVersion({})[id={}] SSH_FXP_EXTENDED(version-select) (version={})",
                      getServerSession(), id, proposed);
        }

        if (GenericUtils.length(proposed) != 1) {
            return Boolean.FALSE;
        }

        char digit = proposed.charAt(0);
        if ((digit < '0') || (digit > '9')) {
            return Boolean.FALSE;
        }

        int value = digit - '0';
        String all = checkVersionCompatibility(buffer, id, value, SftpConstants.SSH_FX_FAILURE);
        if (GenericUtils.isEmpty(all)) {    // validation failed
            return null;
        } else {
            return Boolean.TRUE;
        }
    }

    /**
     * Checks if a proposed version is within supported range. <B>Note:</B>
     * if the user forced a specific value via the {@link #SFTP_VERSION}
     * property, then it is used to validate the proposed value
     *
     * @param buffer        The {@link Buffer} containing the request
     * @param id            The SSH message ID to be used to send the failure message
     *                      if required
     * @param proposed      The proposed version value
     * @param failureOpcode The failure opcode to send if validation fails
     * @return A {@link String} of comma separated values representing all
     * the supported version - {@code null} if validation failed and an
     * appropriate status message was sent
     * @throws IOException If failed to send the failure status message
     */
    protected String checkVersionCompatibility(Buffer buffer, int id, int proposed, int failureOpcode) throws IOException {
        int low = LOWER_SFTP_IMPL;
        int hig = HIGHER_SFTP_IMPL;
        String available = ALL_SFTP_IMPL;
        // check if user wants to use a specific version
        ServerSession session = getServerSession();
        Integer sftpVersion = PropertyResolverUtils.getInteger(session, SFTP_VERSION);
        if (sftpVersion != null) {
            int forcedValue = sftpVersion;
            if ((forcedValue < LOWER_SFTP_IMPL) || (forcedValue > HIGHER_SFTP_IMPL)) {
                throw new IllegalStateException("Forced SFTP version (" + sftpVersion + ") not within supported values: " + available);
            }
            hig = sftpVersion;
            low = hig;
            available = sftpVersion.toString();
        }

        if (log.isTraceEnabled()) {
            log.trace("checkVersionCompatibility({})[id={}] - proposed={}, available={}",
                      getServerSession(), id, proposed, available);
        }

        if ((proposed < low) || (proposed > hig)) {
            sendStatus(BufferUtils.clear(buffer), id, failureOpcode, "Proposed version (" + proposed + ") not in supported range: " + available);
            return null;
        }

        return available;
    }

    protected void doBlock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        int mask = buffer.getInt();

        try {
            doBlock(id, handle, offset, length, mask);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doBlock(int id, String handle, long offset, long length, int mask) throws IOException {
        Handle p = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doBlock({})[id={}] SSH_FXP_BLOCK (handle={}[{}], offset={}, length={}, mask=0x{})",
                      getServerSession(), id, handle, p, offset, length, Integer.toHexString(mask));
        }

        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.blocking(session, handle, fileHandle, offset, length, mask);
        try {
            fileHandle.lock(offset, length, mask);
            listener.blocked(session, handle, fileHandle, offset, length, mask, null);
        } catch (IOException | RuntimeException e) {
            listener.blocked(session, handle, fileHandle, offset, length, mask, e);
            throw e;
        }
    }

    protected void doUnblock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        boolean found;
        try {
            found = doUnblock(id, handle, offset, length);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, found ? SftpConstants.SSH_FX_OK : SftpConstants.SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK, "");
    }

    protected boolean doUnblock(int id, String handle, long offset, long length) throws IOException {
        Handle p = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doUnblock({})[id={}] SSH_FXP_UNBLOCK (handle={}[{}], offset={}, length={})",
                      getServerSession(), id, handle, p, offset, length);
        }

        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.unblocking(session, handle, fileHandle, offset, length);
        try {
            boolean result = fileHandle.unlock(offset, length);
            listener.unblocked(session, handle, fileHandle, offset, length, Boolean.valueOf(result), null);
            return result;
        } catch (IOException | RuntimeException e) {
            listener.unblocked(session, handle, fileHandle, offset, length, null, e);
            throw e;
        }
    }

    protected void doLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        boolean symLink = buffer.getBoolean();

        try {
            if (log.isDebugEnabled()) {
                log.debug("doLink({})[id={}] SSH_FXP_LINK linkpath={}, targetpath={}, symlink={}",
                          getServerSession(), id, linkPath, targetPath, symLink);
            }

            doLink(id, targetPath, linkPath, symLink);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doLink(int id, String targetPath, String linkPath, boolean symLink) throws IOException {
        createLink(id, targetPath, linkPath, symLink);
    }

    protected void doSymLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        try {
            if (log.isDebugEnabled()) {
                log.debug("doSymLink({})[id={}] SSH_FXP_SYMLINK linkpath={}, targetpath={}",
                          getServerSession(), id, targetPath, linkPath);
            }
            doSymLink(id, targetPath, linkPath);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doSymLink(int id, String targetPath, String linkPath) throws IOException {
        createLink(id, targetPath, linkPath, true);
    }

    protected void createLink(int id, String existingPath, String linkPath, boolean symLink) throws IOException {
        Path link = resolveFile(linkPath);
        Path existing = fileSystem.getPath(existingPath);
        if (log.isDebugEnabled()) {
            log.debug("createLink({})[id={}], existing={}[{}], link={}[{}], symlink={})",
                      getServerSession(), id, linkPath, link, existingPath, existing, symLink);
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.linking(session, link, existing, symLink);
        try {
            if (symLink) {
                Files.createSymbolicLink(link, existing);
            } else {
                Files.createLink(link, existing);
            }
            listener.linked(session, link, existing, symLink, null);
        } catch (IOException | RuntimeException e) {
            listener.linked(session, link, existing, symLink, e);
            throw e;
        }
    }

    protected void doReadLink(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        String l;
        try {
            if (log.isDebugEnabled()) {
                log.debug("doReadLink({})[id={}] SSH_FXP_READLINK path={}",
                          getServerSession(), id, path);
            }
            l = doReadLink(id, path);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendLink(BufferUtils.clear(buffer), id, l);
    }

    protected String doReadLink(int id, String path) throws IOException {
        Path f = resolveFile(path);
        Path t = Files.readSymbolicLink(f);
        if (log.isDebugEnabled()) {
            log.debug("doReadLink({})[id={}] path={}[{}]: {}",
                      getServerSession(), id, path, f, t);
        }
        return t.toString();
    }

    protected void doRename(Buffer buffer, int id) throws IOException {
        String oldPath = buffer.getString();
        String newPath = buffer.getString();
        int flags = 0;
        if (version >= SftpConstants.SFTP_V5) {
            flags = buffer.getInt();
        }
        try {
            doRename(id, oldPath, newPath, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRename(int id, String oldPath, String newPath, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doRename({})[id={}] SSH_FXP_RENAME (oldPath={}, newPath={}, flags=0x{})",
                      getServerSession(), id, oldPath, newPath, Integer.toHexString(flags));
        }

        Collection<CopyOption> opts = Collections.emptyList();
        if (flags != 0) {
            opts = new ArrayList<>();
            if ((flags & SftpConstants.SSH_FXP_RENAME_ATOMIC) == SftpConstants.SSH_FXP_RENAME_ATOMIC) {
                opts.add(StandardCopyOption.ATOMIC_MOVE);
            }
            if ((flags & SftpConstants.SSH_FXP_RENAME_OVERWRITE) == SftpConstants.SSH_FXP_RENAME_OVERWRITE) {
                opts.add(StandardCopyOption.REPLACE_EXISTING);
            }
        }

        doRename(id, oldPath, newPath, opts);
    }

    protected void doRename(int id, String oldPath, String newPath, Collection<CopyOption> opts) throws IOException {
        Path o = resolveFile(oldPath);
        Path n = resolveFile(newPath);
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();

        listener.moving(session, o, n, opts);
        try {
            Files.move(o, n, GenericUtils.isEmpty(opts) ? IoUtils.EMPTY_COPY_OPTIONS : opts.toArray(new CopyOption[opts.size()]));
            listener.moved(session, o, n, opts, null);
        } catch (IOException | RuntimeException e) {
            listener.moved(session, o, n, opts, e);
            throw e;
        }
    }

    // see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-extensions-00#section-7
    protected void doCopyData(Buffer buffer, int id) throws IOException {
        String readHandle = buffer.getString();
        long readOffset = buffer.getLong();
        long readLength = buffer.getLong();
        String writeHandle = buffer.getString();
        long writeOffset = buffer.getLong();
        try {
            doCopyData(id, readHandle, readOffset, readLength, writeHandle, writeOffset);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    @SuppressWarnings("resource")
    protected void doCopyData(int id, String readHandle, long readOffset, long readLength, String writeHandle, long writeOffset) throws IOException {
        boolean inPlaceCopy = readHandle.equals(writeHandle);
        Handle rh = handles.get(readHandle);
        Handle wh = inPlaceCopy ? rh : handles.get(writeHandle);
        if (log.isDebugEnabled()) {
            log.debug("doCopyData({})[id={}] SSH_FXP_EXTENDED[{}] read={}[{}], read-offset={}, read-length={}, write={}[{}], write-offset={})",
                      getServerSession(), id, SftpConstants.EXT_COPY_DATA,
                      readHandle, rh, readOffset, readLength,
                      writeHandle, wh, writeOffset);
        }

        FileHandle srcHandle = validateHandle(readHandle, rh, FileHandle.class);
        Path srcPath = srcHandle.getFile();
        int srcAccess = srcHandle.getAccessMask();
        if ((srcAccess & SftpConstants.ACE4_READ_DATA) != SftpConstants.ACE4_READ_DATA) {
            throw new AccessDeniedException("File not opened for read: " + srcPath);
        }

        ValidateUtils.checkTrue(readLength >= 0L, "Invalid read length: %d", readLength);
        ValidateUtils.checkTrue(readOffset >= 0L, "Invalid read offset: %d", readOffset);

        long totalSize = Files.size(srcHandle.getFile());
        long effectiveLength = readLength;
        if (effectiveLength == 0L) {
            effectiveLength = totalSize - readOffset;
        } else {
            long maxRead = readOffset + effectiveLength;
            if (maxRead > totalSize) {
                effectiveLength = totalSize - readOffset;
            }
        }
        ValidateUtils.checkTrue(effectiveLength > 0L, "Non-positive effective copy data length: %d", effectiveLength);

        FileHandle dstHandle = inPlaceCopy ? srcHandle : validateHandle(writeHandle, wh, FileHandle.class);
        int dstAccess = dstHandle.getAccessMask();
        if ((dstAccess & SftpConstants.ACE4_WRITE_DATA) != SftpConstants.ACE4_WRITE_DATA) {
            throw new AccessDeniedException("File not opened for write: " + srcHandle);
        }

        ValidateUtils.checkTrue(writeOffset >= 0L, "Invalid write offset: %d", writeOffset);
        // check if overlapping ranges as per the draft
        if (inPlaceCopy) {
            long maxRead = readOffset + effectiveLength;
            if (maxRead > totalSize) {
                maxRead = totalSize;
            }

            long maxWrite = writeOffset + effectiveLength;
            if (maxWrite > readOffset) {
                throw new IllegalArgumentException("Write range end [" + writeOffset + "-" + maxWrite + "]"
                        + " overlaps with read range [" + readOffset + "-" + maxRead + "]");
            } else if (maxRead > writeOffset) {
                throw new IllegalArgumentException("Read range end [" + readOffset + "-" + maxRead + "]"
                        + " overlaps with write range [" + writeOffset + "-" + maxWrite + "]");
            }
        }

        byte[] copyBuf = new byte[Math.min(IoUtils.DEFAULT_COPY_SIZE, (int) effectiveLength)];
        while (effectiveLength > 0L) {
            int remainLength = Math.min(copyBuf.length, (int) effectiveLength);
            int readLen = srcHandle.read(copyBuf, 0, remainLength, readOffset);
            if (readLen < 0) {
                throw new EOFException("Premature EOF while still remaining " + effectiveLength + " bytes");
            }
            dstHandle.write(copyBuf, 0, readLen, writeOffset);

            effectiveLength -= readLen;
            readOffset += readLen;
            writeOffset += readLen;
        }
    }

    // see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-extensions-00#section-6
    protected void doCopyFile(Buffer buffer, int id) throws IOException {
        String srcFile = buffer.getString();
        String dstFile = buffer.getString();
        boolean overwriteDestination = buffer.getBoolean();

        try {
            doCopyFile(id, srcFile, dstFile, overwriteDestination);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doCopyFile(int id, String srcFile, String dstFile, boolean overwriteDestination) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doCopyFile({})[id={}] SSH_FXP_EXTENDED[{}] (src={}, dst={}, overwrite=0x{})",
                      getServerSession(), id, SftpConstants.EXT_COPY_FILE,
                      srcFile, dstFile, overwriteDestination);
        }

        doCopyFile(id, srcFile, dstFile,
                overwriteDestination
                        ? Collections.<CopyOption>singletonList(StandardCopyOption.REPLACE_EXISTING)
                        : Collections.<CopyOption>emptyList());
    }

    protected void doCopyFile(int id, String srcFile, String dstFile, Collection<CopyOption> opts) throws IOException {
        Path src = resolveFile(srcFile);
        Path dst = resolveFile(dstFile);
        Files.copy(src, dst, GenericUtils.isEmpty(opts) ? IoUtils.EMPTY_COPY_OPTIONS : opts.toArray(new CopyOption[opts.size()]));
    }

    protected void doStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, Object> attrs;
        try {
            attrs = doStat(id, path, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String, Object> doStat(int id, String path, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doStat({})[id={}] SSH_FXP_STAT (path={}, flags=0x{})",
                      getServerSession(), id, path, Integer.toHexString(flags));
        }
        Path p = resolveFile(path);
        return resolveFileAttributes(p, flags, IoUtils.getLinkOptions(false));
    }

    protected void doRealPath(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("doRealPath({})[id={}] SSH_FXP_REALPATH (path={})", getServerSession(), id, path);
        }
        path = GenericUtils.trimToEmpty(path);
        if (GenericUtils.isEmpty(path)) {
            path = ".";
        }

        Map<String, ?> attrs = Collections.<String, Object>emptyMap();
        Pair<Path, Boolean> result;
        try {
            LinkOption[] options = IoUtils.getLinkOptions(false);
            if (version < SftpConstants.SFTP_V6) {
                /*
                 * See http://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt:
                 *
                 *      The SSH_FXP_REALPATH request can be used to have the server
                 *      canonicalize any given path name to an absolute path.
                 *
                 * See also SSHD-294
                 */
                result = doRealPathV345(id, path, options);
            } else {
                /*
                 * See https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.9
                 *
                 *      This field is optional, and if it is not present in the packet, it
                 *      is assumed to be SSH_FXP_REALPATH_NO_CHECK.
                 */
                int control = SftpConstants.SSH_FXP_REALPATH_NO_CHECK;
                if (buffer.available() > 0) {
                    control = buffer.getUByte();
                    if (log.isDebugEnabled()) {
                        log.debug("doRealPath({}) - control=0x{} for path={}",
                                  getServerSession(), Integer.toHexString(control), path);
                    }
                }

                Collection<String> extraPaths = new LinkedList<>();
                while (buffer.available() > 0) {
                    extraPaths.add(buffer.getString());
                }

                result = doRealPathV6(id, path, extraPaths, options);

                Path p = result.getFirst();
                Boolean status = result.getSecond();
                switch (control) {
                    case SftpConstants.SSH_FXP_REALPATH_STAT_IF:
                        if (status == null) {
                            attrs = handleUnknownStatusFileAttributes(p, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
                        } else if (status) {
                            try {
                                attrs = getAttributes(p, IoUtils.getLinkOptions(false));
                            } catch (IOException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("doRealPath({}) - failed ({}) to retrieve attributes of {}: {}",
                                              getServerSession(), e.getClass().getSimpleName(), p, e.getMessage());
                                }
                                if (log.isTraceEnabled()) {
                                    log.trace("doRealPath(" + getServerSession() + ")[" + p + "] attributes retrieval failure details", e);
                                }
                            }
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("doRealPath({}) - dummy attributes for non-existing file: {}", getServerSession(), p);
                            }
                        }
                        break;
                    case SftpConstants.SSH_FXP_REALPATH_STAT_ALWAYS:
                        if (status == null) {
                            attrs = handleUnknownStatusFileAttributes(p, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
                        } else if (status) {
                            attrs = getAttributes(p, options);
                        } else {
                            throw new FileNotFoundException(p.toString());
                        }
                        break;
                    case SftpConstants.SSH_FXP_REALPATH_NO_CHECK:
                        break;
                    default:
                        log.warn("doRealPath({}) unknown control value 0x{} for path={}",
                                 getServerSession(), Integer.toHexString(control), p);
                }
            }
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendPath(BufferUtils.clear(buffer), id, result.getFirst(), attrs);
    }

    protected Pair<Path, Boolean> doRealPathV6(int id, String path, Collection<String> extraPaths, LinkOption... options) throws IOException {
        Path p = resolveFile(path);
        int numExtra = GenericUtils.size(extraPaths);
        if (numExtra > 0) {
            if (log.isDebugEnabled()) {
                log.debug("doRealPathV6({})[id={}] path={}, extra={}",
                          getServerSession(), id, path, extraPaths);
            }
            StringBuilder sb = new StringBuilder(GenericUtils.length(path) + numExtra * 8);
            sb.append(path);

            for (String p2 : extraPaths) {
                p = p.resolve(p2);
                sb.append('/').append(p2);
            }

            path = sb.toString();
        }

        return validateRealPath(id, path, p, options);
    }

    protected Pair<Path, Boolean> doRealPathV345(int id, String path, LinkOption... options) throws IOException {
        return validateRealPath(id, path, resolveFile(path), options);
    }

    /**
     * @param id      The request identifier
     * @param path    The original path
     * @param f       The resolve {@link Path}
     * @param options The {@link LinkOption}s to use to verify file existence and access
     * @return A {@link Pair} whose left-hand is the <U>absolute <B>normalized</B></U>
     * {@link Path} and right-hand is a {@link Boolean} indicating its status
     * @throws IOException If failed to validate the file
     * @see IoUtils#checkFileExists(Path, LinkOption...)
     */
    protected Pair<Path, Boolean> validateRealPath(int id, String path, Path f, LinkOption... options) throws IOException {
        Path p = normalize(f);
        Boolean status = IoUtils.checkFileExists(p, options);
        return new Pair<>(p, status);
    }

    protected void doRemoveDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        try {
            doRemoveDirectory(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRemoveDirectory(int id, String path, LinkOption... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doRemoveDirectory({})[id={}] SSH_FXP_RMDIR (path={})[{}]",
                      getServerSession(), id, path, p);
        }
        if (Files.isDirectory(p, options)) {
            doRemove(id, p);
        } else {
            throw new NotDirectoryException(p.toString());
        }
    }

    /**
     * Called when need to delete a file / directory - also informs the {@link SftpEventListener}
     *
     * @param id Deletion request ID
     * @param p {@link Path} to delete
     * @throws IOException If failed to delete
     */
    protected void doRemove(int id, Path p) throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.removing(session, p);
        try {
            Files.delete(p);
            listener.removed(session, p, null);
        } catch (IOException | RuntimeException e) {
            listener.removed(session, p, e);
            throw e;
        }
    }

    protected void doMakeDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        try {
            doMakeDirectory(id, path, attrs, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doMakeDirectory(int id, String path, Map<String, ?> attrs, LinkOption... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doMakeDirectory({})[id={}] SSH_FXP_MKDIR (path={}[{}], attrs={})",
                      getServerSession(), id, path, p, attrs);
        }

        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot validate make-directory existence for " + p);
        }

        if (status) {
            if (Files.isDirectory(p, options)) {
                throw new FileAlreadyExistsException(p.toString(), p.toString(), "Target directory already exists");
            } else {
                throw new FileNotFoundException(p.toString() + " already exists as a file");
            }
        } else {
            SftpEventListener listener = getSftpEventListenerProxy();
            ServerSession session = getServerSession();
            listener.creating(session, p, attrs);
            try {
                Files.createDirectory(p);
                doSetAttributes(p, attrs);
                listener.created(session, p, attrs, null);
            } catch (IOException | RuntimeException e) {
                listener.created(session, p, attrs, e);
                throw e;
            }
        }
    }

    protected void doRemove(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        try {
            doRemove(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRemove(int id, String path, LinkOption... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doRemove({})[id={}] SSH_FXP_REMOVE (path={}[{}])",
                      getServerSession(), id, path, p);
        }

        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot determine existence of remove candidate: " + p);
        }
        if (!status) {
            throw new FileNotFoundException(p.toString());
        } else if (Files.isDirectory(p, options)) {
            throw new SftpException(SftpConstants.SSH_FX_FILE_IS_A_DIRECTORY, p.toString() + " is a folder");
        } else {
            doRemove(id, p);
        }
    }

    protected void doReadDir(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doReadDir({})[id={}] SSH_FXP_READDIR (handle={}[{}])",
                      getServerSession(), id, handle, h);
        }

        Buffer reply = null;
        try {
            DirectoryHandle dh = validateHandle(handle, h, DirectoryHandle.class);
            if (dh.isDone()) {
                sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_EOF, "Directory reading is done");
                return;
            }

            Path file = dh.getFile();
            LinkOption[] options = IoUtils.getLinkOptions(false);
            Boolean status = IoUtils.checkFileExists(file, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot determine existence of read-dir for " + file);
            }

            if (!status) {
                throw new FileNotFoundException(file.toString());
            } else if (!Files.isDirectory(file, options)) {
                throw new NotDirectoryException(file.toString());
            } else if (!Files.isReadable(file)) {
                throw new AccessDeniedException("Not readable: " + file.toString());
            }

            if (dh.isSendDot() || dh.isSendDotDot() || dh.hasNext()) {
                // There is at least one file in the directory or we need to send the "..".
                // Send only a few files at a time to not create packets of a too
                // large size or have a timeout to occur.

                reply = BufferUtils.clear(buffer);
                reply.putByte((byte) SftpConstants.SSH_FXP_NAME);
                reply.putInt(id);
                int lenPos = reply.wpos();
                reply.putInt(0);

                int count = doReadDir(id, handle, dh, reply, PropertyResolverUtils.getIntProperty(getServerSession(), MAX_PACKET_LENGTH_PROP, DEFAULT_MAX_PACKET_LENGTH));
                BufferUtils.updateLengthPlaceholder(reply, lenPos, count);
                ServerSession session = getServerSession();
                if ((!dh.isSendDot()) && (!dh.isSendDotDot()) && (!dh.hasNext())) {
                    dh.markDone();
                }

                Boolean indicator = SftpHelper.indicateEndOfNamesList(reply, getVersion(), session, Boolean.valueOf(dh.isDone()));
                if (log.isDebugEnabled()) {
                    log.debug("doReadDir({})({})[{}] - seding {} entries - eol={}", session, handle, h, count, indicator);
                }
            } else {
                // empty directory
                dh.markDone();
                sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_EOF, "Empty directory");
                return;
            }

            ValidateUtils.checkNotNull(reply, "No reply buffer created");
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        send(reply);
    }

    protected void doOpenDir(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        String handle;

        try {
            handle = doOpenDir(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendHandle(BufferUtils.clear(buffer), id, handle);
    }

    protected String doOpenDir(int id, String path, LinkOption... options) throws IOException {
        Path p = resolveNormalizedLocation(path);
        if (log.isDebugEnabled()) {
            log.debug("doOpenDir({})[id={}] SSH_FXP_OPENDIR (path={})[{}]",
                      getServerSession(), id, path, p);
        }

        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot determine open-dir existence for " + p);
        }

        if (!status) {
            throw new FileNotFoundException(path);
        } else if (!Files.isDirectory(p, options)) {
            throw new NotDirectoryException(path);
        } else if (!Files.isReadable(p)) {
            throw new AccessDeniedException("Not readable: " + p);
        } else {
            String handle = generateFileHandle(p);
            DirectoryHandle dirHandle = new DirectoryHandle(p);
            SftpEventListener listener = getSftpEventListenerProxy();
            listener.open(getServerSession(), handle, dirHandle);
            handles.put(handle, dirHandle);
            return handle;
        }
    }

    protected void doFSetStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        try {
            doFSetStat(id, handle, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doFSetStat(int id, String handle, Map<String, ?> attrs) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doFsetStat({})[id={}] SSH_FXP_FSETSTAT (handle={}[{}], attrs={})",
                      getServerSession(), id, handle, h, attrs);
        }

        doSetAttributes(validateHandle(handle, h, Handle.class).getFile(), attrs);
    }

    protected void doSetStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        try {
            doSetStat(id, path, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doSetStat(int id, String path, Map<String, ?> attrs) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doSetStat({})[id={}] SSH_FXP_SETSTAT (path={}, attrs={})",
                      getServerSession(), id, path, attrs);
        }
        Path p = resolveFile(path);
        doSetAttributes(p, attrs);
    }

    protected void doFStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, ?> attrs;
        try {
            attrs = doFStat(id, handle, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String, Object> doFStat(int id, String handle, int flags) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doFStat({})[id={}] SSH_FXP_FSTAT (handle={}[{}], flags=0x{})",
                      getServerSession(), id, handle, h, Integer.toHexString(flags));
        }

        return resolveFileAttributes(validateHandle(handle, h, Handle.class).getFile(), flags, IoUtils.getLinkOptions(true));
    }

    protected void doLStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, ?> attrs;
        try {
            attrs = doLStat(id, path, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String, Object> doLStat(int id, String path, int flags) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doLStat({})[id={}] SSH_FXP_LSTAT (path={}[{}], flags=0x{})",
                      getServerSession(), id, path, p, Integer.toHexString(flags));
        }

        return resolveFileAttributes(p, flags, IoUtils.getLinkOptions(false));
    }

    protected void doWrite(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int length = buffer.getInt();
        try {
            doWrite(id, handle, offset, length, buffer.array(), buffer.rpos(), buffer.available());
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doWrite(int id, String handle, long offset, int length, byte[] data, int doff, int remaining) throws IOException {
        Handle h = handles.get(handle);
        if (log.isTraceEnabled()) {
            log.trace("doWrite({})[id={}] SSH_FXP_WRITE (handle={}[{}], offset={}, data=byte[{}])",
                      getServerSession(), id, handle, h, offset, length);
        }

        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        if (length < 0) {
            throw new IllegalStateException("Bad length (" + length + ") for writing to " + fh);
        }

        if (remaining < length) {
            throw new IllegalStateException("Not enough buffer data for writing to " + fh + ": required=" + length + ", available=" + remaining);
        }

        if (fh.isOpenAppend()) {
            fh.append(data, doff, length);
        } else {
            fh.write(data, doff, length, offset);
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.write(getServerSession(), handle, fh, offset, data, doff, length);
    }

    protected void doRead(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int requestedLength = buffer.getInt();
        int maxAllowed = PropertyResolverUtils.getIntProperty(getServerSession(), MAX_PACKET_LENGTH_PROP, DEFAULT_MAX_PACKET_LENGTH);
        int readLen = Math.min(requestedLength, maxAllowed);

        if (log.isTraceEnabled()) {
            log.trace("doRead({})[id={}]({})[offset={}] - req={}, max={}, effective={}",
                      getServerSession(), id, handle, offset, requestedLength, maxAllowed, readLen);
        }

        try {
            ValidateUtils.checkTrue(readLen >= 0, "Illegal requested read length: %d", readLen);

            buffer.clear();
            buffer.ensureCapacity(readLen + Long.SIZE /* the header */, Int2IntFunction.IDENTITY);

            buffer.putByte((byte) SftpConstants.SSH_FXP_DATA);
            buffer.putInt(id);
            int lenPos = buffer.wpos();
            buffer.putInt(0);

            int startPos = buffer.wpos();
            int len = doRead(id, handle, offset, readLen, buffer.array(), startPos);
            if (len < 0) {
                throw new EOFException("Unable to read " + readLen + " bytes from offset=" + offset + " of " + handle);
            }
            buffer.wpos(startPos + len);
            BufferUtils.updateLengthPlaceholder(buffer, lenPos, len);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        send(buffer);
    }

    protected int doRead(int id, String handle, long offset, int length, byte[] data, int doff) throws IOException {
        Handle h = handles.get(handle);
        if (log.isTraceEnabled()) {
            log.trace("doRead({})[id={}] SSH_FXP_READ (handle={}[{}], offset={}, length={})",
                      getServerSession(), id, handle, h, offset, length);
        }

        ValidateUtils.checkTrue(length > 0L, "Invalid read length: %d", length);
        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        int readLen = fh.read(data, doff, length, offset);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.read(getServerSession(), handle, fh, offset, data, doff, length, readLen);
        return readLen;
    }

    protected void doClose(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        try {
            doClose(id, handle);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "", "");
    }

    protected void doClose(int id, String handle) throws IOException {
        Handle h = handles.remove(handle);
        if (log.isDebugEnabled()) {
            log.debug("doClose({})[id={}] SSH_FXP_CLOSE (handle={}[{}])",
                      getServerSession(), id, handle, h);
        }
        validateHandle(handle, h, Handle.class).close();

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.close(getServerSession(), handle, h);
    }

    protected void doOpen(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        /*
         * Be consistent with FileChannel#open - if no mode specified then READ is assumed
         */
        int access = 0;
        if (version >= SftpConstants.SFTP_V5) {
            access = buffer.getInt();
            if (access == 0) {
                access = SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
            }
        }

        int pflags = buffer.getInt();
        if (pflags == 0) {
            pflags = SftpConstants.SSH_FXF_READ;
        }

        if (version < SftpConstants.SFTP_V5) {
            int flags = pflags;
            pflags = 0;
            switch (flags & (SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE)) {
                case SftpConstants.SSH_FXF_READ:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    break;
                case SftpConstants.SSH_FXF_WRITE:
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
                default:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
            }
            if ((flags & SftpConstants.SSH_FXF_APPEND) != 0) {
                access |= SftpConstants.ACE4_APPEND_DATA;
                pflags |= SftpConstants.SSH_FXF_APPEND_DATA | SftpConstants.SSH_FXF_APPEND_DATA_ATOMIC;
            }
            if ((flags & SftpConstants.SSH_FXF_CREAT) != 0) {
                if ((flags & SftpConstants.SSH_FXF_EXCL) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_NEW;
                } else if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_TRUNCATE;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_OR_CREATE;
                }
            } else {
                if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_TRUNCATE_EXISTING;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_EXISTING;
                }
            }
        }

        Map<String, Object> attrs = readAttrs(buffer);
        String handle;
        try {
            handle = doOpen(id, path, pflags, access, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendHandle(BufferUtils.clear(buffer), id, handle);
    }

    /**
     * @param id     Request id
     * @param path   Path
     * @param pflags Open mode flags - see {@code SSH_FXF_XXX} flags
     * @param access Access mode flags - see {@code ACE4_XXX} flags
     * @param attrs  Requested attributes
     * @return The assigned (opaque) handle
     * @throws IOException if failed to execute
     */
    protected String doOpen(int id, String path, int pflags, int access, Map<String, Object> attrs) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doOpen({})[id={}] SSH_FXP_OPEN (path={}, access=0x{}, pflags=0x{}, attrs={})",
                      getServerSession(), id, path, Integer.toHexString(access), Integer.toHexString(pflags), attrs);
        }
        int curHandleCount = handles.size();
        int maxHandleCount = PropertyResolverUtils.getIntProperty(getServerSession(), MAX_OPEN_HANDLES_PER_SESSION, DEFAULT_MAX_OPEN_HANDLES);
        if (curHandleCount > maxHandleCount) {
            throw new IllegalStateException("Too many open handles: current=" + curHandleCount + ", max.=" + maxHandleCount);
        }

        Path file = resolveFile(path);
        String handle = generateFileHandle(file);
        FileHandle fileHandle = new FileHandle(this, file, pflags, access, attrs);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.open(getServerSession(), handle, fileHandle);
        handles.put(handle, fileHandle);
        return handle;
    }

    // we stringify our handles and treat them as such on decoding as well as it is easier to use as a map key
    protected String generateFileHandle(Path file) {
        // use several rounds in case the file handle size is relatively small so we might get conflicts
        for (int index = 0; index < maxFileHandleRounds; index++) {
            randomizer.fill(workBuf, 0, fileHandleSize);
            String handle = BufferUtils.toHex(workBuf, 0, fileHandleSize, BufferUtils.EMPTY_HEX_SEPARATOR);
            if (handles.containsKey(handle)) {
                if (log.isTraceEnabled()) {
                    log.trace("generateFileHandle({})[{}] handle={} in use at round {}",
                              getServerSession(), file, handle, Integer.valueOf(index));
                }
                continue;
            }

            if (log.isTraceEnabled()) {
                log.trace("generateFileHandle({})[{}] {}", getServerSession(), file, handle);
            }
            return handle;
        }

        throw new IllegalStateException("Failed to generate a unique file handle for " + file);
    }

    protected void doInit(Buffer buffer, int id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doInit({})[id={}] SSH_FXP_INIT (version={})", getServerSession(), id, id);
        }

        String all = checkVersionCompatibility(buffer, id, id, SftpConstants.SSH_FX_OP_UNSUPPORTED);
        if (GenericUtils.isEmpty(all)) { // i.e. validation failed
            return;
        }

        version = id;
        while (buffer.available() > 0) {
            String name = buffer.getString();
            byte[] data = buffer.getBytes();
            extensions.put(name, data);
        }

        buffer.clear();

        buffer.putByte((byte) SftpConstants.SSH_FXP_VERSION);
        buffer.putInt(version);
        appendExtensions(buffer, all);

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.initialized(getServerSession(), version);

        send(buffer);
    }

    protected void appendExtensions(Buffer buffer, String supportedVersions) {
        appendVersionsExtension(buffer, supportedVersions);
        appendNewlineExtension(buffer, resolveNewlineValue(getServerSession()));
        appendVendorIdExtension(buffer, VersionProperties.getVersionProperties());
        appendOpenSSHExtensions(buffer);
        appendAclSupportedExtension(buffer);

        Map<String, OptionalFeature> extensions = getSupportedClientExtensions();
        int numExtensions = GenericUtils.size(extensions);
        List<String> extras = (numExtensions <= 0) ? Collections.<String>emptyList() : new ArrayList<String>(numExtensions);
        if (numExtensions > 0) {
            for (Map.Entry<String, OptionalFeature> ee : extensions.entrySet()) {
                String name = ee.getKey();
                OptionalFeature f = ee.getValue();
                if (!f.isSupported()) {
                    if (log.isDebugEnabled()) {
                        log.debug("appendExtensions({}) skip unsupported extension={}", getServerSession(), name);
                    }
                    continue;
                }

                extras.add(name);
            }
        }
        appendSupportedExtension(buffer, extras);
        appendSupported2Extension(buffer, extras);
    }

    protected int appendAclSupportedExtension(Buffer buffer) {
        ServerSession session = getServerSession();
        Collection<Integer> maskValues = resolveAclSupportedCapabilities(session);
        int mask = AclSupportedParser.AclCapabilities.constructAclCapabilities(maskValues);
        if (mask != 0) {
            if (log.isTraceEnabled()) {
                log.trace("appendAclSupportedExtension({}) capabilities={}",
                          session, AclSupportedParser.AclCapabilities.decodeAclCapabilities(mask));
            }

            buffer.putString(SftpConstants.EXT_ACL_SUPPORTED);

            // placeholder for length
            int lenPos = buffer.wpos();
            buffer.putInt(0);
            buffer.putInt(mask);
            BufferUtils.updateLengthPlaceholder(buffer, lenPos);
        }

        return mask;
    }

    protected Collection<Integer> resolveAclSupportedCapabilities(ServerSession session) {
        String override = PropertyResolverUtils.getString(session, ACL_SUPPORTED_MASK_PROP);
        if (override == null) {
            return DEFAULT_ACL_SUPPORTED_MASK;
        }

        // empty means not supported
        if (log.isDebugEnabled()) {
            log.debug("resolveAclSupportedCapabilities({}) override='{}'", session, override);
        }

        if (override.length() == 0) {
            return Collections.emptySet();
        }

        String[] names = GenericUtils.split(override, ',');
        Set<Integer> maskValues = new HashSet<Integer>(names.length);
        for (String n : names) {
            Integer v = ValidateUtils.checkNotNull(
                    AclSupportedParser.AclCapabilities.getAclCapabilityValue(n), "Unknown ACL capability: %s", n);
            maskValues.add(v);
        }

        return maskValues;
    }

    protected List<OpenSSHExtension> appendOpenSSHExtensions(Buffer buffer) {
        List<OpenSSHExtension> extList = resolveOpenSSHExtensions(getServerSession());
        if (GenericUtils.isEmpty(extList)) {
            return extList;
        }

        for (OpenSSHExtension ext : extList) {
            buffer.putString(ext.getName());
            buffer.putString(ext.getVersion());
        }

        return extList;
    }

    protected List<OpenSSHExtension> resolveOpenSSHExtensions(ServerSession session) {
        String value = PropertyResolverUtils.getString(session, OPENSSH_EXTENSIONS_PROP);
        if (value == null) {    // No override
            return DEFAULT_OPEN_SSH_EXTENSIONS;
        }

        if (log.isDebugEnabled()) {
            log.debug("resolveOpenSSHExtensions({}) override='{}'", session, value);
        }

        String[] pairs = GenericUtils.split(value, ',');
        int numExts = GenericUtils.length(pairs);
        if (numExts <= 0) {     // User does not want to report ANY extensions
            return Collections.emptyList();
        }

        List<OpenSSHExtension> extList = new ArrayList<>(numExts);
        for (String nvp : pairs) {
            nvp = GenericUtils.trimToEmpty(nvp);
            if (GenericUtils.isEmpty(nvp)) {
                continue;
            }

            int pos = nvp.indexOf('=');
            ValidateUtils.checkTrue((pos > 0) && (pos < (nvp.length() - 1)), "Malformed OpenSSH extension spec: %s", nvp);
            String name = GenericUtils.trimToEmpty(nvp.substring(0, pos));
            String version = GenericUtils.trimToEmpty(nvp.substring(pos + 1));
            extList.add(new OpenSSHExtension(name, ValidateUtils.checkNotNullAndNotEmpty(version, "No version specified for OpenSSH extension %s", name)));
        }

        return extList;
    }

    protected Map<String, OptionalFeature> getSupportedClientExtensions() {
        ServerSession session = getServerSession();
        String value = PropertyResolverUtils.getString(session, CLIENT_EXTENSIONS_PROP);
        if (value == null) {
            return DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;
        }

        if (log.isDebugEnabled()) {
            log.debug("getSupportedClientExtensions({}) override='{}'", session, value);
        }

        if (value.length() <= 0) {  // means don't report any extensions
            return Collections.emptyMap();
        }

        if (value.indexOf(',') <= 0) {
            return Collections.singletonMap(value, OptionalFeature.TRUE);
        }

        String[] comps = GenericUtils.split(value, ',');
        Map<String, OptionalFeature> result = new LinkedHashMap<>(comps.length);
        for (String c : comps) {
            result.put(c, OptionalFeature.TRUE);
        }

        return result;
    }

    /**
     * Appends the &quot;versions&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param value  The recommended value - ignored if {@code null}/empty
     * @see SftpConstants#EXT_VERSIONS
     */
    protected void appendVersionsExtension(Buffer buffer, String value) {
        if (GenericUtils.isEmpty(value)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendVersionsExtension({}) value={}", getServerSession(), value);
        }

        buffer.putString(SftpConstants.EXT_VERSIONS);
        buffer.putString(value);
    }

    /**
     * Appends the &quot;newline&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param value  The recommended value - ignored if {@code null}/empty
     * @see SftpConstants#EXT_NEWLINE
     */
    protected void appendNewlineExtension(Buffer buffer, String value) {
        if (GenericUtils.isEmpty(value)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendNewlineExtension({}) value={}",
                      getServerSession(), BufferUtils.toHex(':', value.getBytes(StandardCharsets.UTF_8)));
        }

        buffer.putString(SftpConstants.EXT_NEWLINE);
        buffer.putString(value);
    }

    protected String resolveNewlineValue(ServerSession session) {
        String value = PropertyResolverUtils.getString(session, NEWLINE_VALUE);
        if (value == null) {
            return IoUtils.EOL;
        } else {
            return value;   // empty means disabled
        }
    }

    /**
     * Appends the &quot;vendor-id&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     *
     * @param buffer            The {@link Buffer} to append to
     * @param versionProperties The currently available version properties - ignored
     *                          if {@code null}/empty. The code expects the following values:
     *                          <UL>
     *                              <LI>{@code groupId} - as the vendor name</LI>
     *                              <LI>{@code artifactId} - as the product name</LI>
     *                              <LI>{@code version} - as the product version</LI>
     *                          </UL>
     * @see SftpConstants#EXT_VENDOR_ID
     * @see <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09 - section 4.4</A>
     */
    protected void appendVendorIdExtension(Buffer buffer, Map<String, ?> versionProperties) {
        if (GenericUtils.isEmpty(versionProperties)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendVendorIdExtension({}): {}", getServerSession(), versionProperties);
        }
        buffer.putString(SftpConstants.EXT_VENDOR_ID);

        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(Collections.unmodifiableMap(versionProperties));
        // placeholder for length
        int lenPos = buffer.wpos();
        buffer.putInt(0);
        buffer.putString(PropertyResolverUtils.getStringProperty(resolver, "groupId", getClass().getPackage().getName()));   // vendor-name
        buffer.putString(PropertyResolverUtils.getStringProperty(resolver, "artifactId", getClass().getSimpleName()));       // product-name
        buffer.putString(PropertyResolverUtils.getStringProperty(resolver, "version", FactoryManager.DEFAULT_VERSION));      // product-version
        buffer.putLong(0L); // product-build-number
        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    /**
     * Appends the &quot;supported&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported
     *               - may be {@code null}/empty
     */
    protected void appendSupportedExtension(Buffer buffer, Collection<String> extras) {
        buffer.putString(SftpConstants.EXT_SUPPORTED);

        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_SIZE | SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS
                | SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME | SftpConstants.SSH_FILEXFER_ATTR_CREATETIME
                | SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME | SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP
                | SftpConstants.SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_APPEND
                | SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_TRUNC | SftpConstants.SSH_FXF_EXCL);
        // TODO: supported-access-mask
        buffer.putInt(0);
        // max-read-size
        buffer.putInt(0);
        // supported extensions
        buffer.putStringList(extras, false);

        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    /**
     * Appends the &quot;supported2&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported
     *               - may be {@code null}/empty
     * @see SftpConstants#EXT_SUPPORTED
     * @see <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10">DRAFT 13 section 5.4</A>
     */
    protected void appendSupported2Extension(Buffer buffer, Collection<String> extras) {
        buffer.putString(SftpConstants.EXT_SUPPORTED2);

        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_SIZE | SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS
                | SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME | SftpConstants.SSH_FILEXFER_ATTR_CREATETIME
                | SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME | SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP
                | SftpConstants.SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SftpConstants.SSH_FXF_ACCESS_DISPOSITION | SftpConstants.SSH_FXF_APPEND_DATA);
        // TODO: supported-access-mask
        buffer.putInt(0);
        // max-read-size
        buffer.putInt(0);
        // supported-open-block-vector
        buffer.putShort(0);
        // supported-block-vector
        buffer.putShort(0);
        // attrib-extension-count + attributes name
        buffer.putStringList(Collections.<String>emptyList(), true);
        // extension-count + supported extensions
        buffer.putStringList(extras, true);

        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    protected void sendHandle(Buffer buffer, int id, String handle) throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        send(buffer);
    }

    protected void sendAttrs(Buffer buffer, int id, Map<String, ?> attributes) throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, attributes);
        send(buffer);
    }

    protected void sendLink(Buffer buffer, int id, String link) throws IOException {
        //in case we are running on Windows
        String unixPath = link.replace(File.separatorChar, '/');
        //normalize the given path, use *nix style separator
        String normalizedPath = SelectorUtils.normalizePath(unixPath, "/");

        buffer.putByte((byte) SftpConstants.SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);   // one response
        buffer.putString(normalizedPath);

        /*
         * As per the spec (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.10):
         *
         *      The server will respond with a SSH_FXP_NAME packet containing only
         *      one name and a dummy attributes value.
         */
        Map<String, Object> attrs = Collections.<String, Object>emptyMap();
        if (version == SftpConstants.SFTP_V3) {
            buffer.putString(SftpHelper.getLongName(normalizedPath, attrs));
        }

        writeAttrs(buffer, attrs);
        SftpHelper.indicateEndOfNamesList(buffer, getVersion(), getServerSession());
        send(buffer);
    }

    protected void sendPath(Buffer buffer, int id, Path f, Map<String, ?> attrs) throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);   // one reply

        String originalPath = f.toString();
        //in case we are running on Windows
        String unixPath = originalPath.replace(File.separatorChar, '/');
        //normalize the given path, use *nix style separator
        String normalizedPath = SelectorUtils.normalizePath(unixPath, "/");
        if (normalizedPath.length() == 0) {
            normalizedPath = "/";
        }
        buffer.putString(normalizedPath);

        if (version == SftpConstants.SFTP_V3) {
            f = resolveFile(normalizedPath);
            buffer.putString(getLongName(f, getShortName(f), attrs));
        }

        writeAttrs(buffer, attrs);
        SftpHelper.indicateEndOfNamesList(buffer, getVersion(), getServerSession());
        send(buffer);
    }

    /**
     * @param id      Request id
     * @param handle  The (opaque) handle assigned to this directory
     * @param dir     The {@link DirectoryHandle}
     * @param buffer  The {@link Buffer} to write the results
     * @param maxSize Max. buffer size
     * @return Number of written entries
     * @throws IOException If failed to generate an entry
     */
    protected int doReadDir(int id, String handle, DirectoryHandle dir, Buffer buffer, int maxSize) throws IOException {
        int nb = 0;
        LinkOption[] options = IoUtils.getLinkOptions(false);
        Map<String, Path> entries = new TreeMap<>();
        while ((dir.isSendDot() || dir.isSendDotDot() || dir.hasNext()) && (buffer.wpos() < maxSize)) {
            if (dir.isSendDot()) {
                writeDirEntry(id, dir, entries, buffer, nb, dir.getFile(), ".", options);
                dir.markDotSent();    // do not send it again
            } else if (dir.isSendDotDot()) {
                writeDirEntry(id, dir, entries, buffer, nb, dir.getFile().getParent(), "..", options);
                dir.markDotDotSent(); // do not send it again
            } else {
                Path f = dir.next();
                writeDirEntry(id, dir, entries, buffer, nb, f, getShortName(f), options);
            }

            nb++;
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.read(getServerSession(), handle, dir, entries);
        return nb;
    }

    /**
     * @param id        Request id
     * @param dir       The {@link DirectoryHandle}
     * @param entries   An in / out {@link Map} for updating the written entry -
     *                  key = short name, value = entry {@link Path}
     * @param buffer    The {@link Buffer} to write the results
     * @param index     Zero-based index of the entry to be written
     * @param f         The entry {@link Path}
     * @param shortName The entry short name
     * @param options   The {@link LinkOption}s to use for querying the entry-s attributes
     * @throws IOException If failed to generate the entry data
     */
    protected void writeDirEntry(int id, DirectoryHandle dir, Map<String, Path> entries, Buffer buffer, int index, Path f, String shortName, LinkOption... options)
            throws IOException {
        Map<String, ?> attrs = resolveFileAttributes(f, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
        entries.put(shortName, f);

        buffer.putString(shortName);
        if (version == SftpConstants.SFTP_V3) {
            String longName = getLongName(f, shortName, options);
            buffer.putString(longName);
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(" + getServerSession() + ") id=" + id + ")[" + index + "] - "
                        + shortName + " [" + longName + "]: " + attrs);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(" + getServerSession() + "(id=" + id + ")[" + index + "] - "
                        + shortName + ": " + attrs);
            }
        }

        writeAttrs(buffer, attrs);
    }

    protected String getLongName(Path f, String shortName, LinkOption... options) throws IOException {
        return getLongName(f, shortName, true, options);
    }

    protected String getLongName(Path f, String shortName, boolean sendAttrs, LinkOption... options) throws IOException {
        Map<String, Object> attributes;
        if (sendAttrs) {
            attributes = getAttributes(f, options);
        } else {
            attributes = Collections.emptyMap();
        }
        return getLongName(f, shortName, attributes);
    }

    protected String getLongName(Path f, String shortName, Map<String, ?> attributes) throws IOException {
        return SftpHelper.getLongName(shortName, attributes);
    }

    protected String getShortName(Path f) throws IOException {
        Path nrm = normalize(f);
        int  count = nrm.getNameCount();
        /*
         * According to the javadoc:
         *
         *      The number of elements in the path, or 0 if this path only
         *      represents a root component
         */
        if (OsUtils.isUNIX()) {
            Path name = f.getFileName();
            if (name == null) {
                Path p = resolveFile(".");
                name = p.getFileName();
            }

            if (name == null) {
                if (count > 0) {
                    name = nrm.getFileName();
                }
            }

            if (name != null) {
                return name.toString();
            } else {
                return nrm.toString();
            }
        } else {    // need special handling for Windows root drives
            if (count > 0) {
                Path name = nrm.getFileName();
                return name.toString();
            } else {
                return nrm.toString().replace(File.separatorChar, '/');
            }
        }
    }

    protected Map<String, Object> resolveFileAttributes(Path file, int flags, LinkOption... options) throws IOException {
        Boolean status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            return handleUnknownStatusFileAttributes(file, flags, options);
        } else if (!status) {
            throw new FileNotFoundException(file.toString());
        } else {
            return getAttributes(file, flags, options);
        }
    }

    protected void writeAttrs(Buffer buffer, Map<String, ?> attributes) throws IOException {
        SftpHelper.writeAttrs(buffer, getVersion(), attributes);
    }

    protected Map<String, Object> getAttributes(Path file, LinkOption... options) throws IOException {
        return getAttributes(file, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
    }

    protected Map<String, Object> handleUnknownStatusFileAttributes(Path file, int flags, LinkOption... options) throws IOException {
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case ThrowException:
                throw new AccessDeniedException("Cannot determine existence for attributes of " + file);
            case Warn:
                log.warn("handleUnknownStatusFileAttributes(" + getServerSession() + ")[" + file + "] cannot determine existence");
                break;
            default:
                log.warn("handleUnknownStatusFileAttributes(" + getServerSession() + ")[" + file + "] unknown policy: " + unsupportedAttributePolicy);
        }

        return getAttributes(file, flags, options);
    }

    /**
     * @param file The {@link Path} location for the required attributes
     * @param flags A mask of the original required attributes - ignored by the
     * default implementation
     * @param options The {@link LinkOption}s to use in order to access the file
     * if necessary
     * @return A {@link Map} of the retrieved attributes
     * @throws IOException If failed to access the file
     * @see #resolveMissingFileAttributes(Path, int, Map, LinkOption...)
     */
    protected Map<String, Object> getAttributes(Path file, int flags, LinkOption ... options) throws IOException {
        FileSystem           fs = file.getFileSystem();
        Collection<String>   supportedViews = fs.supportedFileAttributeViews();
        Map<String, Object>  attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Collection<String>   views;

        if (GenericUtils.isEmpty(supportedViews)) {
            views = Collections.emptyList();
        } else if (supportedViews.contains("unix")) {
            views = DEFAULT_UNIX_VIEW;
        } else {
            views = new ArrayList<>(supportedViews.size());
            for (String v : supportedViews) {
                views.add(v + ":*");
            }
        }

        for (String v : views) {
            Map<String, Object> ta = readFileAttributes(file, v, options);
            if (GenericUtils.size(ta) > 0) {
                attrs.putAll(ta);
            }
        }

        Map<String, Object> completions = resolveMissingFileAttributes(file, flags, attrs, options);
        if (GenericUtils.size(completions) > 0) {
            attrs.putAll(completions);
        }

        return attrs;
    }

    /**
     * Called by {@link #getAttributes(Path, int, LinkOption...)} in order
     * to complete any attributes that could not be retrieved via the supported
     * file system views. These attributes are deemed important so an extra
     * effort is made to provide a value for them
     * @param file The {@link Path} location for the required attributes
     * @param flags A mask of the original required attributes - ignored by the
     * default implementation
     * @param current The {@link Map} of attributes already retrieved - may be
     * {@code null}/empty and/or unmodifiable
     * @param options The {@link LinkOption}s to use in order to access the file
     * if necessary
     * @return A {@link Map} of the extra attributes whose values need to be
     * updated in the original map. <B>Note:</B> it is allowed to specify values
     * which <U>override</U> existing ones - the default implementation does not
     * override values that have a non-{@code null} value
     * @throws IOException If failed to access the attributes - in which case
     * an <U>error</U> is returned to the SFTP client
     * @see #FILEATTRS_RESOLVERS
     */
    protected Map<String, Object> resolveMissingFileAttributes(Path file, int flags, Map<String, Object> current, LinkOption ... options) throws IOException {
        Map<String, Object> attrs = null;
        for (Map.Entry<String, FileInfoExtractor<?>> re : FILEATTRS_RESOLVERS.entrySet()) {
            String name = re.getKey();
            Object value = GenericUtils.isEmpty(current) ? null : current.get(name);
            FileInfoExtractor<?> x = re.getValue();
            try {
                Object resolved = resolveMissingFileAttributeValue(file, name, value, x, options);
                if (Objects.equals(resolved, value)) {
                    continue;
                }

                if (attrs == null) {
                    attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                }

                attrs.put(name, resolved);

                if (log.isDebugEnabled()) {
                    log.debug("resolveMissingFileAttributes({})[{}[{}]] replace {} with {}",
                              getServerSession(), file, name, value, resolved);
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("resolveMissingFileAttributes({})[{}[{}]] failed ({}) to resolve missing value: {}",
                              getServerSession(), file, name, e.getClass().getSimpleName(), e.getMessage());
                }
                if (log.isTraceEnabled()) {
                    log.trace("resolveMissingFileAttributes(" + getServerSession() + ")"
                            + "[" + file + "[" + name + "]] missing value resolution failure details", e);
                }
            }
        }

        if (attrs == null) {
            return Collections.emptyMap();
        } else {
            return attrs;
        }
    }

    protected Object resolveMissingFileAttributeValue(Path file, String name, Object value, FileInfoExtractor<?> x, LinkOption ... options) throws IOException {
        if (value != null) {
            return value;
        } else {
            return x.infoOf(file, options);
        }
    }

    protected Map<String, Object> addMissingAttribute(Path file, Map<String, Object> current, String name, FileInfoExtractor<?> x, LinkOption ... options) throws IOException {
        Object value = GenericUtils.isEmpty(current) ? null : current.get(name);
        if (value != null) {    // already have the value
            return current;
        }

        // skip if still no value
        value = x.infoOf(file, options);
        if (value == null) {
            return current;
        }

        if (current == null) {
            current = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        }

        current.put(name, value);
        return current;
    }

    protected Map<String, Object> readFileAttributes(Path file, String view, LinkOption ... options) throws IOException {
        try {
            return Files.readAttributes(file, view, options);
        } catch (IOException e) {
            return handleReadFileAttributesException(file, view, options, e);
        }
    }

    protected Map<String, Object> handleReadFileAttributesException(Path file, String view, LinkOption[] options, IOException e) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("handleReadFileAttributesException(" + file + ")[" + view + "] details", e);
        }

        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("handleReadFileAttributesException(" + file + ")[" + view + "] " + e.getClass().getSimpleName() + ": " + e.getMessage());
                break;
            case ThrowException:
                throw e;
            default:
                log.warn("handleReadFileAttributesException(" + file + ")[" + view + "]"
                       + " Unknown policy (" + unsupportedAttributePolicy + ")"
                       + " for " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        return Collections.emptyMap();
    }

    protected void doSetAttributes(Path file, Map<String, ?> attributes) throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.modifyingAttributes(session, file, attributes);
        try {
            setFileAttributes(file, attributes, IoUtils.getLinkOptions(false));
            listener.modifiedAttributes(session, file, attributes, null);
        } catch (IOException | RuntimeException e) {
            listener.modifiedAttributes(session, file, attributes, e);
            throw e;
        }
    }

    protected void setFileAttributes(Path file, Map<String, ?> attributes, LinkOption ... options) throws IOException {
        Set<String> unsupported = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, ?> ae : attributes.entrySet()) {
            String attribute = ae.getKey();
            Object value = ae.getValue();
            String view = null;
            switch (attribute) {
                case "size": {
                    long newSize = ((Number) value).longValue();
                    try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
                        channel.truncate(newSize);
                    }
                    continue;
                }
                case "uid":
                    view = "unix";
                    break;
                case "gid":
                    view = "unix";
                    break;
                case "owner":
                    view = "posix";
                    value = toUser(file, (UserPrincipal) value);
                    break;
                case "group":
                    view = "posix";
                    value = toGroup(file, (GroupPrincipal) value);
                    break;
                case "permissions":
                    view = "posix";
                    break;
                case "acl":
                    view = "acl";
                    break;
                case "creationTime":
                    view = "basic";
                    break;
                case "lastModifiedTime":
                    view = "basic";
                    break;
                case "lastAccessTime":
                    view = "basic";
                    break;
                case "extended":
                    view = "extended";
                    break;
                default:    // ignored
            }
            if ((GenericUtils.length(view) > 0) && (value != null)) {
                try {
                    setFileAttribute(file, view, attribute, value, options);
                } catch (Exception e) {
                    handleSetFileAttributeFailure(file, view, attribute, value, unsupported, e);
                }
            }
        }

        handleUnsupportedAttributes(unsupported);
    }

    protected void handleSetFileAttributeFailure(Path file, String view, String attribute, Object value, Collection<String> unsupported, Exception e) throws IOException {
        if (e instanceof UnsupportedOperationException) {
            if (log.isDebugEnabled()) {
                log.debug("handleSetFileAttributeFailure({})[{}] {}:{}={} unsupported: {}",
                          getServerSession(), file, view, attribute, value, e.getMessage());
            }
            unsupported.add(attribute);
        } else {
            log.warn("handleSetFileAttributeFailure({})[{}] {}:{}={} - failed ({}) to set: {}",
                     getServerSession(), file, view, attribute, value, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleSetFileAttributeFailure(" + getServerSession() + ")"
                        + "[" + file + "] " + view + ":" + attribute + "=" + value
                        + " failure details", e);
            }
            if (e instanceof IOException) {
                throw (IOException) e;
            } else {
                throw new IOException(e);
            }
        }
    }

    protected void setFileAttribute(Path file, String view, String attribute, Object value, LinkOption ... options) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("setFileAttribute({})[{}] {}:{}={}", getServerSession(), file, view, attribute, value);
        }

        if ("acl".equalsIgnoreCase(attribute) && "acl".equalsIgnoreCase(view)) {
            @SuppressWarnings("unchecked")
            List<AclEntry> acl = (List<AclEntry>) value;
            setFileAccessControl(file, acl, options);
        } else if ("permissions".equalsIgnoreCase(attribute)) {
            @SuppressWarnings("unchecked")
            Set<PosixFilePermission> perms = (Set<PosixFilePermission>) value;
            setFilePermissions(file, perms, options);
        } else if ("owner".equalsIgnoreCase(attribute) || "group".equalsIgnoreCase(attribute)) {
            setFileOwnership(file, attribute, (Principal) value, options);
        } else if ("creationTime".equalsIgnoreCase(attribute) || "lastModifiedTime".equalsIgnoreCase(attribute) || "lastAccessTime".equalsIgnoreCase(attribute)) {
            setFileTime(file, view, attribute, (FileTime) value, options);
        } else if ("extended".equalsIgnoreCase(view) && "extended".equalsIgnoreCase(attribute)) {
            @SuppressWarnings("unchecked")
            Map<String, byte[]> extensions = (Map<String, byte[]>) value;
            setFileExtensions(file, extensions, options);
        } else {
            Files.setAttribute(file, view + ":" + attribute, value, options);
        }
    }

    protected void setFileTime(Path file, String view, String attribute, FileTime value, LinkOption ... options) throws IOException {
        if (value == null) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("setFileTime({})[{}] {}:{}={}", getServerSession(), file, view, attribute, value);
        }

        Files.setAttribute(file, view + ":" + attribute, value, options);
    }

    protected void setFileOwnership(Path file, String attribute, Principal value, LinkOption ... options) throws IOException {
        if (value == null) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("setFileOwnership({})[{}] {}={}", getServerSession(), file, attribute, value);
        }

        /*
         * Quoting from Javadoc of FileOwnerAttributeView#setOwner:
         *
         *      To ensure consistent and correct behavior across platforms
         *      it is recommended that this method should only be used
         *      to set the file owner to a user principal that is not a group.
         */
        if ("owner".equalsIgnoreCase(attribute)) {
            FileOwnerAttributeView view = Files.getFileAttributeView(file, FileOwnerAttributeView.class, options);
            if (view == null) {
                throw new UnsupportedOperationException("Owner view not supported for " + file);
            }

            if (!(value instanceof UserPrincipal)) {
                throw new StreamCorruptedException("Owner is not " + UserPrincipal.class.getSimpleName() + ": " + value.getClass().getSimpleName());
            }

            view.setOwner((UserPrincipal) value);
        } else if ("group".equalsIgnoreCase(attribute)) {
            PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class, options);
            if (view == null) {
                throw new UnsupportedOperationException("POSIX view not supported");
            }

            if (!(value instanceof GroupPrincipal)) {
                throw new StreamCorruptedException("Group is not " + GroupPrincipal.class.getSimpleName() + ": " + value.getClass().getSimpleName());
            }

            view.setGroup((GroupPrincipal) value);
        } else {
            throw new UnsupportedOperationException("Unknown ownership attribute: " + attribute);
        }
    }

    protected void setFileExtensions(Path file, Map<String, byte[]> extensions, LinkOption ... options) throws IOException {
        if (GenericUtils.isEmpty(extensions)) {
            return;
        }

        /* According to v3,4,5:
         *
         *      Implementations SHOULD ignore extended data fields that they do not understand.
         *
         * But according to v6 (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-28):
         *      Implementations MUST return SSH_FX_UNSUPPORTED if there are any unrecognized extensions.
         */
        if (version < SftpConstants.SFTP_V6) {
            if (log.isDebugEnabled()) {
                log.debug("setFileExtensions({})[{}]: {}", getServerSession(), file, extensions);
            }
        } else {
            throw new UnsupportedOperationException("File extensions not supported");
        }
    }

    protected void setFilePermissions(Path file, Set<PosixFilePermission> perms, LinkOption ... options) throws IOException {
        if (OsUtils.isWin32()) {
            IoUtils.setPermissionsToFile(file.toFile(), perms);
            return;
        }

        PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("POSIX view not supported for " + file);
        }

        if (log.isTraceEnabled()) {
            log.trace("setFilePermissions({})[{}] {}", getServerSession(), file, perms);
        }
        view.setPermissions(perms);
    }

    protected void setFileAccessControl(Path file, List<AclEntry> acl, LinkOption ... options) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("ACL view not supported for " + file);
        }

        if (log.isTraceEnabled()) {
            log.trace("setFileAccessControl({})[{}] {}", getServerSession(), file, acl);
        }
        view.setAcl(acl);
    }

    protected void handleUnsupportedAttributes(Collection<String> attributes) {
        if (attributes.isEmpty()) {
            return;
        }

        String attrsList = GenericUtils.join(attributes, ',');
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("Unsupported attributes: " + attrsList);
                break;
            case ThrowException:
                throw new UnsupportedOperationException("Unsupported attributes: " + attrsList);
            default:
                log.warn("Unknown policy for attributes=" + attrsList + ": " + unsupportedAttributePolicy);
        }
    }

    protected GroupPrincipal toGroup(Path file, GroupPrincipal name) throws IOException {
        String groupName = name.toString();
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        try {
            if (lookupService == null) {
                throw new UserPrincipalNotFoundException(groupName);
            }
            return lookupService.lookupPrincipalByGroupName(groupName);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(GroupPrincipal.class, groupName, e);
            return null;
        }
    }

    protected UserPrincipal toUser(Path file, UserPrincipal name) throws IOException {
        String username = name.toString();
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        try {
            if (lookupService == null) {
                throw new UserPrincipalNotFoundException(username);
            }
            return lookupService.lookupPrincipalByName(username);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(UserPrincipal.class, username, e);
            return null;
        }
    }

    protected void handleUserPrincipalLookupServiceException(Class<? extends Principal> principalType, String name, IOException e) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("handleUserPrincipalLookupServiceException(" + principalType.getSimpleName() + "[" + name + "]) details", e);
        }

        /* According to Javadoc:
         *
         *      "Where an implementation does not support any notion of group
         *      or user then this method always throws UserPrincipalNotFoundException."
         */
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("handleUserPrincipalLookupServiceException(" + principalType.getSimpleName() + "[" + name + "])"
                        + " failed (" + e.getClass().getSimpleName() + "): " + e.getMessage());
                break;
            case ThrowException:
                throw e;
            default:
                log.warn("Unknown policy for principal=" + principalType.getSimpleName() + "[" + name + "]: " + unsupportedAttributePolicy);
        }
    }

    protected Map<String, Object> readAttrs(Buffer buffer) throws IOException {
        return SftpHelper.readAttrs(buffer, getVersion());
    }

    /**
     * Makes sure that the local handle is not null and of the specified type
     *
     * @param <H>    The generic handle type
     * @param handle The original handle id
     * @param h      The resolved {@link Handle} instance
     * @param type   The expected handle type
     * @return The cast type
     * @throws IOException If a generic exception occurred
     * @throws FileNotFoundException  If the handle instance is {@code null}
     * @throws InvalidHandleException If the handle instance is not of the expected type
     */
    protected <H extends Handle> H validateHandle(String handle, Handle h, Class<H> type) throws IOException {
        if (h == null) {
            throw new FileNotFoundException("No such current handle: " + handle);
        }

        Class<?> t = h.getClass();
        if (!type.isAssignableFrom(t)) {
            throw new InvalidHandleException(handle, h, type);
        }

        return type.cast(h);
    }

    protected void sendStatus(Buffer buffer, int id, Throwable e) throws IOException {
        int substatus = SftpHelper.resolveSubstatus(e);
        sendStatus(buffer, id, substatus, e.toString());
    }

    protected void sendStatus(Buffer buffer, int id, int substatus, String msg) throws IOException {
        sendStatus(buffer, id, substatus, (msg != null) ? msg : "", "");
    }

    protected void sendStatus(Buffer buffer, int id, int substatus, String msg, String lang) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doSendStatus({})[id={}] SSH_FXP_STATUS (substatus={}, lang={}, msg={})",
                      getServerSession(), id, SftpConstants.getStatusName(substatus), lang, msg);
        }

        buffer.putByte((byte) SftpConstants.SSH_FXP_STATUS);
        buffer.putInt(id);
        buffer.putInt(substatus);
        buffer.putString(msg);
        buffer.putString(lang);
        send(buffer);
    }

    protected void send(Buffer buffer) throws IOException {
        int len = buffer.available();
        BufferUtils.writeInt(out, len, workBuf, 0, workBuf.length);
        out.write(buffer.array(), buffer.rpos(), len);
        out.flush();
    }

    @Override
    public void destroy() {
        if (closed.getAndSet(true)) {
            return; // ignore if already closed
        }

        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("destroy({}) - mark as closed", session);
        }

        try {
            SftpEventListener listener = getSftpEventListenerProxy();
            listener.destroying(session);
        } catch (Exception e) {
            log.warn("destroy({}) Failed ({}) to announce destruction event: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("destroy(" + session + ") destruction announcement failure details", e);
            }
        }

        // if thread has not completed, cancel it
        if ((pendingFuture != null) && (!pendingFuture.isDone())) {
            boolean result = pendingFuture.cancel(true);
            // TODO consider waiting some reasonable (?) amount of time for cancellation
            if (log.isDebugEnabled()) {
                log.debug("destroy(" + session + ") - cancel pending future=" + result);
            }
        }

        pendingFuture = null;

        if ((executors != null) && (!executors.isShutdown()) && shutdownExecutor) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("destroy(" + session + ") - shutdown executor service - runners count=" + runners.size());
            }
        }

        executors = null;

        try {
            fileSystem.close();
        } catch (UnsupportedOperationException e) {
            if (log.isDebugEnabled()) {
                log.debug("destroy(" + session + ") closing the file system is not supported");
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("destroy(" + session + ")"
                        + " failed (" + e.getClass().getSimpleName() + ")"
                        + " to close file system: " + e.getMessage(), e);
            }
        }
    }

    protected Path resolveNormalizedLocation(String remotePath) throws IOException, InvalidPathException {
        return normalize(resolveFile(remotePath));
    }

    protected Path normalize(Path f) {
        if (f == null) {
            return null;
        }

        Path abs = f.isAbsolute() ? f : f.toAbsolutePath();
        return abs.normalize();
    }

    /**
     * @param remotePath The remote path - separated by '/'
     * @return The local {@link Path}
     * @throws IOException If failed to resolve the local path
     * @throws InvalidPathException If bad local path specification
     */
    protected Path resolveFile(String remotePath) throws IOException, InvalidPathException {
        String path = SelectorUtils.translateToLocalFileSystemPath(remotePath, '/', defaultDir.getFileSystem());
        Path p = defaultDir.resolve(path);
        if (log.isTraceEnabled()) {
            log.trace("resolveFile({}) {} => {}", getServerSession(), remotePath, p);
        }
        return p;
    }
}
