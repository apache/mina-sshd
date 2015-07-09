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
package org.apache.sshd.server.subsystem.sftp;

import static org.apache.sshd.common.subsystem.sftp.SftpConstants.*;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemLoopException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.VersionProperties;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Int2IntFunction;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem extends AbstractLoggingBean implements Command, Runnable, SessionAware, FileSystemAware {

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final String MAX_OPEN_HANDLES_PER_SESSION = "max-open-handles-per-session";
        public static final int DEFAULT_MAX_OPEN_HANDLES = Integer.MAX_VALUE;

    /**
     * Size in bytes of the opaque handle value
     * @see #DEFAULT_FILE_HANDLE_SIZE
     */
    public static final String FILE_HANDLE_SIZE = "sftp-handle-size";
        public static final int MIN_FILE_HANDLE_SIZE = 4;  // ~uint32
        public static final int DEFAULT_FILE_HANDLE_SIZE = 16;
        public static final int MAX_FILE_HANDLE_SIZE = 64;  // ~sha512 

    /**
     * Max. rounds to attempt to create a unique file handle - if all handles
     * already in use after these many rounds, then an exception is thrown
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

    public static final int LOWER_SFTP_IMPL = SFTP_V3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = SFTP_V6; //  .. up to
    public static final String ALL_SFTP_IMPL;
    
    /**
     * Force the use of a max. packet length - especially for {@link #doReadDir(Buffer, int)}
     * @see #DEFAULT_MAX_PACKET_LENGTH
     */
    public static final String MAX_PACKET_LENGTH_PROP = "sftp-max-packet-length";
        public static final int  DEFAULT_MAX_PACKET_LENGTH = 1024 * 16;
   
    /**
     * Allows controlling reports of which client extensions are supported
     * (and reported via &quot;support&quot; and &quot;support2&quot; server
     * extensions) as a comma-separate list of names. <B>Note:</B> requires
     * overriding the {@link #executeExtendedCommand(Buffer, int, String)}
     * command accordingly. If empty string is set then no server extensions
     * are reported
     * @see #DEFAULT_SUPPORTED_CLIENT_EXTENSIONS
     */
    public static final String CLIENT_EXTENSIONS_PROP = "sftp-client-extensions";
        /**
         * The default reported supported client extensions
         */
        public static final Set<String> DEFAULT_SUPPORTED_CLIENT_EXTENSIONS =
                // TODO text-seek - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-13.txt
                // TODO space-available - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
                // TODO home-directory - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
                // TODO check-file-handle/check-file-name - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.2
                Collections.unmodifiableSet(
                        GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                                Arrays.asList(
                                        SftpConstants.EXT_VERSELECT,
                                        SftpConstants.EXT_COPYFILE,
                                        SftpConstants.EXT_MD5HASH,
                                        SftpConstants.EXT_MD5HASH_HANDLE,
                                        SftpConstants.EXT_CHKFILE_HANDLE,
                                        SftpConstants.EXT_CHKFILE_NAME,
                                        SftpConstants.EXT_COPYDATA
                                )));

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
    protected ServerSession session;
    protected boolean closed;
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

    protected static abstract class Handle implements java.io.Closeable {
        private Path file;

        public Handle(Path file) {
            this.file = file;
        }

        public Path getFile() {
            return file;
        }

        @Override
        public void close() throws IOException {
            // ignored
        }

        @Override
        public String toString() {
            return Objects.toString(getFile());
        }
    }

    protected static class InvalidHandleException extends IOException {
        private static final long serialVersionUID = -1686077114375131889L;

        public InvalidHandleException(String handle, Handle h, Class<? extends Handle> expected) {
            super(handle + "[" + h + "] is not a " + expected.getSimpleName());
        }
    }

    protected static class DirectoryHandle extends Handle implements Iterator<Path> {
        private boolean done, sendDotDot, sendDot=true;
        // the directory should be read once at "open directory"
        private DirectoryStream<Path> ds;
        private Iterator<Path> fileList;

        public DirectoryHandle(Path file) throws IOException {
            super(file);
            ds = Files.newDirectoryStream(file);
            
            Path parent = file.getParent();
            sendDotDot = (parent != null);  // if no parent then no need to send ".."
            fileList = ds.iterator();
        }

        public boolean isDone() {
            return done;
        }

        public void markDone() {
            this.done = true;
            // allow the garbage collector to do the job
            this.fileList = null;
        }

        public boolean isSendDot() {
            return sendDot;
        }
        
        public void markDotSent() {
            sendDot = false;
        }

        public boolean isSendDotDot() {
            return sendDotDot;
        }
        
        public void markDotDotSent() {
            sendDotDot = false;
        }

        @Override
        public boolean hasNext() {
            return fileList.hasNext();
        }

        @Override
        public Path next() {
            return fileList.next();
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("Not allowed to remove " + toString());
        }

        @Override
        public void close() throws IOException {
            markDone(); // just making sure
            ds.close();
        }
    }

    protected class FileHandle extends Handle {
        private final int access;
        private final FileChannel channel;
        private long pos;
        private final List<FileLock> locks = new ArrayList<>();

        public FileHandle(Path file, int flags, int access, Map<String, Object> attrs) throws IOException {
            super(file);
            this.access = access;

            Set<OpenOption> options = new HashSet<>();
            if (((access & ACE4_READ_DATA) != 0) || ((access & ACE4_READ_ATTRIBUTES) != 0)) {
                options.add(StandardOpenOption.READ);
            }
            if (((access & ACE4_WRITE_DATA) != 0) || ((access & ACE4_WRITE_ATTRIBUTES) != 0)) {
                options.add(StandardOpenOption.WRITE);
            }
            switch (flags & SSH_FXF_ACCESS_DISPOSITION) {
                case SSH_FXF_CREATE_NEW:
                    options.add(StandardOpenOption.CREATE_NEW);
                    break;
                case SSH_FXF_CREATE_TRUNCATE:
                    options.add(StandardOpenOption.CREATE);
                    options.add(StandardOpenOption.TRUNCATE_EXISTING);
                    break;
                case SSH_FXF_OPEN_EXISTING:
                    break;
                case SSH_FXF_OPEN_OR_CREATE:
                    options.add(StandardOpenOption.CREATE);
                    break;
                case SSH_FXF_TRUNCATE_EXISTING:
                    options.add(StandardOpenOption.TRUNCATE_EXISTING);
                    break;
                default:    // ignored
            }
            if ((flags & SSH_FXF_APPEND_DATA) != 0) {
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
                setAttributes(file, attrs);
            }
            this.channel = channel;
            this.pos = 0;
        }

        public int getAccessMask() {
            return access;
        }

        public int read(byte[] data, long offset) throws IOException {
            return read(data, 0, data.length, offset);
        }

        public int read(byte[] data, int doff, int length, long offset) throws IOException {
            if (pos != offset) {
                channel.position(offset);
                pos = offset;
            }
            int read = channel.read(ByteBuffer.wrap(data, doff, length));
            pos += read;
            return read;
        }

        public void write(byte[] data, long offset) throws IOException {
            write(data, 0, data.length, offset);
        }

        public void write(byte[] data, int doff, int length, long offset) throws IOException {
            if (pos != offset) {
                channel.position(offset);
                pos = offset;
            }
            channel.write(ByteBuffer.wrap(data, doff, length));
            pos += length;
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }

        public void lock(long offset, long length, int mask) throws IOException {
            long size = length == 0 ? channel.size() - offset : length;
            FileLock lock = channel.tryLock(offset, size, false);
            synchronized (locks) {
                locks.add(lock);
            }
        }

        public boolean unlock(long offset, long length) throws IOException {
            long size = length == 0 ? channel.size() - offset : length;
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

    /**
     * @param executorService The {@link ExecutorService} to be used by
     *                        the {@link SftpSubsystem} command when starting execution. If
     *                        {@code null} then a single-threaded ad-hoc service is used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when subsystem terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @param policy The {@link UnsupportedAttributePolicy} to use if failed to access
     * some local file attributes
     * @see ThreadUtils#newSingleThreadExecutor(String)
     */
    public SftpSubsystem(ExecutorService executorService, boolean shutdownOnExit, UnsupportedAttributePolicy policy) {
        if ((executors = executorService) == null) {
            executors = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
            shutdownExecutor = true;    // we always close the ad-hoc executor service
        } else {
            shutdownExecutor = shutdownOnExit;
        }
        
        if ((unsupportedAttributePolicy=policy) == null) {
            throw new IllegalArgumentException("No policy provided");
        }
    }

    public int getVersion() {
        return version;
    }

    public final UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return unsupportedAttributePolicy;
    }

    @Override
    public void setSession(ServerSession session) {
        this.session = session;
        
        FactoryManager manager = session.getFactoryManager();
        Factory<? extends Random> factory = manager.getRandomFactory();
        this.randomizer = factory.create();

        this.fileHandleSize = FactoryManagerUtils.getIntProperty(manager, FILE_HANDLE_SIZE, DEFAULT_FILE_HANDLE_SIZE);
        ValidateUtils.checkTrue(this.fileHandleSize >= MIN_FILE_HANDLE_SIZE, "File handle size too small: %d", this.fileHandleSize);
        ValidateUtils.checkTrue(this.fileHandleSize <= MAX_FILE_HANDLE_SIZE, "File handle size too big: %d", this.fileHandleSize);

        this.maxFileHandleRounds = FactoryManagerUtils.getIntProperty(manager, MAX_FILE_HANDLE_RAND_ROUNDS, DEFAULT_FILE_HANDLE_ROUNDS);
        ValidateUtils.checkTrue(this.maxFileHandleRounds >= MIN_FILE_HANDLE_ROUNDS, "File handle rounds too small: %d", this.maxFileHandleRounds);
        ValidateUtils.checkTrue(this.maxFileHandleRounds <= MAX_FILE_HANDLE_ROUNDS, "File handle rounds too big: %d", this.maxFileHandleRounds);
        
        if (workBuf.length < this.fileHandleSize) {
            workBuf = new byte[this.fileHandleSize];
        }
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        if (fileSystem != this.fileSystem) {
            this.fileSystem = fileSystem;
            this.defaultDir = fileSystem.getRootDirectories().iterator().next();
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
        DataInputStream dis = null;
        try {
            dis = new DataInputStream(in);
            while (true) {
                int length = dis.readInt();
                if (length < 5) {
                    throw new IllegalArgumentException("Bad length to read: " + length);
                }
                Buffer buffer = new ByteArrayBuffer(length + 4);
                buffer.putInt(length);
                int nb = length;
                while (nb > 0) {
                    int l = dis.read(buffer.array(), buffer.wpos(), nb);
                    if (l < 0) {
                        throw new IllegalArgumentException("Premature EOF while read length=" + length + " while remain=" + nb);
                    }
                    buffer.wpos(buffer.wpos() + l);
                    nb -= l;
                }
                process(buffer);
            }
        } catch (Throwable t) {
            if (!closed && !(t instanceof EOFException)) { // Ignore
                log.error("Exception caught in SFTP subsystem", t);
            }
        } finally {
            if (dis != null) {
                try {
                    dis.close();
                } catch (IOException ioe) {
                    log.error("Could not close DataInputStream", ioe);
                }
            }

            if (handles != null) {
                for (Map.Entry<String, Handle> entry : handles.entrySet()) {
                    Handle handle = entry.getValue();
                    try {
                        handle.close();
                    } catch (IOException ioe) {
                        log.error("Could not close open handle: " + entry.getKey(), ioe);
                    }
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
            log.debug("process(length={}, type={}, id={})",
                      Integer.valueOf(length), Integer.valueOf(type), Integer.valueOf(id));
        }

        switch (type) {
            case SSH_FXP_INIT:
                doInit(buffer, id);
                break;
            case SSH_FXP_OPEN:
                doOpen(buffer, id);
                break;
            case SSH_FXP_CLOSE:
                doClose(buffer, id);
                break;
            case SSH_FXP_READ:
                doRead(buffer, id);
                break;
            case SSH_FXP_WRITE:
                doWrite(buffer, id);
                break;
            case SSH_FXP_LSTAT:
                doLStat(buffer, id);
                break;
            case SSH_FXP_FSTAT:
                doFStat(buffer, id);
                break;
            case SSH_FXP_SETSTAT:
                doSetStat(buffer, id);
                break;
            case SSH_FXP_FSETSTAT:
                doFSetStat(buffer, id);
                break;
            case SSH_FXP_OPENDIR:
                doOpenDir(buffer, id);
                break;
            case SSH_FXP_READDIR:
                doReadDir(buffer, id);
                break;
            case SSH_FXP_REMOVE:
                doRemove(buffer, id);
                break;
            case SSH_FXP_MKDIR:
                doMakeDirectory(buffer, id);
                break;
            case SSH_FXP_RMDIR:
                doRemoveDirectory(buffer, id);
                break;
            case SSH_FXP_REALPATH:
                doRealPath(buffer, id);
                break;
            case SSH_FXP_STAT:
                doStat(buffer, id);
                break;
            case SSH_FXP_RENAME:
                doRename(buffer, id);
                break;
            case SSH_FXP_READLINK:
                doReadLink(buffer, id);
                break;
            case SSH_FXP_SYMLINK:
                doSymLink(buffer, id);
                break;
            case SSH_FXP_LINK:
                doLink(buffer, id);
                break;
            case SSH_FXP_BLOCK:
                doBlock(buffer, id);
                break;
            case SSH_FXP_UNBLOCK:
                doUnblock(buffer, id);
                break;
            case SSH_FXP_EXTENDED:
                doExtended(buffer, id);
                break;
            default:
                log.warn("Unknown command type received: {}", Integer.valueOf(type));
                sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OP_UNSUPPORTED, "Command " + type + " is unsupported or not implemented");
        }

        if (type != SSH_FXP_INIT) {
            requestsCount++;
        }
    }

    protected void doExtended(Buffer buffer, int id) throws IOException {
        executeExtendedCommand(buffer, id, buffer.getString());
    }

    /**
     * @param buffer The command {@link Buffer}
     * @param id  The request id
     * @param extension The extension name
     * @throws IOException If failed to execute the extension
     */
    protected void executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
        switch (extension) {
            case "text-seek":
                doTextSeek(buffer, id);
                break;
            case SftpConstants.EXT_VERSELECT:
                doVersionSelect(buffer, id);
                break;
            case SftpConstants.EXT_COPYFILE:
                doCopyFile(buffer, id);
                break;
            case SftpConstants.EXT_COPYDATA:
                doCopyData(buffer, id);
                break;
            case SftpConstants.EXT_MD5HASH:
            case SftpConstants.EXT_MD5HASH_HANDLE:
                doMD5Hash(buffer, id, extension);
                break;
            case SftpConstants.EXT_CHKFILE_HANDLE:
            case SftpConstants.EXT_CHKFILE_NAME:
                doCheckFileHash(buffer, id, extension);
                break;
            default:
                log.info("Received unsupported SSH_FXP_EXTENDED({})", extension);
                sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_EXTENDED(" + extension + ") is unsupported or not implemented");
                break;
        }
    }

    protected void doTextSeek(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long line = buffer.getLong();
        try {
            // TODO : implement text-seek - see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-03#section-6.3
            doTextSeek(id, handle, line);
        } catch(IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doTextSeek(int id, String handle, long line) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_EXTENDED(text-seek) (handle={}[{}], line={})", handle, h, Long.valueOf(line));
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        throw new UnsupportedOperationException("doTextSeek(" + fileHandle + ")");
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
            buffer.putByte((byte) SSH_FXP_EXTENDED_REPLY);
            buffer.putInt(id);
            buffer.putString(SftpConstants.EXT_CHKFILE_RESPONSE);
            doCheckFileHash(id, targetType, target, Arrays.asList(algos), startOffset, length, blockSize, buffer);
        } catch(Exception e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }
        
        send(buffer);
    }

    protected void doCheckFileHash(int id, String targetType, String target, Collection<String> algos,
                                   long startOffset, long length, int blockSize, Buffer buffer)
                    throws Exception {
        Path path;
        if (SftpConstants.EXT_CHKFILE_HANDLE.equalsIgnoreCase(targetType)) {
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
            if ((access & ACE4_READ_DATA) == 0) {
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
            for (int index=0; Files.isSymbolicLink(path) && (index < Byte.MAX_VALUE /* TODO make this configurable */); index++) {
                path = Files.readSymbolicLink(path);
            }
            
            if (Files.isSymbolicLink(path)) {
                throw new FileSystemLoopException(target + " yields a circular or too long chain of symlinks");
            }

            if (Files.isDirectory(path, IoUtils.getLinkOptions(false))) {
                throw new NotDirectoryException(path.toString());
            }
        }

        ValidateUtils.checkNotNullAndNotEmpty(algos, "No hash algorithms specified", GenericUtils.EMPTY_OBJECT_ARRAY);
        
        NamedFactory<? extends Digest> factory = null;
        for (String a : algos) {
            if ((factory = BuiltinDigests.fromFactoryName(a)) != null) {
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
        ValidateUtils.checkNotNull(factory, "No digest factory provided", GenericUtils.EMPTY_OBJECT_ARRAY);
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
                       : new byte[Math.min((int) effectiveLength, blockSize)]
                       ;
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        try(FileChannel channel = FileChannel.open(file, IoUtils.EMPTY_OPEN_OPTIONS)) {
            channel.position(startOffset);

            Digest digest = factory.create();
            digest.init();

            if (blockSize == 0) {
                while(effectiveLength > 0L) {
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
                    log.trace("doCheckFileHash({}) offset={}, length={} - hash={}",
                              file, Long.valueOf(startOffset), Long.valueOf(length),
                              BufferUtils.printHex(':', hashValue));
                }
                buffer.putBytes(hashValue);
            } else {
                for (int count=0; effectiveLength > 0L; count++) {
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
                        log.trace("doCheckFileHash({})[{}] offset={}, length={} - hash={}",
                                  file, Integer.valueOf(count), Long.valueOf(startOffset), Long.valueOf(length),
                                  BufferUtils.printHex(':', hashValue));
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
        byte[] quickCheckHash = buffer.getBytes(), hashValue;
        
        try {
            hashValue = doMD5Hash(id, targetType, target, startOffset, length, quickCheckHash);
            if (log.isTraceEnabled()) {
                log.debug("doMD5Hash({})[{}] offset={}, length={}, quick-hash={} - hash={}",
                          targetType, target, Long.valueOf(startOffset), Long.valueOf(length), BufferUtils.printHex(':', quickCheckHash),
                          BufferUtils.printHex(':', hashValue));
            }

        } catch(Exception e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        buffer.clear();
        buffer.putByte((byte) SSH_FXP_EXTENDED_REPLY);
        buffer.putInt(id);
        buffer.putString(targetType);
        buffer.putBytes(hashValue);
        send(buffer);
    }

    protected byte[] doMD5Hash(int id, String targetType, String target, long startOffset, long length, byte[] quickCheckHash) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("doMD5Hash({})[{}] offset={}, length={}, quick-hash={}",
                      targetType, target, Long.valueOf(startOffset), Long.valueOf(length), BufferUtils.printHex(':', quickCheckHash));
        }

        Path path;
        if (SftpConstants.EXT_MD5HASH_HANDLE.equalsIgnoreCase(targetType)) {
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
            if ((access & ACE4_READ_DATA) == 0) {
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
        long effectiveLength = length, totalSize = Files.size(path);
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

        Digest digest = BuiltinDigests.md5.create();
        digest.init();

        long effectiveLength = length;
        byte[] digestBuf = new byte[(int) Math.min(effectiveLength, SftpConstants.MD5_QUICK_HASH_SIZE)];
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        boolean hashMatches = false;
        byte[] hashValue = null;

        try(FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            channel.position(startOffset);

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section 9.1.1:
             * 
             *      If this is a zero length string, the client does not have the
             *      data, and is requesting the hash for reasons other than comparing
             *      with a local file.  The server MAY return SSH_FX_OP_UNSUPPORTED in
             *      this case.
             */
            if (GenericUtils.length(quickCheckHash) <= 0) {
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
                        log.trace("doMD5Hash({}) offset={}, length={} - quick-hash mismatched expected={}, actual={}",
                                  path, Long.valueOf(startOffset), Long.valueOf(length),
                                  BufferUtils.printHex(':', quickCheckHash), BufferUtils.printHex(':', hashValue));
                    }
                }
            }

            if (hashMatches) {
                while(effectiveLength > 0L) {
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
            log.trace("doMD5Hash({}) offset={}, length={} - matches={}, quick={} hash={}",
                      path, Long.valueOf(startOffset), Long.valueOf(length), Boolean.valueOf(hashMatches),
                      BufferUtils.printHex(':', quickCheckHash), BufferUtils.printHex(':', hashValue));
        }

        return hashValue;
    }

    protected void doVersionSelect(Buffer buffer, int id) throws IOException {
        String proposed = buffer.getString();
        /*
         * The 'version-select' MUST be the first request from the client to the
         * server; if it is not, the server MUST fail the request and close the
         * channel.
         */
        if (requestsCount > 0L) {
           sendStatus(BufferUtils.clear(buffer), id, SSH_FX_FAILURE, "Version selection not the 1st request for proposal = " + proposed);
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
        } if (result.booleanValue()) {
            version = Integer.parseInt(proposed);
            sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
        } else {
            sendStatus(BufferUtils.clear(buffer), id, SSH_FX_FAILURE, "Unsupported version " + proposed);
            session.close(true);
        }
    }

    /**
     * @param buffer The {@link Buffer} holding the request
     * @param id The request id
     * @param proposed The proposed value
     * @return A {@link Boolean} indicating whether to accept/reject the proposal.
     * If {@code null} then rejection response has been sent, otherwise and
     * appropriate response is generated
     * @throws IOException If failed send an independent rejection response
     */
    protected Boolean validateProposedVersion(Buffer buffer, int id, String proposed) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_EXTENDED(version-select) (version={})", proposed);
        }
        
        if (GenericUtils.length(proposed) != 1) {
            return Boolean.FALSE;
        }

        char digit = proposed.charAt(0);
        if ((digit < '0') || (digit > '9')) {
            return Boolean.FALSE;
        }

        int value = digit - '0';
        String all = checkVersionCompatibility(buffer, id, value, SSH_FX_FAILURE);
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
     * @param buffer The {@link Buffer} containing the request
     * @param id The SSH message ID to be used to send the failure message
     * if required
     * @param proposed The proposed version value
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
        Integer sftpVersion = FactoryManagerUtils.getInteger(session, SFTP_VERSION);
        if (sftpVersion != null) {
            int forcedValue = sftpVersion.intValue();
            if ((forcedValue < LOWER_SFTP_IMPL) || (forcedValue > HIGHER_SFTP_IMPL)) {
                throw new IllegalStateException("Forced SFTP version (" + sftpVersion + ") not within supported values: " + available);
            }
            low = hig = sftpVersion.intValue();
            available = sftpVersion.toString();
        }

        if (log.isTraceEnabled()) {
            log.trace("checkVersionCompatibility(id={}) - proposed={}, available={}",
                      Integer.valueOf(id), Integer.valueOf(proposed), available);
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doBlock(int id, String handle, long offset, long length, int mask) throws IOException {
        Handle p = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_BLOCK (handle={}[{}], offset={}, length={}, mask=0x{})",
                      handle, p, Long.valueOf(offset), Long.valueOf(length), Integer.toHexString(mask));
        }
        
        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        fileHandle.lock(offset, length, mask);
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

        sendStatus(BufferUtils.clear(buffer), id, found ? SSH_FX_OK : SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK, "");
    }

    protected boolean doUnblock(int id, String handle, long offset, long length) throws IOException {
        Handle p = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_UNBLOCK (handle={}[{}], offset={}, length={})",
                      handle, p, Long.valueOf(offset), Long.valueOf(length));
        }

        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        return fileHandle.unlock(offset, length);
    }

    protected void doLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        boolean symLink = buffer.getBoolean();

        try {
            doLink(id, targetPath, linkPath, symLink);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }
        
        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doLink(int id, String targetPath, String linkPath, boolean symLink) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_LINK (linkpath={}, targetpath={}, symlink={})",
                      linkPath, targetPath, Boolean.valueOf(symLink));
        }
        
        Path link = resolveFile(linkPath);
        Path target = fileSystem.getPath(targetPath);
        if (symLink) {
            Files.createSymbolicLink(link, target);
        } else {
            Files.createLink(link, target);
        }
    }

    protected void doSymLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        try {
            doSymLink(id, targetPath, linkPath);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doSymLink(int id, String targetPath, String linkPath) throws IOException {
        log.debug("Received SSH_FXP_SYMLINK (linkpath={}, targetpath={})", targetPath, linkPath);
        Path link = resolveFile(linkPath);
        Path target = fileSystem.getPath(targetPath);
        Files.createSymbolicLink(link, target);
    }

    protected void doReadLink(Buffer buffer, int id) throws IOException {
        String path = buffer.getString(), l;
        try {
             l = doReadLink(id, path);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendLink(BufferUtils.clear(buffer), id, l);
    }

    protected String doReadLink(int id, String path) throws IOException {
        Path f = resolveFile(path);
        log.debug("Received SSH_FXP_READLINK (path={}[{}])", path, f);
        
        Path t = Files.readSymbolicLink(f);
        return t.toString();
    }

    protected void doRename(Buffer buffer, int id) throws IOException {
        String oldPath = buffer.getString();
        String newPath = buffer.getString();
        int flags = 0;
        if (version >= SFTP_V5) {
            flags = buffer.getInt();
        }
        try {
            doRename(id, oldPath, newPath, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doRename(int id, String oldPath, String newPath, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_RENAME (oldPath={}, newPath={}, flags=0x{})",
                       oldPath, newPath, Integer.toHexString(flags));
        }

        Collection<CopyOption> opts = Collections.emptyList();
        if (flags != 0) {
            opts = new ArrayList<>();
            if ((flags & SSH_FXP_RENAME_ATOMIC) == SSH_FXP_RENAME_ATOMIC) {
                opts.add(StandardCopyOption.ATOMIC_MOVE);
            }
            if ((flags & SSH_FXP_RENAME_OVERWRITE) == SSH_FXP_RENAME_OVERWRITE) {
                opts.add(StandardCopyOption.REPLACE_EXISTING);
            }
        }
        
        doRename(id, oldPath, newPath, opts);
    }
    
    protected void doRename(int id, String oldPath, String newPath, Collection<CopyOption> opts) throws IOException {
        Path o = resolveFile(oldPath);
        Path n = resolveFile(newPath);
        Files.move(o, n, GenericUtils.isEmpty(opts) ? IoUtils.EMPTY_COPY_OPTIONS : opts.toArray(new CopyOption[opts.size()]));
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    @SuppressWarnings("resource")
    protected void doCopyData(int id, String readHandle, long readOffset, long readLength, String writeHandle, long writeOffset) throws IOException {
        boolean inPlaceCopy = readHandle.equals(writeHandle);
        Handle rh = handles.get(readHandle);
        Handle wh = inPlaceCopy ? rh : handles.get(writeHandle);
        if (log.isDebugEnabled()) {
            log.debug("SSH_FXP_EXTENDED[{}] read={}[{}], read-offset={}, read-length={}, write={}[{}], write-offset={})",
                      SftpConstants.EXT_COPYDATA,
                      readHandle, rh, Long.valueOf(readOffset), Long.valueOf(readLength),
                      writeHandle, wh, Long.valueOf(writeOffset));
        }

        FileHandle srcHandle = validateHandle(readHandle, rh, FileHandle.class);
        Path srcPath = srcHandle.getFile();
        int srcAccess = srcHandle.getAccessMask();
        if ((srcAccess & ACE4_READ_DATA) != ACE4_READ_DATA) {
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
        if ((dstAccess & ACE4_WRITE_DATA) != ACE4_WRITE_DATA) {
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
                                                 + " overlaps with read range [" + readOffset + "-" +  maxRead + "]");
            } else if (maxRead > writeOffset) {
                throw new IllegalArgumentException("Read range end [" + readOffset + "-" +  maxRead + "]"
                                                 + " overlaps with write range [" + writeOffset + "-" + maxWrite + "]");
            }
        }
        
        byte[] copyBuf = new byte[Math.min(IoUtils.DEFAULT_COPY_SIZE, (int) effectiveLength)];
        while(effectiveLength > 0L) {
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doCopyFile(int id, String srcFile, String dstFile, boolean overwriteDestination) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("SSH_FXP_EXTENDED[{}] (src={}, dst={}, overwrite=0x{})",
                      SftpConstants.EXT_COPYFILE, srcFile, dstFile, Boolean.valueOf(overwriteDestination));
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
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String,Object> attrs;
        try {
             attrs = doStat(id, path, flags);
        } catch(IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }
        
        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String,Object> doStat(int id, String path, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_STAT (path={}, flags=0x{})", path, Integer.toHexString(flags));
        }
        Path p = resolveFile(path);
        return resolveFileAttributes(p, flags, true);
    }

    protected void doRealPath(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        log.debug("Received SSH_FXP_REALPATH (path={})", path);
        path = GenericUtils.trimToEmpty(path);
        if (GenericUtils.isEmpty(path)) {
            path = ".";
        }

        Map<String,?> attrs = Collections.<String, Object>emptyMap();
        Path p;
        try {
            if (version < SFTP_V6) {
                p = doRealPathV6(id, path);
            } else {
                // Read control byte
                int control = 0;
                if (buffer.available() > 0) {
                    control = buffer.getUByte();
                }

                Collection<String> extraPaths = new LinkedList<>();
                while (buffer.available() > 0) {
                    extraPaths.add(buffer.getString());
                }

                p = doRealPathV345(id, path, extraPaths);
                if (control == SSH_FXP_REALPATH_STAT_IF) {
                    try {
                        attrs = getAttributes(p, false);
                    } catch (IOException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Failed ({}) to retrieve attributes of {}: {}",
                                      e.getClass().getSimpleName(), p, e.getMessage());
                        }
                    }
                } else if (control == SSH_FXP_REALPATH_STAT_ALWAYS) {
                    attrs = getAttributes(p, false);
                }
            }
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendPath(BufferUtils.clear(buffer), id, p, attrs);
    }

    protected Path doRealPathV345(int id, String path, Collection<String> extraPaths) throws IOException {
        Path p = resolveFile(path);
        
        if (GenericUtils.size(extraPaths) > 0) {
            for (String p2 : extraPaths) {
                p = p.resolve(p2);
            }
        }

        p = p.toAbsolutePath();
        return p.normalize();
    }

    protected Path doRealPathV6(int id, String path) throws IOException {
        Path f = resolveFile(path);
        Path abs = f.toAbsolutePath();
        Path p = abs.normalize();
        Boolean status = IoUtils.checkFileExists(p, IoUtils.EMPTY_LINK_OPTIONS);
        if (status == null) {
            return handleUnknownRealPathStatus(path, abs, p);
        } else if (status.booleanValue()) {
            return p;
        } else {
            throw new FileNotFoundException(path);
        }
    }

    protected Path handleUnknownRealPathStatus(String path, Path absolute, Path normalized) throws IOException {
        switch(unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("handleUnknownRealPathStatus(" + path + ") abs=" + absolute + ", normal=" + normalized);
                break;
            case ThrowException:
                throw new AccessDeniedException("Cannot determine existence status of real path: " + normalized);
            
            default:
                log.warn("handleUnknownRealPathStatus(" + path + ") abs=" + absolute + ", normal=" + normalized
                       + " - unknown policy: " + unsupportedAttributePolicy);
        }
        
        return absolute;
    }

    protected void doRemoveDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        try {
            doRemoveDirectory(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }
        
        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doRemoveDirectory(int id, String path, LinkOption ... options) throws IOException {
        Path p = resolveFile(path);
        log.debug("Received SSH_FXP_RMDIR (path={})[{}]", path, p);
        if (Files.isDirectory(p, options)) {
            Files.delete(p);
        } else {
            throw new NotDirectoryException(p.toString());
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doMakeDirectory(int id, String path, Map<String,?> attrs, LinkOption ... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_MKDIR (path={}[{}], attrs={})", path, p, attrs);
        }
        
        Boolean  status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot validate make-directory existence for " + p);
        }

        if (status.booleanValue()) {
            if (Files.isDirectory(p, options)) {
                throw new FileAlreadyExistsException(p.toString(), p.toString(), "Target directory already exists");
            } else {
                throw new FileNotFoundException(p.toString() + " already exists as a file");
            }
        } else {
            Files.createDirectory(p);
            setAttributes(p, attrs);
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doRemove(int id, String path, LinkOption ... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_REMOVE (path={}[{}])", path, p);
        }
        
        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot determine existence of remove candidate: " + p);
        }
        if (!status.booleanValue()) {
            throw new FileNotFoundException(p.toString());
        } else if (Files.isDirectory(p, options)) {
            throw new FileNotFoundException(p.toString() + " is as a folder");
        } else {
            Files.delete(p);
        }
    }

    protected void doReadDir(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Handle h = handles.get(handle);
        log.debug("Received SSH_FXP_READDIR (handle={}[{}])", handle, h);

        Buffer reply = null;
        try {
            DirectoryHandle dh = validateHandle(handle, h, DirectoryHandle.class);
            if (dh.isDone()) {
                throw new EOFException("Directory reading is done");
            }

            Path            file = dh.getFile();
            LinkOption[]    options = IoUtils.getLinkOptions(false);
            Boolean         status = IoUtils.checkFileExists(file, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot determine existence of read-dir for " + file);
            }

            if (!status.booleanValue()) {
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
                reply.putByte((byte) SSH_FXP_NAME);
                reply.putInt(id);
                int lenPos = reply.wpos();
                reply.putInt(0);

                int count = doReadDir(id, dh, reply, FactoryManagerUtils.getIntProperty(session, MAX_PACKET_LENGTH_PROP, DEFAULT_MAX_PACKET_LENGTH));
                BufferUtils.updateLengthPlaceholder(reply, lenPos, count);
                if (log.isTraceEnabled()) {
                    log.trace("doReadDir({})[{}] - sent {} entries", handle, h, Integer.valueOf(count));
                }
                if ((!dh.isSendDot()) && (!dh.isSendDotDot()) && (!dh.hasNext())) {
                    // if no more files to send
                    dh.markDone();
                }
            } else {
                // empty directory
                dh.markDone();
                throw new EOFException("Empty directory");
            }
            
            ValidateUtils.checkNotNull(reply, "No reply buffer created", GenericUtils.EMPTY_OBJECT_ARRAY);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }
        
        send(reply);
    }

    protected void doOpenDir(Buffer buffer, int id) throws IOException {
        String path = buffer.getString(), handle;

        try {
            handle = doOpenDir(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendHandle(BufferUtils.clear(buffer), id, handle);
    }

    protected String doOpenDir(int id, String path, LinkOption ... options) throws IOException {
        Path f = resolveFile(path);
        Path abs = f.toAbsolutePath();
        Path p = abs.normalize();
        log.debug("Received SSH_FXP_OPENDIR (path={})[{}]", path, p);
        
        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException("Cannot determine open-dir existence for " + p);
        }

        if (!status.booleanValue()) {
            throw new FileNotFoundException(path);
        } else if (!Files.isDirectory(p, options)) {
            throw new NotDirectoryException(path);
        } else if (!Files.isReadable(p)) {
            throw new AccessDeniedException("Not readable: " + p);
        } else {
            String handle = generateFileHandle(p);
            handles.put(handle, new DirectoryHandle(p));
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
        
        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doFSetStat(int id, String handle, Map<String,?> attrs) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_FSETSTAT (handle={}[{}], attrs={})", handle, h, attrs);
        }

        setAttributes(validateHandle(handle, h, Handle.class).getFile(), attrs);
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doSetStat(int id, String path, Map<String,?> attrs) throws IOException {
        log.debug("Received SSH_FXP_SETSTAT (path={}, attrs={})", path, attrs);
        Path p = resolveFile(path);
        setAttributes(p, attrs);
    }

    protected void doFStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }
        
        Map<String,?> attrs;
        try {
            attrs = doFStat(id, handle, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String,Object> doFStat(int id, String handle, int flags) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_FSTAT (handle={}[{}], flags=0x{})", handle, h, Integer.toHexString(flags));
        }
        
        return resolveFileAttributes(validateHandle(handle, h, Handle.class).getFile(), flags, true);
    }

    protected void doLStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }
        
        Map<String,?> attrs;
        try {
            attrs = doLStat(id, path, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendAttrs(BufferUtils.clear(buffer), id, attrs);
    }

    protected Map<String,Object> doLStat(int id, String path, int flags) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_LSTAT (path={}[{}], flags=0x{})", path, p, Integer.toHexString(flags));
        }

        return resolveFileAttributes(p, flags, false);
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

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "");
    }

    protected void doWrite(int id, String handle, long offset, int length, byte[] data, int doff, int remaining) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_WRITE (handle={}[{}], offset={}, data=byte[{}])",
                      handle, h, Long.valueOf(offset), Integer.valueOf(length));
        }
        
        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        if (length < 0) {
            throw new IllegalStateException("Bad length (" + length + ") for writing to " + fh);
        }

        if (remaining < length) {
            throw new IllegalStateException("Not enough buffer data for writing to " + fh + ": required=" + length + ", available=" + remaining);
        }

        fh.write(data, doff, length, offset);
    }

    protected void doRead(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int readLen = buffer.getInt();
        try {
            buffer.clear();
            buffer.ensureCapacity(readLen + Long.SIZE, Int2IntFunction.IDENTITY);

            buffer.putByte((byte) SSH_FXP_DATA);
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
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_READ (handle={}[{}], offset={}, length={})",
                      handle, h, Long.valueOf(offset), Integer.valueOf(length));
        }
        ValidateUtils.checkTrue(length > 0, "Invalid read length: %d", length);
        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        
        return fh.read(data, doff, length, offset);
    }

    protected void doClose(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        try {
            doClose(id, handle);
        } catch (IOException | RuntimeException e) {
            sendStatus(BufferUtils.clear(buffer), id, e);
            return;
        }

        sendStatus(BufferUtils.clear(buffer), id, SSH_FX_OK, "", "");
    }

    protected void doClose(int id, String handle) throws IOException {
        Handle h = handles.remove(handle);
        log.debug("Received SSH_FXP_CLOSE (handle={}[{}])", handle, h);
        validateHandle(handle, h, Handle.class).close();
    }

    protected void doOpen(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        /*
         * Be consistent with FileChannel#open - if no mode specified then READ is assumed
         */
        int access = 0;
        if (version >= SFTP_V5) {
            if ((access=buffer.getInt()) == 0) {
                access = ACE4_READ_DATA | ACE4_READ_ATTRIBUTES;
            }
        }

        int pflags = buffer.getInt();
        if (pflags == 0) {
            pflags = SSH_FXF_READ;
        }

        if (version < SFTP_V5) {
            int flags = pflags;
            pflags = 0;
            switch (flags & (SSH_FXF_READ | SSH_FXF_WRITE)) {
                case SSH_FXF_READ:
                    access |= ACE4_READ_DATA | ACE4_READ_ATTRIBUTES;
                    break;
                case SSH_FXF_WRITE:
                    access |= ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES;
                    break;
                default:
                    access |= ACE4_READ_DATA | ACE4_READ_ATTRIBUTES;
                    access |= ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES;
                    break;
            }
            if ((flags & SSH_FXF_APPEND) != 0) {
                access |= ACE4_APPEND_DATA;
                pflags |= SSH_FXF_APPEND_DATA | SSH_FXF_APPEND_DATA_ATOMIC;
            }
            if ((flags & SSH_FXF_CREAT) != 0) {
                if ((flags & SSH_FXF_EXCL) != 0) {
                    pflags |= SSH_FXF_CREATE_NEW;
                } else if ((flags & SSH_FXF_TRUNC) != 0) {
                    pflags |= SSH_FXF_CREATE_TRUNCATE;
                } else {
                    pflags |= SSH_FXF_OPEN_OR_CREATE;
                }
            } else {
                if ((flags & SSH_FXF_TRUNC) != 0) {
                    pflags |= SSH_FXF_TRUNCATE_EXISTING;
                } else {
                    pflags |= SSH_FXF_OPEN_EXISTING;
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
     * @param id Request id
     * @param path Path
     * @param pflags Open mode flags - see {@code SSH_FXF_XXX} flags
     * @param access Access mode flags - see {@code ACE4_XXX} flags
     * @param attrs Requested attributes
     * @return The assigned (opaque) handle
     * @throws IOException if failed to execute
     */
    protected String doOpen(int id, String path, int pflags, int access, Map<String, Object> attrs) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_OPEN (path={}, access=0x{}, pflags=0x{}, attrs={})",
                      path, Integer.toHexString(access), Integer.toHexString(pflags), attrs);
        }
        int curHandleCount = handles.size();
        int maxHandleCount = FactoryManagerUtils.getIntProperty(session, MAX_OPEN_HANDLES_PER_SESSION, DEFAULT_MAX_OPEN_HANDLES);
        if (curHandleCount > maxHandleCount) {
            throw new IllegalStateException("Too many open handles: current=" + curHandleCount + ", max.=" + maxHandleCount);
        }
        
        Path file = resolveFile(path);
        String handle = generateFileHandle(file);
        handles.put(handle, new FileHandle(file, pflags, access, attrs));
        return handle;
    }

    // we stringify our handles and treat them as such on decoding as well as it is easier to use as a map key
    protected String generateFileHandle(Path file) {
        // use several rounds in case the file handle size is relatively small so we might get conflicts
        for (int index=0; index < maxFileHandleRounds; index++) {
            randomizer.fill(workBuf, 0, fileHandleSize);
            String handle = BufferUtils.printHex(workBuf, 0, fileHandleSize, BufferUtils.EMPTY_HEX_SEPARATOR);
            if (handles.containsKey(handle)) {
                if (log.isTraceEnabled()) {
                    log.trace("generateFileHandle({}) handle={} in use at round {}", file, handle, Integer.valueOf(index));
                }
                continue;
            }

            if (log.isTraceEnabled()) {
                log.trace("generateFileHandle({}) {}", file, handle);
            }
            return handle;
        }
        
        throw new IllegalStateException("Failed to generate a unique file handle for " + file);
    }

    protected void doInit(Buffer buffer, int id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_INIT (version={})", Integer.valueOf(id));
        }

        String all = checkVersionCompatibility(buffer, id, id, SSH_FX_OP_UNSUPPORTED);
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

        buffer.putByte((byte) SSH_FXP_VERSION);
        buffer.putInt(version);
        appendExtensions(buffer, all);

        send(buffer);
    }

    protected void appendExtensions(Buffer buffer, String supportedVersions) {
        appendVersionsExtension(buffer, supportedVersions);
        appendNewlineExtension(buffer, System.getProperty("line.separator"));
        appendVendorIdExtension(buffer, VersionProperties.getVersionProperties());

        /* TODO updateAvailableExtensions(extensions, appendAclSupportedExtension(...)
            buffer.putString("acl-supported");
            buffer.putInt(4);
            // capabilities
            buffer.putInt(0);
        */

        Collection<String> extras = getSupportedClientExtensions();
        appendSupportedExtension(buffer, extras);
        appendSupported2Extension(buffer, extras);
    }

    protected Collection<String> getSupportedClientExtensions() {
        String value = FactoryManagerUtils.getString(session, CLIENT_EXTENSIONS_PROP);
        if (value == null) {
            return DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;
        }
        
        if (value.length() <= 0) {  // means don't report any extensions
            return Collections.<String>emptyList();
        }

        String[] comps = GenericUtils.split(value, ',');
        return Arrays.asList(comps);
    }
    /**
     * Appends the &quot;versions&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     * @param buffer The {@link Buffer} to append to
     * @param value The recommended value
     * @see SftpConstants#EXT_VERSIONS
     */
    protected void appendVersionsExtension(Buffer buffer, String value) {
        buffer.putString(EXT_VERSIONS);
        buffer.putString(value);
    }

    /**
     * Appends the &quot;newline&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     * @param buffer The {@link Buffer} to append to
     * @param value The recommended value
     * @see SftpConstants#EXT_NEWLINE
     */
    protected void appendNewlineExtension(Buffer buffer, String value) {
        buffer.putString(EXT_NEWLINE);
        buffer.putString(value);
    }
    
    /**
     * Appends the &quot;vendor-id&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     * @param buffer The {@link Buffer} to append to
     * @param versionProperties The currently available version properties
     * @see SftpConstants#EXT_VENDORID
     * @see <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09 - section 4.4</A>
     */
    protected void appendVendorIdExtension(Buffer buffer, Map<String,?> versionProperties) {
        buffer.putString(EXT_VENDORID);
        
        // placeholder for length
        int lenPos = buffer.wpos();
        buffer.putInt(0);
        buffer.putString(FactoryManagerUtils.getStringProperty(versionProperties, "groupId", getClass().getPackage().getName()));   // vendor-name
        buffer.putString(FactoryManagerUtils.getStringProperty(versionProperties, "artifactId", getClass().getSimpleName()));       // product-name
        buffer.putString(FactoryManagerUtils.getStringProperty(versionProperties, "version", FactoryManager.DEFAULT_VERSION));      // product-version
        buffer.putLong(0L); // product-build-number
        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    /**
     * Appends the &quot;supported&quot; extension to the buffer. <B>Note:</B>
     * if overriding this method make sure you either do not append anything
     * or use the correct extension name
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported
     * - may be {@code null}/empty
     */
    protected void appendSupportedExtension(Buffer buffer, Collection<String> extras) {
        buffer.putString(EXT_SUPPORTED);
        
        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_CREATETIME
                | SSH_FILEXFER_ATTR_MODIFYTIME | SSH_FILEXFER_ATTR_OWNERGROUP
                | SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND
                | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL);
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
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported
     * - may be {@code null}/empty
     * @see SftpConstants#EXT_SUPPORTED
     * @see <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10">DRAFT 13 section 5.4</A>
     */
    protected void appendSupported2Extension(Buffer buffer, Collection<String> extras) {
        buffer.putString(EXT_SUPPORTED2);
        
        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_CREATETIME
                | SSH_FILEXFER_ATTR_MODIFYTIME | SSH_FILEXFER_ATTR_OWNERGROUP
                | SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SSH_FXF_ACCESS_DISPOSITION | SSH_FXF_APPEND_DATA);
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
        buffer.putByte((byte) SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        send(buffer);
    }

    protected void sendAttrs(Buffer buffer, int id, Map<String,?> attributes) throws IOException {
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, attributes);
        send(buffer);
    }

    protected void sendPath(Buffer buffer, int id, Path f, Map<String,?> attrs) throws IOException {
        buffer.putByte((byte) SSH_FXP_NAME);
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

        if (version == SFTP_V3) {
            f = resolveFile(normalizedPath);
            buffer.putString(getLongName(f, attrs));
            buffer.putInt(0);   // no flags
        } else if (version >= SFTP_V4) {
            writeAttrs(buffer, attrs);
        } else {
            throw new IllegalStateException("sendPath(" + f + ") unsupported version: " + version);
        }
        send(buffer);
    }

    protected void sendLink(Buffer buffer, int id, String link) throws IOException {
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);
        //normalize the given path, use *nix style separator
        buffer.putString(link);
        buffer.putString(link);
        buffer.putInt(0);
        send(buffer);
    }

    /**
     * @param id Request id
     * @param dir The {@link DirectoryHandle}
     * @param buffer The {@link Buffer} to write the results
     * @param maxSize Max. buffer size
     * @return Number of written entries
     * @throws IOException If failed to generate an entry
     */
    protected int doReadDir(int id, DirectoryHandle dir, Buffer buffer, int maxSize) throws IOException {
        int nb = 0;
        while ((dir.isSendDot() || dir.isSendDotDot() || dir.hasNext()) && (buffer.wpos() < maxSize)) {
            if (dir.isSendDot()) {
                writeDirEntry(id, dir, buffer, nb, dir.getFile(), ".");
                dir.markDotSent();    // do not send it again
            } else if (dir.isSendDotDot()) {
                writeDirEntry(id, dir, buffer, nb, dir.getFile().getParent(), "..");
                dir.markDotDotSent(); // do not send it again
            } else {
                Path f = dir.next();
                writeDirEntry(id, dir, buffer, nb, f, getShortName(f));
            }

            nb++;
        }
        
        return nb;
    }

    /**
     * @param id Request id
     * @param dir The {@link DirectoryHandle}
     * @param buffer The {@link Buffer} to write the results
     * @param index Zero-based index of the entry to be written
     * @param f The entry {@link Path}
     * @param shortName The entry short name
     * @throws IOException If failed to generate the entry data
     */
    protected void writeDirEntry(int id, DirectoryHandle dir, Buffer buffer, int index, Path f, String shortName) throws IOException {
        buffer.putString(shortName);
        if (version == SFTP_V3) {
            String  longName = getLongName(f);
            buffer.putString(longName);
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(id=" + id + ")[" + index + "] - " + shortName + " [" + longName + "]");
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(id=" + id + ")[" + index + "] - " + shortName);
            }
        }
        
        Map<String,?> attrs = resolveFileAttributes(f, SSH_FILEXFER_ATTR_ALL, false);
        writeAttrs(buffer, attrs);
    }

    protected String getLongName(Path f) throws IOException {
        return getLongName(f, true);
    }

    private String getLongName(Path f, boolean sendAttrs) throws IOException {
        Map<String, Object> attributes;
        if (sendAttrs) {
            attributes = getAttributes(f, false);
        } else {
            attributes = Collections.emptyMap();
        }
        return getLongName(f, attributes);
    }

    private String getLongName(Path f, Map<String,?> attributes) throws IOException {
        String username;
        if (attributes.containsKey("owner")) {
            username = Objects.toString(attributes.get("owner"));
        } else {
            username = "owner";
        }
        if (username.length() > 8) {
            username = username.substring(0, 8);
        } else {
            for (int i = username.length(); i < 8; i++) {
                username = username + " ";
            }
        }
        String group;
        if (attributes.containsKey("group")) {
            group = Objects.toString(attributes.get("group"));
        } else {
            group = "group";
        }
        if (group.length() > 8) {
            group = group.substring(0, 8);
        } else {
            for (int i = group.length(); i < 8; i++) {
                group = group + " ";
            }
        }

        Number length = (Number) attributes.get("size");
        if (length == null) {
            length = Long.valueOf(0L);
        }
        String lengthString = String.format("%1$8s", length);

        Boolean isDirectory = (Boolean) attributes.get("isDirectory");
        Boolean isLink = (Boolean) attributes.get("isSymbolicLink");
        @SuppressWarnings("unchecked")
        Set<PosixFilePermission> perms = (Set<PosixFilePermission>) attributes.get("permissions");
        if (perms == null) {
            perms = EnumSet.noneOf(PosixFilePermission.class);
        }

        StringBuilder sb = new StringBuilder();
        sb.append((isDirectory != null && isDirectory.booleanValue()) ? "d" : (isLink != null && isLink.booleanValue()) ? "l" : "-");
        sb.append(PosixFilePermissions.toString(perms));
        sb.append("  ");
        sb.append(attributes.containsKey("nlink") ? attributes.get("nlink") : "1");
        sb.append(" ");
        sb.append(username);
        sb.append(" ");
        sb.append(group);
        sb.append(" ");
        sb.append(lengthString);
        sb.append(" ");
        sb.append(getUnixDate((FileTime) attributes.get("lastModifiedTime")));
        sb.append(" ");
        sb.append(getShortName(f));

        return sb.toString();
    }

    protected String getShortName(Path f) {
        if (OsUtils.isUNIX()) {
            Path    name=f.getFileName();
            if (name == null) {
                Path    p=resolveFile(".");
                name = p.getFileName();
            }
            
            return name.toString();
        } else {    // need special handling for Windows root drives
            Path    abs=f.toAbsolutePath().normalize();
            int     count=abs.getNameCount();
            /*
             * According to the javadoc:
             * 
             *      The number of elements in the path, or 0 if this path only
             *      represents a root component
             */
            if (count > 0) {
                Path    name=abs.getFileName();
                return name.toString();
            } else {
                return abs.toString().replace(File.separatorChar, '/');
            }
        }
    }

    protected int attributesToPermissions(boolean isReg, boolean isDir, boolean isLnk, Collection<PosixFilePermission> perms) {
        int pf = 0;
        if (perms != null) {
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
                    default: // ignored
                }
            }
        }
        pf |= isReg ? S_IFREG : 0;
        pf |= isDir ? S_IFDIR : 0;
        pf |= isLnk ? S_IFLNK : 0;
        return pf;
    }

    protected Map<String, Object> resolveFileAttributes(Path file, int flags, boolean followLinks) throws IOException {
        LinkOption[] options = IoUtils.getLinkOptions(followLinks);
        Boolean      status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            return handleUnknownStatusFileAttributes(file, flags, followLinks);
        } else if (!status.booleanValue()) {
            throw new FileNotFoundException(file.toString());
        } else {
            return getAttributes(file, flags, followLinks);
        }
    }

    protected void writeAttrs(Buffer buffer, Map<String,?> attributes) throws IOException {
        boolean isReg = getBool((Boolean) attributes.get("isRegularFile"));
        boolean isDir = getBool((Boolean) attributes.get("isDirectory"));
        boolean isLnk = getBool((Boolean) attributes.get("isSymbolicLink"));
        @SuppressWarnings("unchecked")
        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) attributes.get("permissions");
        Number size = (Number) attributes.get("size");
        FileTime lastModifiedTime = (FileTime) attributes.get("lastModifiedTime");
        FileTime lastAccessTime = (FileTime) attributes.get("lastAccessTime");

        if (version == SFTP_V3) {
            int flags =
                    ((isReg || isLnk) && (size != null) ? SSH_FILEXFER_ATTR_SIZE : 0) |
                    (attributes.containsKey("uid") && attributes.containsKey("gid") ? SSH_FILEXFER_ATTR_UIDGID : 0) |
                    ((perms != null) ? SSH_FILEXFER_ATTR_PERMISSIONS : 0) |
                    (((lastModifiedTime != null) && (lastAccessTime != null)) ? SSH_FILEXFER_ATTR_ACMODTIME : 0);
            buffer.putInt(flags);
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(size.longValue());
            }
            if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
                buffer.putInt(((Number) attributes.get("uid")).intValue());
                buffer.putInt(((Number) attributes.get("gid")).intValue());
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
            }
            if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                buffer.putInt(lastAccessTime.to(TimeUnit.SECONDS));
                buffer.putInt(lastModifiedTime.to(TimeUnit.SECONDS));
            }
        } else if (version >= SFTP_V4) {
            FileTime creationTime = (FileTime) attributes.get("creationTime");
            int flags = (((isReg || isLnk) && (size != null)) ? SSH_FILEXFER_ATTR_SIZE : 0) |
                        ((attributes.containsKey("owner") && attributes.containsKey("group")) ? SSH_FILEXFER_ATTR_OWNERGROUP : 0) |
                        ((perms != null) ? SSH_FILEXFER_ATTR_PERMISSIONS : 0) |
                        ((lastModifiedTime != null) ? SSH_FILEXFER_ATTR_MODIFYTIME : 0) |
                        ((creationTime != null) ? SSH_FILEXFER_ATTR_CREATETIME : 0) |
                        ((lastAccessTime != null) ? SSH_FILEXFER_ATTR_ACCESSTIME : 0);
            buffer.putInt(flags);
            buffer.putByte((byte) (isReg ? SSH_FILEXFER_TYPE_REGULAR :
                    isDir ? SSH_FILEXFER_TYPE_DIRECTORY :
                            isLnk ? SSH_FILEXFER_TYPE_SYMLINK :
                                    SSH_FILEXFER_TYPE_UNKNOWN));
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(size.longValue());
            }
            if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                buffer.putString(Objects.toString(attributes.get("owner")));
                buffer.putString(Objects.toString(attributes.get("group")));
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
            }

            if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                putFileTime(buffer, flags, lastAccessTime);
            }

            if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                putFileTime(buffer, flags, lastAccessTime);
            }
            if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                putFileTime(buffer, flags, lastModifiedTime);
            }
            // TODO: acls
            // TODO: bits
            // TODO: extended
        }
    }

    protected void putFileTime(Buffer buffer, int flags, FileTime time) {
        buffer.putLong(time.to(TimeUnit.SECONDS));
        if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            long nanos = time.to(TimeUnit.NANOSECONDS);
            nanos = nanos % TimeUnit.SECONDS.toNanos(1);
            buffer.putInt((int) nanos);
        }
    }

    protected boolean getBool(Boolean bool) {
        return (bool != null) && bool.booleanValue();
    }

    protected Map<String, Object> getAttributes(Path file, boolean followLinks) throws IOException {
        return getAttributes(file, SSH_FILEXFER_ATTR_ALL, followLinks);
    }

    public static final List<String>    DEFAULT_UNIX_VIEW=Collections.singletonList("unix:*");

    protected Map<String, Object> handleUnknownStatusFileAttributes(Path file, int flags, boolean followLinks) throws IOException {
        switch(unsupportedAttributePolicy) {
            case Ignore:
                break;
            case ThrowException:
                throw new AccessDeniedException("Cannot determine existence for attributes of " + file);
            case Warn:
                log.warn("handleUnknownStatusFileAttributes(" + file + ") cannot determine existence");
                break;
            default:
                log.warn("handleUnknownStatusFileAttributes(" + file + ") unknown policy: " + unsupportedAttributePolicy);
        }
        
        return getAttributes(file, flags, followLinks);
    }

    protected Map<String, Object> getAttributes(Path file, int flags, boolean followLinks) throws IOException {
        FileSystem          fs=file.getFileSystem();
        Collection<String>  supportedViews=fs.supportedFileAttributeViews();
        LinkOption[]        opts=IoUtils.getLinkOptions(followLinks);
        Map<String,Object>  attrs=new HashMap<>();
        Collection<String>  views;

        if (GenericUtils.isEmpty(supportedViews)) {
            views = Collections.<String>emptyList();
        } else if (supportedViews.contains("unix")) {
            views = DEFAULT_UNIX_VIEW;
        } else {
            views = new ArrayList<String>(supportedViews.size());
            for (String v : supportedViews) {
                views.add(v + ":*");
            }
        }

        for (String v : views) {
            Map<String, Object> ta=readFileAttributes(file, v, opts);
            attrs.putAll(ta);
        }

        // if did not get permissions from the supported views return a best approximation
        if (!attrs.containsKey("permissions")) {
            Set<PosixFilePermission> perms=IoUtils.getPermissionsFromFile(file.toFile());
            attrs.put("permissions", perms);
        }

        return attrs;
    }

    protected Map<String, Object> readFileAttributes(Path file, String view, LinkOption ... opts) throws IOException {
        try {
            return Files.readAttributes(file, view, opts);
        } catch(IOException e) {
            return handleReadFileAttributesException(file, view, opts, e);
        }
    }

    protected Map<String, Object> handleReadFileAttributesException(Path file, String view, LinkOption[] opts, IOException e) throws IOException {
        switch(unsupportedAttributePolicy) {
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

    protected void setAttributes(Path file, Map<String,?>  attributes) throws IOException {
        Set<String> unsupported = new HashSet<>();
        for (String attribute : attributes.keySet()) {
            String view = null;
            Object value = attributes.get(attribute);
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
                    if (OsUtils.isWin32()) {
                        @SuppressWarnings("unchecked")
                        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) value;
                        IoUtils.setPermissionsToFile(file.toFile(), perms);
                        continue;
                    }
                    view = "posix";
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
                default:    // ignored
            }
            if (view != null && value != null) {
                try {
                    Files.setAttribute(file, view + ":" + attribute, value, IoUtils.getLinkOptions(false));
                } catch (UnsupportedOperationException e) {
                    unsupported.add(attribute);
                }
            }
        }
        handleUnsupportedAttributes(unsupported);
    }

    protected void handleUnsupportedAttributes(Collection<String> attributes) {
        if (!attributes.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (String attr : attributes) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(attr);
            }
            switch (unsupportedAttributePolicy) {
                case Ignore:
                    break;
                case Warn:
                    log.warn("Unsupported attributes: " + sb.toString());
                    break;
                case ThrowException:
                    throw new UnsupportedOperationException("Unsupported attributes: " + sb.toString());
                default:
                    log.warn("Unknown policy for attributes=" + sb.toString() + ": " + unsupportedAttributePolicy);
            }
        }
    }

    private GroupPrincipal toGroup(Path file, GroupPrincipal name) throws IOException {
        String groupName = name.toString();
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        try {
            return lookupService.lookupPrincipalByGroupName(groupName);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(GroupPrincipal.class, groupName, e);
            return null;
        }
    }

    private UserPrincipal toUser(Path file, UserPrincipal name) throws IOException {
        String username = name.toString();
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        try {
            return lookupService.lookupPrincipalByName(username);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(UserPrincipal.class, username, e);
            return null;
        }
    }

    protected void handleUserPrincipalLookupServiceException(Class<? extends Principal> principalType, String name, IOException e) throws IOException {
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

    protected Map<String, Object> readAttrs(Buffer buffer) throws IOException {
        Map<String, Object> attrs = new HashMap<>();
        int flags = buffer.getInt();
        if (version >= SFTP_V4) {
            int type = buffer.getUByte();
            switch (type) {
                case SSH_FILEXFER_TYPE_REGULAR:
                    attrs.put("isRegular", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_DIRECTORY:
                    attrs.put("isDirectory", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_SYMLINK:
                    attrs.put("isSymbolicLink", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_UNKNOWN:
                    attrs.put("isOther", Boolean.TRUE);
                    break;
                default:    // ignored
            }
        }
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            attrs.put("size", Long.valueOf(buffer.getLong()));
        }
        if ((flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0) {
            attrs.put("allocationSize", Long.valueOf(buffer.getLong()));
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            attrs.put("uid", Integer.valueOf(buffer.getInt()));
            attrs.put("gid", Integer.valueOf(buffer.getInt()));
        }
        if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            attrs.put("owner", new DefaultGroupPrincipal(buffer.getString()));
            attrs.put("group", new DefaultGroupPrincipal(buffer.getString()));
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            attrs.put("permissions", permissionsToAttributes(buffer.getInt()));
        }
        if (version == SFTP_V3) {
            if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, flags));
                attrs.put("lastModifiedTime", readTime(buffer, flags));
            }
        } else if (version >= SFTP_V4) {
            if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                attrs.put("creationTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                attrs.put("lastModifiedTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_CTIME) != 0) {
                attrs.put("ctime", readTime(buffer, flags));
            }
        }
        if ((flags & SSH_FILEXFER_ATTR_ACL) != 0) {
            int count = buffer.getInt();
            List<AclEntry> acls = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                int aclType = buffer.getInt();
                int aclFlag = buffer.getInt();
                int aclMask = buffer.getInt();
                String aclWho = buffer.getString();
                acls.add(buildAclEntry(aclType, aclFlag, aclMask, aclWho));
            }
            attrs.put("acl", acls);
        }
        if ((flags & SSH_FILEXFER_ATTR_BITS) != 0) {
            int bits = buffer.getInt();
            int valid = 0xffffffff;
            if (version >= SFTP_V6) {
                valid = buffer.getInt();
            }
            // TODO: handle attrib bits
        }
        if ((flags & SSH_FILEXFER_ATTR_TEXT_HINT) != 0) {
            boolean text = buffer.getBoolean();
            // TODO: handle text
        }
        if ((flags & SSH_FILEXFER_ATTR_MIME_TYPE) != 0) {
            String mimeType = buffer.getString();
            // TODO: handle mime-type
        }
        if ((flags & SSH_FILEXFER_ATTR_LINK_COUNT) != 0) {
            int nlink = buffer.getInt();
            // TODO: handle link-count
        }
        if ((flags & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) != 0) {
            String untranslated = buffer.getString();
            // TODO: handle untranslated-name
        }
        if ((flags & SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            int count = buffer.getInt();
            Map<String, String> extended = new HashMap<>();
            for (int i = 0; i < count; i++) {
                String key = buffer.getString();
                String val = buffer.getString();
                extended.put(key, val);
            }
            attrs.put("extended", extended);
        }

        return attrs;
    }

    private FileTime readTime(Buffer buffer, int flags) {
        long secs = buffer.getLong();
        long millis = secs * 1000;
        if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            millis += buffer.getInt() / 1000000l;
        }
        return FileTime.from(millis, TimeUnit.MILLISECONDS);
    }

    private AclEntry buildAclEntry(int aclType, int aclFlag, int aclMask, final String aclWho) {
        AclEntryType type;
        switch (aclType) {
        case ACE4_ACCESS_ALLOWED_ACE_TYPE:
            type = AclEntryType.ALLOW;
            break;
        case ACE4_ACCESS_DENIED_ACE_TYPE:
            type = AclEntryType.DENY;
            break;
        case ACE4_SYSTEM_AUDIT_ACE_TYPE:
            type = AclEntryType.AUDIT;
            break;
        case ACE4_SYSTEM_ALARM_ACE_TYPE:
            type = AclEntryType.AUDIT;
            break;
        default:
            throw new IllegalStateException("Unknown acl type: " + aclType);
        }
        Set<AclEntryFlag> flags = new HashSet<>();
        if ((aclFlag & ACE4_FILE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.FILE_INHERIT);
        }
        if ((aclFlag & ACE4_DIRECTORY_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.DIRECTORY_INHERIT);
        }
        if ((aclFlag & ACE4_NO_PROPAGATE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.NO_PROPAGATE_INHERIT);
        }
        if ((aclFlag & ACE4_INHERIT_ONLY_ACE) != 0) {
            flags.add(AclEntryFlag.INHERIT_ONLY);
        }
        Set<AclEntryPermission> mask = new HashSet<>();
        if ((aclMask & ACE4_READ_DATA) != 0) {
            mask.add(AclEntryPermission.READ_DATA);
        }
        if ((aclMask & ACE4_LIST_DIRECTORY) != 0) {
            mask.add(AclEntryPermission.LIST_DIRECTORY);
        }
        if ((aclMask & ACE4_WRITE_DATA) != 0) {
            mask.add(AclEntryPermission.WRITE_DATA);
        }
        if ((aclMask & ACE4_ADD_FILE) != 0) {
            mask.add(AclEntryPermission.ADD_FILE);
        }
        if ((aclMask & ACE4_APPEND_DATA) != 0) {
            mask.add(AclEntryPermission.APPEND_DATA);
        }
        if ((aclMask & ACE4_ADD_SUBDIRECTORY) != 0) {
            mask.add(AclEntryPermission.ADD_SUBDIRECTORY);
        }
        if ((aclMask & ACE4_READ_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.READ_NAMED_ATTRS);
        }
        if ((aclMask & ACE4_WRITE_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.WRITE_NAMED_ATTRS);
        }
        if ((aclMask & ACE4_EXECUTE) != 0) {
            mask.add(AclEntryPermission.EXECUTE);
        }
        if ((aclMask & ACE4_DELETE_CHILD) != 0) {
            mask.add(AclEntryPermission.DELETE_CHILD);
        }
        if ((aclMask & ACE4_READ_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.READ_ATTRIBUTES);
        }
        if ((aclMask & ACE4_WRITE_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.WRITE_ATTRIBUTES);
        }
        if ((aclMask & ACE4_DELETE) != 0) {
            mask.add(AclEntryPermission.DELETE);
        }
        if ((aclMask & ACE4_READ_ACL) != 0) {
            mask.add(AclEntryPermission.READ_ACL);
        }
        if ((aclMask & ACE4_WRITE_ACL) != 0) {
            mask.add(AclEntryPermission.WRITE_ACL);
        }
        if ((aclMask & ACE4_WRITE_OWNER) != 0) {
            mask.add(AclEntryPermission.WRITE_OWNER);
        }
        if ((aclMask & ACE4_SYNCHRONIZE) != 0) {
            mask.add(AclEntryPermission.SYNCHRONIZE);
        }
        UserPrincipal who = new DefaultGroupPrincipal(aclWho);
        return AclEntry.newBuilder()
                .setType(type)
                .setFlags(flags)
                .setPermissions(mask)
                .setPrincipal(who)
                .build();
    }

    /**
     * @param handle The original handle id
     * @param h The resolved {@link Handle} instance
     * @param type The expected handle type
     * @return The cast type
     * @throws FileNotFoundException If the handle instance is {@code null}
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

    protected void sendStatus(Buffer buffer, int id, Exception e) throws IOException {
        int substatus = resolveSubstatus(e);
        sendStatus(buffer, id, substatus, e.toString());
    }

    protected int resolveSubstatus(Exception e) {
        if ((e instanceof NoSuchFileException) || (e instanceof FileNotFoundException)) {
            return SSH_FX_NO_SUCH_FILE;
        } else if (e instanceof InvalidHandleException) {
            return SSH_FX_INVALID_HANDLE;
        } else if (e instanceof FileAlreadyExistsException) {
            return SSH_FX_FILE_ALREADY_EXISTS;
        } else if (e instanceof DirectoryNotEmptyException) {
            return SSH_FX_DIR_NOT_EMPTY;
        } else if (e instanceof NotDirectoryException) {
            return SSH_FX_NOT_A_DIRECTORY;
        } else if (e instanceof AccessDeniedException) {
            return SSH_FX_PERMISSION_DENIED;
        } else if (e instanceof EOFException) {
            return SSH_FX_EOF;
        } else if (e instanceof OverlappingFileLockException) {
            return SSH_FX_LOCK_CONFLICT;
        } else if (e instanceof UnsupportedOperationException) {
            return SSH_FX_OP_UNSUPPORTED;
        } else if (e instanceof IllegalArgumentException) {
            return SSH_FX_INVALID_PARAMETER;
        } else {
            return SSH_FX_FAILURE;
        }
    }

    protected void sendStatus(Buffer buffer, int id, int substatus, String msg) throws IOException {
        sendStatus(buffer, id, substatus, (msg != null) ? msg : "", "");
    }

    protected void sendStatus(Buffer buffer, int id, int substatus, String msg, String lang) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Send SSH_FXP_STATUS (substatus={}, lang={}, msg={})",
                      Integer.valueOf(substatus), lang, msg);
        }

        buffer.putByte((byte) SSH_FXP_STATUS);
        buffer.putInt(id);
        buffer.putInt(substatus);
        buffer.putString(msg);
        buffer.putString(lang);
        send(buffer);
    }

    protected void send(Buffer buffer) throws IOException {
        int len = buffer.available();
        int used = BufferUtils.putUInt(len & 0xFFFFL, workBuf);
        out.write(workBuf, 0, used);
        out.write(buffer.array(), buffer.rpos(), len);
        out.flush();
    }

    @Override
    public void destroy() {
        if (!closed) {
            if (log.isDebugEnabled()) {
                log.debug("destroy() - mark as closed");
            }

            closed = true;

            // if thread has not completed, cancel it
            if ((pendingFuture != null) && (!pendingFuture.isDone())) {
                boolean result = pendingFuture.cancel(true);
                // TODO consider waiting some reasonable (?) amount of time for cancellation
                if (log.isDebugEnabled()) {
                    log.debug("destroy() - cancel pending future=" + result);
                }
            }

            pendingFuture = null;

            if ((executors != null) && (!executors.isShutdown()) && shutdownExecutor) {
                Collection<Runnable> runners = executors.shutdownNow();
                if (log.isDebugEnabled()) {
                    log.debug("destroy() - shutdown executor service - runners count=" + ((runners == null) ? 0 : runners.size()));
                }
            }

            executors = null;

            try {
                fileSystem.close();
            } catch (UnsupportedOperationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Closing the file system is not supported");
                }
            } catch (IOException e) {
                log.debug("Error closing FileSystem", e);
            }
        }
    }

    private Path resolveFile(String path) {
        //in case we are running on Windows
        String localPath = SelectorUtils.translateToLocalPath(path);
        return defaultDir.resolve(localPath);
    }

    private final static String[] MONTHS = { "Jan", "Feb", "Mar", "Apr", "May",
            "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /**
     * Get unix style date string.
     */
    private static String getUnixDate(FileTime time) {
        return getUnixDate(time != null ? time.toMillis() : -1);
    }

    private static String getUnixDate(long millis) {
        if (millis < 0) {
            return "------------";
        }

        StringBuilder sb = new StringBuilder(16);
        Calendar cal = new GregorianCalendar();
        cal.setTimeInMillis(millis);

        // month
        sb.append(MONTHS[cal.get(Calendar.MONTH)]);
        sb.append(' ');

        // day
        int day = cal.get(Calendar.DATE);
        if (day < 10) {
            sb.append(' ');
        }
        sb.append(day);
        sb.append(' ');

        long sixMonth = 15811200000L; // 183L * 24L * 60L * 60L * 1000L;
        long nowTime = System.currentTimeMillis();
        if (Math.abs(nowTime - millis) > sixMonth) {

            // year
            int year = cal.get(Calendar.YEAR);
            sb.append(' ');
            sb.append(year);
        } else {

            // hour
            int hh = cal.get(Calendar.HOUR_OF_DAY);
            if (hh < 10) {
                sb.append('0');
            }
            sb.append(hh);
            sb.append(':');

            // minute
            int mm = cal.get(Calendar.MINUTE);
            if (mm < 10) {
                sb.append('0');
            }
            sb.append(mm);
        }
        return sb.toString();
    }

    protected static class PrincipalBase implements Principal {
        private final String name;

        public PrincipalBase(String name) {
            if (name == null) {
                throw new IllegalArgumentException("name is null");
            }
            this.name = name;
        }

        @Override
        public final String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if ((o == null) || (getClass() != o.getClass())) {
                return false;
            }

            Principal that = (Principal) o;
            if (Objects.equals(getName(),that.getName())) {
                return true;
            } else {
                return false;    // debug breakpoint
            }
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(getName());
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    protected static class DefaultUserPrincipal extends PrincipalBase implements UserPrincipal {
        public DefaultUserPrincipal(String name) {
            super(name);
        }
    }

    protected static class DefaultGroupPrincipal extends PrincipalBase implements GroupPrincipal {
        public DefaultGroupPrincipal(String name) {
            super(name);
        }
    }
}
