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
import java.io.IOException;
import java.net.UnknownServiceException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemLoopException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpHelper;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.HardLinkExtensionParser;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;
import org.apache.sshd.server.CommandLifecycle;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.ExitCallbackAware;
import org.apache.sshd.server.ExitCallbackHolder;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;

/**
 * Base class with most of the SFTP subsystem support
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpSubsystemExecutor
        extends AbstractSftpSubsystemHelper
        implements SessionAware, FileSystemAware, ExecutorServiceConfigurer,
        ExitCallback, ExitCallbackAware, ExitCallbackHolder, CommandLifecycle {

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
     * Maximum amount of data allocated for listing the contents of a directory
     * in any single invocation of {@link #doReadDir(Buffer, int)}
     *
     * @see #DEFAULT_MAX_READDIR_DATA_SIZE
     */
    public static final String MAX_READDIR_DATA_SIZE_PROP = "sftp-max-readdir-data-size";
    public static final int DEFAULT_MAX_READDIR_DATA_SIZE = 16 * 1024;

    protected Random randomizer;
    protected int fileHandleSize = DEFAULT_FILE_HANDLE_SIZE;
    protected int maxFileHandleRounds = DEFAULT_FILE_HANDLE_ROUNDS;
    protected FileSystem fileSystem = FileSystems.getDefault();
    protected Path defaultDir = fileSystem.getPath(System.getProperty("user.dir"));

    protected final AtomicInteger workBufSizeHolder = new AtomicInteger(Math.max(DEFAULT_FILE_HANDLE_SIZE, Integer.BYTES));
    protected final ThreadLocal<byte[]> workBufHolder = new ThreadLocal<>();
    protected final AtomicLong requestsCounter = new AtomicLong(0L);
    protected final AtomicInteger versionHolder = new AtomicInteger(0);
    protected final Map<String, byte[]> extensionsMap = new TreeMap<>(Comparator.naturalOrder());
    protected final Map<String, Handle> handlesMap = new ConcurrentHashMap<>();
    protected final AtomicBoolean closed = new AtomicBoolean(false);

    private ServerSession serverSession;
    private ExecutorService executorService;
    private boolean shutdownOnExit;
    private ExitCallback callback;

    protected AbstractSftpSubsystemExecutor(UnsupportedAttributePolicy policy, SftpFileSystemAccessor accessor, SftpErrorStatusDataHandler handler) {
        this(null, true, policy, accessor, handler);
    }

    protected AbstractSftpSubsystemExecutor(ExecutorService executorService, boolean shutdownOnExit,
            UnsupportedAttributePolicy policy, SftpFileSystemAccessor accessor, SftpErrorStatusDataHandler handler) {
        super(policy, accessor, handler);
        this.executorService = executorService;
        this.shutdownOnExit = shutdownOnExit;
    }

    @Override
    public ExitCallback getExitCallback() {
        return callback;
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void onExit(int exitValue) {
        ExitCallback cb = getExitCallback();
        cb.onExit(exitValue);
    }

    @Override
    public void onExit(int exitValue, String exitMessage) {
        ExitCallback cb = getExitCallback();
        cb.onExit(exitValue, exitMessage);
    }

    @Override
    public int getVersion() {
        return versionHolder.get();
    }

    @Override
    public Path getDefaultDirectory() {
        return defaultDir;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public void setExecutorService(ExecutorService executorService) {
        this.executorService = executorService;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownOnExit;
    }

    @Override
    public void setShutdownOnExit(boolean shutdownOnExit) {
        this.shutdownOnExit = shutdownOnExit;
    }

    @Override
    public void setSession(ServerSession session) {
        this.serverSession = Objects.requireNonNull(session, "No session");

        FactoryManager manager = session.getFactoryManager();
        Factory<? extends Random> factory = manager.getRandomFactory();
        this.randomizer = factory.create();

        this.fileHandleSize = session.getIntProperty(FILE_HANDLE_SIZE, DEFAULT_FILE_HANDLE_SIZE);
        ValidateUtils.checkTrue(this.fileHandleSize >= MIN_FILE_HANDLE_SIZE, "File handle size too small: %d", this.fileHandleSize);
        ValidateUtils.checkTrue(this.fileHandleSize <= MAX_FILE_HANDLE_SIZE, "File handle size too big: %d", this.fileHandleSize);

        this.maxFileHandleRounds = session.getIntProperty(MAX_FILE_HANDLE_RAND_ROUNDS, DEFAULT_FILE_HANDLE_ROUNDS);
        ValidateUtils.checkTrue(this.maxFileHandleRounds >= MIN_FILE_HANDLE_ROUNDS, "File handle rounds too small: %d", this.maxFileHandleRounds);
        ValidateUtils.checkTrue(this.maxFileHandleRounds <= MAX_FILE_HANDLE_ROUNDS, "File handle rounds too big: %d", this.maxFileHandleRounds);

        workBufSizeHolder.set(Math.max(workBufSizeHolder.get(), this.fileHandleSize));
    }

    @Override
    public ServerSession getServerSession() {
        return serverSession;
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        if (fileSystem != this.fileSystem) {
            this.fileSystem = fileSystem;

            Iterable<Path> roots = Objects.requireNonNull(fileSystem.getRootDirectories(), "No root directories");
            Iterator<Path> available = Objects.requireNonNull(roots.iterator(), "No roots iterator");
            ValidateUtils.checkTrue(available.hasNext(), "No available root");
            this.defaultDir = available.next();
        }
    }

    @Override
    protected Buffer process(Buffer command) throws IOException {
        int length = command.getInt();
        int type = command.getUByte();
        int id = command.getInt();
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("process({})[length={}, type={}, id={}] processing",
                      session, length, SftpConstants.getCommandMessageName(type), id);
        }

        Buffer reply;
        switch (type) {
            case SftpConstants.SSH_FXP_INIT:
                reply = doInit(command, id);
                break;
            case SftpConstants.SSH_FXP_OPEN:
                reply = doOpen(command, id);
                break;
            case SftpConstants.SSH_FXP_CLOSE:
                reply = doClose(command, id);
                break;
            case SftpConstants.SSH_FXP_READ:
                reply = doRead(command, id);
                break;
            case SftpConstants.SSH_FXP_WRITE:
                reply = doWrite(command, id);
                break;
            case SftpConstants.SSH_FXP_LSTAT:
                reply = doLStat(command, id);
                break;
            case SftpConstants.SSH_FXP_FSTAT:
                reply = doFStat(command, id);
                break;
            case SftpConstants.SSH_FXP_SETSTAT:
                reply = doSetStat(command, id);
                break;
            case SftpConstants.SSH_FXP_FSETSTAT:
                reply = doFSetStat(command, id);
                break;
            case SftpConstants.SSH_FXP_OPENDIR:
                reply = doOpenDir(command, id);
                break;
            case SftpConstants.SSH_FXP_READDIR:
                reply = doReadDir(command, id);
                break;
            case SftpConstants.SSH_FXP_REMOVE:
                reply = doRemove(command, id);
                break;
            case SftpConstants.SSH_FXP_MKDIR:
                reply = doMakeDirectory(command, id);
                break;
            case SftpConstants.SSH_FXP_RMDIR:
                reply = doRemoveDirectory(command, id);
                break;
            case SftpConstants.SSH_FXP_REALPATH:
                reply = doRealPath(command, id);
                break;
            case SftpConstants.SSH_FXP_STAT:
                reply = doStat(command, id);
                break;
            case SftpConstants.SSH_FXP_RENAME:
                reply = doRename(command, id);
                break;
            case SftpConstants.SSH_FXP_READLINK:
                reply = doReadLink(command, id);
                break;
            case SftpConstants.SSH_FXP_SYMLINK:
                reply = doSymLink(command, id);
                break;
            case SftpConstants.SSH_FXP_LINK:
                reply = doLink(command, id);
                break;
            case SftpConstants.SSH_FXP_BLOCK:
                reply = doBlock(command, id);
                break;
            case SftpConstants.SSH_FXP_UNBLOCK:
                reply = doUnblock(command, id);
                break;
            case SftpConstants.SSH_FXP_EXTENDED:
                reply = doExtended(command, id);
                break;
            default: {
                String name = SftpConstants.getCommandMessageName(type);
                log.warn("process({})[length={}, type={}, id={}] unknown command", session, length, name, id);
                reply = sendStatus(BufferUtils.clear(command), id, SftpConstants.SSH_FX_OP_UNSUPPORTED, "Command " + name + " is unsupported or not implemented");
            }
        }

        if (type != SftpConstants.SSH_FXP_INIT) {
            requestsCounter.incrementAndGet();
        }

        return reply;
    }

    @Override
    protected Buffer executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
        switch (extension) {
            case SftpConstants.EXT_TEXT_SEEK:
                return doTextSeek(buffer, id);
            case SftpConstants.EXT_VERSION_SELECT:
                return doVersionSelect(buffer, id);
            case SftpConstants.EXT_COPY_FILE:
                return doCopyFile(buffer, id);
            case SftpConstants.EXT_COPY_DATA:
                return doCopyData(buffer, id);
            case SftpConstants.EXT_MD5_HASH:
            case SftpConstants.EXT_MD5_HASH_HANDLE:
                return doMD5Hash(buffer, id, extension);
            case SftpConstants.EXT_CHECK_FILE_HANDLE:
            case SftpConstants.EXT_CHECK_FILE_NAME:
                return doCheckFileHash(buffer, id, extension);
            case FsyncExtensionParser.NAME:
                return doOpenSSHFsync(buffer, id);
            case SftpConstants.EXT_SPACE_AVAILABLE:
                return doSpaceAvailable(buffer, id);
            case HardLinkExtensionParser.NAME:
                return doOpenSSHHardLink(buffer, id);
            default:
                if (log.isDebugEnabled()) {
                    log.debug("executeExtendedCommand({}) received unsupported SSH_FXP_EXTENDED({})", getServerSession(), extension);
                }
                return sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OP_UNSUPPORTED,
                    "Command SSH_FXP_EXTENDED(" + extension + ") is unsupported or not implemented");
        }
    }

    @Override
    protected void createLink(int id, String existingPath, String linkPath, boolean symLink) throws IOException {
        Path link = resolveFile(linkPath);
        Path existing = fileSystem.getPath(existingPath);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("createLink({})[id={}], existing={}[{}], link={}[{}], symlink={})",
                session, id, linkPath, link, existingPath, existing, symLink);
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.linking(session, link, existing, symLink);
        try {
            if (symLink) {
                Files.createSymbolicLink(link, existing);
            } else {
                Files.createLink(link, existing);
            }
        } catch (IOException | RuntimeException e) {
            listener.linked(session, link, existing, symLink, e);
            throw e;
        }
        listener.linked(session, link, existing, symLink, null);
    }

    @Override
    protected void doTextSeek(int id, String handle, long line) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }
        if (log.isDebugEnabled()) {
            log.debug("doTextSeek({})[id={}] SSH_FXP_EXTENDED(text-seek) (handle={}[{}], line={})",
                      getServerSession(), id, handle, h, line);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        throw new UnknownServiceException("doTextSeek(" + fileHandle + ")");
    }

    @Override
    protected void doOpenSSHFsync(int id, String handle) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doOpenSSHFsync({})[id={}] {}[{}]", session, id, handle, h);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.syncFileData(session, this, fileHandle.getFile(), fileHandle.getFileHandle(), fileHandle.getFileChannel());
    }

    @Override
    protected void doCheckFileHash(
            int id, String targetType, String target, Collection<String> algos,
            long startOffset, long length, int blockSize, Buffer buffer)
                    throws Exception {
        Path path;
        if (SftpConstants.EXT_CHECK_FILE_HANDLE.equalsIgnoreCase(targetType)) {
            Handle h;
            synchronized (handlesMap) {
                h = handlesMap.get(target);
            }

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
                throw new AccessDeniedException(path.toString(), path.toString(), "File not opened for read");
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
                throw new FileSystemLoopException(target);
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

    @Override
    protected byte[] doMD5Hash(
            int id, String targetType, String target, long startOffset, long length, byte[] quickCheckHash)
                    throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("doMD5Hash({})({})[{}] offset={}, length={}, quick-hash={}",
                      getServerSession(), targetType, target, startOffset, length,
                      BufferUtils.toHex(':', quickCheckHash));
        }

        Path path;
        if (SftpConstants.EXT_MD5_HASH_HANDLE.equalsIgnoreCase(targetType)) {
            Handle h;
            synchronized (handlesMap) {
                h = handlesMap.get(target);
            }
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
                throw new AccessDeniedException(path.toString(), path.toString(), "File not opened for read");
            }
        } else {
            path = resolveFile(target);
            if (Files.isDirectory(path, IoUtils.getLinkOptions(true))) {
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

    protected Buffer doVersionSelect(Buffer buffer, int id) throws IOException {
        String proposed = buffer.getString();
        ServerSession session = getServerSession();
        /*
         * The 'version-select' MUST be the first request from the client to the
         * server; if it is not, the server MUST fail the request and close the
         * channel.
         */
        if (requestsCounter.get() > 0L) {
            buffer = sendStatus(BufferUtils.clear(buffer), id,
                SftpConstants.SSH_FX_FAILURE,
                "Version selection not the 1st request for proposal = " + proposed);
            session.close(true);
            return buffer;
        }

        Boolean result = validateProposedVersion(buffer, id, proposed);
        /*
         * "MUST then close the channel without processing any further requests"
         */
        if (result == null) {   // response sent internally
            session.close(true);
            return null;
        }
        if (result) {
            versionHolder.set(Integer.parseInt(proposed));
            return sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_OK, "");
        } else {
            buffer = sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_FAILURE, "Unsupported version " + proposed);
            session.close(true);
            return buffer;
        }
    }

    @Override
    protected void doBlock(int id, String handle, long offset, long length, int mask) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doBlock({})[id={}] SSH_FXP_BLOCK (handle={}[{}], offset={}, length={}, mask=0x{})",
                session, id, handle, h, offset, length, Integer.toHexString(mask));
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.blocking(session, handle, fileHandle, offset, length, mask);
        try {
            fileHandle.lock(offset, length, mask);
        } catch (IOException | RuntimeException e) {
            listener.blocked(session, handle, fileHandle, offset, length, mask, e);
            throw e;
        }
        listener.blocked(session, handle, fileHandle, offset, length, mask, null);
    }

    @Override
    protected void doUnblock(int id, String handle, long offset, long length) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doUnblock({})[id={}] SSH_FXP_UNBLOCK (handle={}[{}], offset={}, length={})",
                session, id, handle, h, offset, length);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.unblocking(session, handle, fileHandle, offset, length);
        try {
            fileHandle.unlock(offset, length);
        } catch (IOException | RuntimeException e) {
            listener.unblocked(session, handle, fileHandle, offset, length, e);
            throw e;
        }
        listener.unblocked(session, handle, fileHandle, offset, length, null);
    }

    @Override
    @SuppressWarnings("resource")
    protected void doCopyData(int id, String readHandle, long readOffset, long readLength, String writeHandle, long writeOffset) throws IOException {
        boolean inPlaceCopy = Objects.equals(readHandle, writeHandle);

        Handle rh;
        Handle wh;
        synchronized (handlesMap) {
            rh = handlesMap.get(readHandle);
            wh = inPlaceCopy ? rh : handlesMap.get(writeHandle);
        }

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
            throw new AccessDeniedException(srcPath.toString(), srcPath.toString(), "Source file not opened for read");
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
            throw new AccessDeniedException(srcHandle.toString(), srcHandle.toString(), "Source handle not opened for write");
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
            int readLen;
            synchronized (srcHandle) {
                readLen = srcHandle.read(copyBuf, 0, remainLength, readOffset);
            }
            if (readLen < 0) {
                throw new EOFException("Premature EOF while still remaining " + effectiveLength + " bytes");
            }

            synchronized (dstHandle) {
                dstHandle.write(copyBuf, 0, readLen, writeOffset);
            }

            effectiveLength -= readLen;
            readOffset += readLen;
            writeOffset += readLen;
        }
    }

    @Override
    protected Buffer doReadDir(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doReadDir({})[id={}] SSH_FXP_READDIR (handle={}[{}])", session, id, handle, h);
        }

        Buffer reply = null;
        try {
            DirectoryHandle dh = validateHandle(handle, h, DirectoryHandle.class);
            boolean done;
            synchronized (dh) {
                done = dh.isDone();
            }
            if (done) {
                return sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_EOF, "Directory reading is done");
            }

            Path file = dh.getFile();
            LinkOption[] options =
                getPathResolutionLinkOption(SftpConstants.SSH_FXP_READDIR, "", file);
            Boolean status = IoUtils.checkFileExists(file, options);
            if (status == null) {
                throw new AccessDeniedException(file.toString(), file.toString(), "Cannot determine existence of read-dir");
            }

            if (!status) {
                throw new NoSuchFileException(file.toString(), file.toString(), "Non-existent directory");
            } else if (!Files.isDirectory(file, options)) {
                throw new NotDirectoryException(file.toString());
            } else if (!Files.isReadable(file)) {
                throw new AccessDeniedException(file.toString(), file.toString(), "Not readable");
            }

            boolean emptyDir;
            synchronized (dh) {
                if (dh.isSendDot() || dh.isSendDotDot() || dh.hasNext()) {
                    emptyDir = false;   // still have something to send
                    // There is at least one file in the directory or we need to send the "..".
                    // Send only a few files at a time to not create packets of a too
                    // large size or have a timeout to occur.

                    reply = BufferUtils.clear(buffer);
                    reply.putByte((byte) SftpConstants.SSH_FXP_NAME);
                    reply.putInt(id);

                    int lenPos = reply.wpos();
                    reply.putInt(0);

                    int maxDataSize = session.getIntProperty(MAX_READDIR_DATA_SIZE_PROP, DEFAULT_MAX_READDIR_DATA_SIZE);
                    int count = doReadDir(id, handle, dh, reply, maxDataSize, IoUtils.getLinkOptions(false));
                    BufferUtils.updateLengthPlaceholder(reply, lenPos, count);
                    if ((!dh.isSendDot()) && (!dh.isSendDotDot()) && (!dh.hasNext())) {
                        dh.markDone();
                    }

                    Boolean indicator =
                        SftpHelper.indicateEndOfNamesList(reply, getVersion(), session, dh.isDone());
                    if (debugEnabled) {
                        log.debug("doReadDir({})({})[{}] - seding {} entries - eol={}", session, handle, h, count, indicator);
                    }
                } else {
                    // empty directory
                    dh.markDone();
                    emptyDir = true;
                }
            }

            if (emptyDir) {
                return sendStatus(BufferUtils.clear(buffer), id, SftpConstants.SSH_FX_EOF, "Empty directory");
            }

            Objects.requireNonNull(reply, "No reply buffer created");
        } catch (IOException | RuntimeException e) {
            return sendStatus(BufferUtils.clear(buffer), id, e, SftpConstants.SSH_FXP_READDIR, handle);
        }

        return send(reply);
    }

    @Override
    protected String doOpenDir(int id, String path, Path p, LinkOption... options) throws IOException {
        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException(p.toString(), p.toString(), "Cannot determine open-dir existence");
        }

        if (!status) {
            throw new NoSuchFileException(path, path, "Referenced target directory N/A");
        } else if (!Files.isDirectory(p, options)) {
            throw new NotDirectoryException(path);
        } else if (!Files.isReadable(p)) {
            throw new AccessDeniedException(p.toString(), p.toString(), "Not readable");
        } else {
            String handle;
            synchronized (handlesMap) {
                handle = generateFileHandle(p);
                DirectoryHandle dirHandle = new DirectoryHandle(this, p, handle);
                handlesMap.put(handle, dirHandle);
            }
            return handle;
        }
    }

    @Override
    protected void doFSetStat(int id, String handle, Map<String, ?> attrs) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }
        if (log.isDebugEnabled()) {
            log.debug("doFsetStat({})[id={}] SSH_FXP_FSETSTAT (handle={}[{}], attrs={})",
                      getServerSession(), id, handle, h, attrs);
        }

        Handle fileHandle = validateHandle(handle, h, Handle.class);
        doSetAttributes(fileHandle.getFile(), attrs);
    }

    @Override
    protected Map<String, Object> doFStat(int id, String handle, int flags) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }
        if (log.isDebugEnabled()) {
            log.debug("doFStat({})[id={}] SSH_FXP_FSTAT (handle={}[{}], flags=0x{})",
                      getServerSession(), id, handle, h, Integer.toHexString(flags));
        }

        Handle fileHandle = validateHandle(handle, h, Handle.class);
        return resolveFileAttributes(fileHandle.getFile(), flags, IoUtils.getLinkOptions(true));
    }

    @Override
    protected void doWrite(int id, String handle, long offset, int length, byte[] data, int doff, int remaining) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        if (log.isTraceEnabled()) {
            log.trace("doWrite({})[id={}] SSH_FXP_WRITE (handle={}[{}], offset={}, data=byte[{}])",
                      session, id, handle, h, offset, length);
        }

        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        if (length < 0) {
            throw new IllegalStateException("Bad length (" + length + ") for writing to " + fh);
        }

        if (remaining < length) {
            throw new IllegalStateException("Not enough buffer data for writing to " + fh + ": required=" + length + ", available=" + remaining);
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.writing(session, handle, fh, offset, data, doff, length);
        try {
            boolean appendMode = fh.isOpenAppend();
            synchronized (fh) {
                if (appendMode) {
                    fh.append(data, doff, length);
                } else {
                    fh.write(data, doff, length, offset);
                }
            }
        } catch (IOException | RuntimeException e) {
            listener.written(session, handle, fh, offset, data, doff, length, e);
            throw e;
        }
        listener.written(session, handle, fh, offset, data, doff, length, null);
    }

    @Override
    protected int doRead(int id, String handle, long offset, int length, byte[] data, int doff) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.get(handle);
        }

        ServerSession session = getServerSession();
        if (log.isTraceEnabled()) {
            log.trace("doRead({})[id={}] SSH_FXP_READ (handle={}[{}], offset={}, length={})",
                    session, id, handle, h, offset, length);
        }

        ValidateUtils.checkTrue(length > 0L, "Invalid read length: %d", length);
        FileHandle fh = validateHandle(handle, h, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        int readLen;
        listener.reading(session, handle, fh, offset, data, doff, length);
        try {
            synchronized (fh) {
                readLen = fh.read(data, doff, length, offset);
            }
        } catch (IOException | RuntimeException e) {
            listener.read(session, handle, fh, offset, data, doff, length, -1, e);
            throw e;
        }
        listener.read(session, handle, fh, offset, data, doff, length, readLen, null);
        return readLen;
    }

    @Override
    protected void doClose(int id, String handle) throws IOException {
        Handle h;
        synchronized (handlesMap) {
            h = handlesMap.remove(handle);
        }

        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doClose({})[id={}] SSH_FXP_CLOSE (handle={}[{}])",
                      session, id, handle, h);
        }

        h = validateHandle(handle, h, Handle.class);
        h = closeHandle(h);

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.close(session, handle, h);
    }

    @Override
    protected String doOpen(int id, String path, int pflags, int access, Map<String, Object> attrs) throws IOException {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doOpen({})[id={}] SSH_FXP_OPEN (path={}, access=0x{}, pflags=0x{}, attrs={})",
                      session, id, path, Integer.toHexString(access), Integer.toHexString(pflags), attrs);
        }

        int curHandleCount;
        synchronized (handlesMap) {
            curHandleCount = handlesMap.size();
        }
        int maxHandleCount = session.getIntProperty(MAX_OPEN_HANDLES_PER_SESSION, DEFAULT_MAX_OPEN_HANDLES);
        if (curHandleCount > maxHandleCount) {
            throw new IllegalStateException("Too many open handles: current=" + curHandleCount + ", max.=" + maxHandleCount);
        }

        Path file = resolveFile(path);
        String handle;
        synchronized (handlesMap) {
            handle = generateFileHandle(file);
            FileHandle fileHandle = new FileHandle(this, file, handle, pflags, access, attrs);
            handlesMap.put(handle, fileHandle);
        }

        return handle;
    }

    // we stringify our handles and treat them as such on decoding as well as it is easier to use as a map key
    // NOTE: assumes handlesMap is locked
    protected String generateFileHandle(Path file) {
        // use several rounds in case the file handle size is relatively small so we might get conflicts
        boolean traceEnabled = log.isTraceEnabled();
        byte[] workBuf = getTemporaryWorkBuffer(fileHandleSize);
        for (int index = 0; index < maxFileHandleRounds; index++) {
            randomizer.fill(workBuf, 0, fileHandleSize);
            String handle = BufferUtils.toHex(workBuf, 0, fileHandleSize, BufferUtils.EMPTY_HEX_SEPARATOR);
            if (handlesMap.containsKey(handle)) {
                if (traceEnabled) {
                    log.trace("generateFileHandle({})[{}] handle={} in use at round {}",
                              getServerSession(), file, handle, index);
                }
                continue;
            }

            if (traceEnabled) {
                log.trace("generateFileHandle({})[{}] {}", getServerSession(), file, handle);
            }
            return handle;
        }

        throw new IllegalStateException("Failed to generate a unique file handle for " + file);
    }

    protected Buffer doInit(Buffer buffer, int id) throws IOException {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doInit({})[id={}] SSH_FXP_INIT (version={})", session, id, id);
        }

        String all = checkVersionCompatibility(buffer, id, id, SftpConstants.SSH_FX_OP_UNSUPPORTED);
        if (GenericUtils.isEmpty(all)) { // i.e. validation failed
            return null;
        }

        versionHolder.set(id);
        synchronized (extensionsMap) {
            while (buffer.available() > 0) {
                String name = buffer.getString();
                byte[] data = buffer.getBytes();
                extensionsMap.put(name, data);
            }
        }

        buffer.clear();

        int version = getVersion();
        buffer.putByte((byte) SftpConstants.SSH_FXP_VERSION);
        buffer.putInt(version);
        appendExtensions(buffer, all);

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.initialized(session, version);

        return send(buffer);
    }

    protected byte[] getTemporaryWorkBuffer(int minSize) {
        byte[] workBuf = workBufHolder.get();
        if ((workBuf == null) || (workBuf.length < minSize)) {
            workBuf = new byte[Math.max(minSize, workBufSizeHolder.get())];
            workBufHolder.set(workBuf);
        }

        return workBuf;
    }

    @Override
    public void destroy() throws Exception {
        ServerSession session = getServerSession();
        Exception err = null;
        try {
            preDestroy();
        } catch (Exception e) {
            log.error("destroy({}) failed ({}) to pre-destroy: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            doDestroy();
        } catch (Exception e) {
            log.error("destroy({}) failed ({}) to do-destroy: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            postDestroy();
        } catch (Exception e) {
            log.error("destroy({}) failed ({}) to post-destroy: {}",
                    session, e.getClass().getSimpleName(), e.getMessage());
            err = GenericUtils.accumulateException(err, e);
        }

        if (err != null) {
            throw err;
        }
    }

    protected void preDestroy() throws Exception {
        if (closed.getAndSet(true)) {
            return; // ignore if already closed
        }

        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("preDestroy({}) - mark as closed", session);
        }

        try {
            SftpEventListener listener = getSftpEventListenerProxy();
            listener.destroying(session);
        } catch (Exception e) {
            log.warn("preDestroy({}) Failed ({}) to announce destruction event: {}",
                session, e.getClass().getSimpleName(), e.getMessage());
            if (debugEnabled) {
                log.debug("preDestroy(" + session + ") destruction announcement failure details", e);
            }
        }
    }

    protected abstract void doDestroy() throws Exception;

    protected void postDestroy() throws Exception {
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();

        closeAllHandles();

        try {
            fileSystem.close();
        } catch (UnsupportedOperationException e) {
            if (debugEnabled) {
                log.debug("postDestroy(" + session + ") closing the file system is not supported");
            }
        } catch (IOException e) {
            if (debugEnabled) {
                log.debug("postDestroy(" + session + ")"
                        + " failed (" + e.getClass().getSimpleName() + ")"
                        + " to close file system: " + e.getMessage(), e);
            }
        }
    }

    protected void closeAllHandles() {
        boolean debugEnabled = log.isDebugEnabled();
        ServerSession session = getServerSession();
        synchronized (handlesMap) {
            handlesMap.forEach((id, handle) -> {
                try {
                    handle = closeHandle(handle);
                    if (debugEnabled) {
                        log.debug("run({}) closed pending handle {} [{}]", session, id, handle);
                    }
                } catch (IOException ioe) {
                    log.error("run({}) failed ({}) to close handle={}[{}]: {}",
                          session, ioe.getClass().getSimpleName(), id, handle, ioe.getMessage());
                }
            });
            handlesMap.clear();
        }
    }

    protected <H extends Handle> H closeHandle(H handle) throws IOException {
        if (handle == null) {
            return null;
        }

        synchronized (handle) {
            handle.close();
        }

        return handle;
    }
}
