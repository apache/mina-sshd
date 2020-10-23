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
package org.apache.sshd.sftp.server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
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
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.channel.BufferedIoOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.ChannelSessionAware;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.channel.ChannelDataReceiver;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AsyncCommand;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.SftpHelper;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem
        extends AbstractSftpSubsystemHelper
        implements Command, Runnable, SessionAware, FileSystemAware, ExecutorServiceCarrier,
        AsyncCommand, ChannelSessionAware, ChannelDataReceiver {

    protected static final Buffer CLOSE = new ByteArrayBuffer(null, 0, 0);

    protected final AtomicBoolean closed = new AtomicBoolean(false);
    protected final AtomicLong requestsCount = new AtomicLong(0L);
    protected final Map<String, byte[]> extensions = new TreeMap<>(Comparator.naturalOrder());
    protected final Map<String, Handle> handles = new ConcurrentHashMap<>();
    protected final Buffer buffer = new ByteArrayBuffer(1024);
    protected final BlockingQueue<Buffer> requests = new LinkedBlockingQueue<>();

    protected ExitCallback callback;
    protected IoOutputStream out;
    protected IoOutputStream err;
    protected Environment env;
    protected Random randomizer;
    protected int fileHandleSize = SftpModuleProperties.DEFAULT_FILE_HANDLE_SIZE;
    protected int maxFileHandleRounds = SftpModuleProperties.DEFAULT_FILE_HANDLE_ROUNDS;
    protected Future<?> pendingFuture;
    protected byte[] workBuf = new byte[Math.max(SftpModuleProperties.DEFAULT_FILE_HANDLE_SIZE, Integer.BYTES)];
    protected FileSystem fileSystem = FileSystems.getDefault();
    protected Path defaultDir = fileSystem.getPath("").toAbsolutePath().normalize();
    protected int version;

    protected ServerSession serverSession;
    protected ChannelSession channelSession;
    protected CloseableExecutorService executorService;

    /**
     * @param executorService        The {@link CloseableExecutorService} to be used by the {@link SftpSubsystem}
     *                               command when starting execution. If {@code null} then a single-threaded ad-hoc
     *                               service is used.
     * @param policy                 The {@link UnsupportedAttributePolicy} to use if failed to access some local file
     *                               attributes
     * @param accessor               The {@link SftpFileSystemAccessor} to use for opening files and directories
     * @param errorStatusDataHandler The (never {@code null}) {@link SftpErrorStatusDataHandler} to use when generating
     *                               failed commands error messages
     * @see                          ThreadUtils#newSingleThreadExecutor(String)
     */
    public SftpSubsystem(
                         CloseableExecutorService executorService, UnsupportedAttributePolicy policy,
                         SftpFileSystemAccessor accessor, SftpErrorStatusDataHandler errorStatusDataHandler) {
        super(policy, accessor, errorStatusDataHandler);

        if (executorService == null) {
            this.executorService = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
        } else {
            this.executorService = executorService;
        }
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public Path getDefaultDirectory() {
        return defaultDir;
    }

    @Override
    public CloseableExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public void setSession(ServerSession session) {
        this.serverSession = Objects.requireNonNull(session, "No session");

        FactoryManager manager = session.getFactoryManager();
        Factory<? extends Random> factory = manager.getRandomFactory();
        this.randomizer = factory.create();

        this.fileHandleSize = SftpModuleProperties.FILE_HANDLE_SIZE.getRequired(session);
        this.maxFileHandleRounds = SftpModuleProperties.MAX_FILE_HANDLE_RAND_ROUNDS.getRequired(session);

        if (workBuf.length < this.fileHandleSize) {
            workBuf = new byte[this.fileHandleSize];
        }
    }

    @Override
    public ServerSession getServerSession() {
        return serverSession;
    }

    @Override
    public void setChannelSession(ChannelSession session) {
        this.channelSession = session;
        session.setDataReceiver(this);

        SftpErrorStatusDataHandler errHandler = getErrorStatusDataHandler();
        if (errHandler instanceof ChannelSessionAware) {
            ((ChannelSessionAware) errHandler).setChannelSession(session);
        }
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        if (fileSystem != this.fileSystem) {
            this.fileSystem = fileSystem;
            this.defaultDir = fileSystem.getPath("").toAbsolutePath().normalize();
        }
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void setInputStream(InputStream in) {
        // Do nothing
    }

    @Override
    public void setOutputStream(OutputStream out) {
        // Do nothing
    }

    @Override
    public void setErrorStream(OutputStream err) {
        // Do nothing
    }

    @Override
    public void setIoInputStream(IoInputStream in) {
        // Do nothing
    }

    @Override
    public void setIoOutputStream(IoOutputStream out) {
        this.out = new BufferedIoOutputStream("sftp out buffer", out);
    }

    @Override
    public void setIoErrorStream(IoOutputStream err) {
        this.err = err;
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        this.env = env;
        try {
            CloseableExecutorService executor = getExecutorService();
            pendingFuture = executor.submit(this);
        } catch (RuntimeException e) { // e.g., RejectedExecutionException
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start command: " + e.getMessage(), e);
            throw new IOException(e);
        }
    }

    @Override
    public int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException {
        buffer.compact();
        buffer.putRawBytes(buf, start, len);
        while (buffer.available() >= Integer.BYTES) {
            int rpos = buffer.rpos();
            int msglen = buffer.getInt();
            if (buffer.available() >= msglen) {
                Buffer b = new ByteArrayBuffer(msglen + Integer.BYTES + Long.SIZE /* a bit extra */, false);
                b.putInt(msglen);
                b.putRawBytes(buffer.array(), buffer.rpos(), msglen);
                requests.add(b);
                buffer.rpos(rpos + msglen + Integer.BYTES);
            } else {
                buffer.rpos(rpos);
                break;
            }
        }
        return 0;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Buffer buffer = requests.take();
                if (buffer == CLOSE) {
                    break;
                }
                int len = buffer.available();
                process(buffer);
                Window localWindow = channelSession.getLocalWindow();
                localWindow.consumeAndCheck(len);
            }
        } catch (Throwable t) {
            if (!closed.get()) { // Ignore
                Session session = getServerSession();
                error("run({}) {} caught in SFTP subsystem: {}",
                        session, t.getClass().getSimpleName(), t.getMessage(), t);
            }
        } finally {
            closeAllHandles();
            callback.onExit(0);
        }
    }

    @Override
    public void close() throws IOException {
        requests.clear();
        requests.add(CLOSE);
    }

    @Override
    protected void doProcess(Buffer buffer, int length, int type, int id) throws IOException {
        super.doProcess(buffer, length, type, id);
        if (type != SftpConstants.SSH_FXP_INIT) {
            requestsCount.incrementAndGet();
        }
    }

    @Override
    protected void createLink(
            int id, String existingPath, String linkPath, boolean symLink)
            throws IOException {
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
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            accessor.createLink(session, this, link, existing, symLink);
        } catch (IOException | RuntimeException | Error e) {
            listener.linked(session, link, existing, symLink, e);
            throw e;
        }
        listener.linked(session, link, existing, symLink, null);
    }

    @Override
    protected void doTextSeek(int id, String handle, long line) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doTextSeek({})[id={}] SSH_FXP_EXTENDED(text-seek) (handle={}[{}], line={})",
                    getServerSession(), id, handle, h, line);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        throw new UnknownServiceException("doTextSeek(" + fileHandle + ")");
    }

    @Override
    protected void doOpenSSHFsync(int id, String handle) throws IOException {
        Handle h = handles.get(handle);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doOpenSSHFsync({})[id={}] {}[{}]", session, id, handle, h);
        }

        FileHandle fileHandle = validateHandle(handle, h, FileHandle.class);
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.syncFileData(
                session, this, fileHandle, fileHandle.getFile(),
                fileHandle.getFileHandle(), fileHandle.getFileChannel());
    }

    @Override
    protected void doCheckFileHash(
            int id, String targetType, String target, Collection<String> algos,
            long startOffset, long length, int blockSize, Buffer buffer)
            throws Exception {
        Path path;
        if (SftpConstants.EXT_CHECK_FILE_HANDLE.equalsIgnoreCase(targetType)) {
            Handle h = handles.get(target);
            FileHandle fileHandle = validateHandle(target, h, FileHandle.class);
            path = fileHandle.getFile();

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
             * section 9.1.2:
             *
             * If ACE4_READ_DATA was not included when the file was opened, the server MUST return
             * STATUS_PERMISSION_DENIED.
             */
            int access = fileHandle.getAccessMask();
            if ((access & SftpConstants.ACE4_READ_DATA) == 0) {
                throw new AccessDeniedException(
                        path.toString(), path.toString(), "File not opened for read");
            }
        } else {
            path = resolveFile(target);

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
             * section 9.1.2:
             *
             * If 'check-file-name' refers to a SSH_FILEXFER_TYPE_SYMLINK, the target should be opened.
             */
            for (int index = 0;
                 Files.isSymbolicLink(path) && (index < Byte.MAX_VALUE /* TODO make this configurable */);
                 index++) {
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
            Handle h = handles.get(target);
            FileHandle fileHandle = validateHandle(target, h, FileHandle.class);
            path = fileHandle.getFile();

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
             * section 9.1.1:
             *
             * The handle MUST be a file handle, and ACE4_READ_DATA MUST have been included in the desired-access when
             * the file was opened
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
         * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt section
         * 9.1.1:
         *
         * If both start-offset and length are zero, the entire file should be included
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

    @Override
    protected void doVersionSelect(Buffer buffer, int id, String proposed) throws IOException {
        ServerSession session = getServerSession();
        /*
         * The 'version-select' MUST be the first request from the client to the server; if it is not, the server MUST
         * fail the request and close the channel.
         */
        if (requestsCount.get() > 0L) {
            sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_FAILURE,
                    "Version selection not the 1st request for proposal = " + proposed);
            session.close(true);
            return;
        }

        Boolean result = validateProposedVersion(buffer, id, proposed);
        /*
         * "MUST then close the channel without processing any further requests"
         */
        if (result == null) { // response sent internally
            session.close(true);
            return;
        }
        if (result) {
            version = Integer.parseInt(proposed);
            sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
        } else {
            sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_FAILURE, "Unsupported version " + proposed);
            session.close(true);
        }
    }

    @Override
    protected void doBlock(int id, String handle, long offset, long length, int mask) throws IOException {
        Handle p = handles.get(handle);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doBlock({})[id={}] SSH_FXP_BLOCK (handle={}[{}], offset={}, length={}, mask=0x{})",
                    session, id, handle, p, offset, length, Integer.toHexString(mask));
        }

        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.blocking(session, handle, fileHandle, offset, length, mask);
        try {
            fileHandle.lock(offset, length, mask);
        } catch (IOException | RuntimeException | Error e) {
            listener.blocked(session, handle, fileHandle, offset, length, mask, e);
            throw e;
        }
        listener.blocked(session, handle, fileHandle, offset, length, mask, null);
    }

    @Override
    protected void doUnblock(int id, String handle, long offset, long length) throws IOException {
        Handle p = handles.get(handle);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doUnblock({})[id={}] SSH_FXP_UNBLOCK (handle={}[{}], offset={}, length={})",
                    session, id, handle, p, offset, length);
        }

        FileHandle fileHandle = validateHandle(handle, p, FileHandle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        listener.unblocking(session, handle, fileHandle, offset, length);
        try {
            fileHandle.unlock(offset, length);
        } catch (IOException | RuntimeException | Error e) {
            listener.unblocked(session, handle, fileHandle, offset, length, e);
            throw e;
        }
        listener.unblocked(session, handle, fileHandle, offset, length, null);
    }

    @Override
    @SuppressWarnings("resource")
    protected void doCopyData(
            int id, String readHandle, long readOffset, long readLength, String writeHandle, long writeOffset)
            throws IOException {
        boolean inPlaceCopy = readHandle.equals(writeHandle);
        Handle rh = handles.get(readHandle);
        Handle wh = inPlaceCopy ? rh : handles.get(writeHandle);
        if (log.isDebugEnabled()) {
            log.debug("doCopyData({})[id={}] SSH_FXP_EXTENDED[{}] read={}[{}]"
                      + ", read-offset={}, read-length={}, write={}[{}], write-offset={})",
                    getServerSession(), id, SftpConstants.EXT_COPY_DATA,
                    readHandle, rh, readOffset, readLength,
                    writeHandle, wh, writeOffset);
        }

        FileHandle srcHandle = validateHandle(readHandle, rh, FileHandle.class);
        Path srcPath = srcHandle.getFile();
        int srcAccess = srcHandle.getAccessMask();
        if ((srcAccess & SftpConstants.ACE4_READ_DATA) != SftpConstants.ACE4_READ_DATA) {
            throw new AccessDeniedException(
                    srcPath.toString(), srcPath.toString(), "Source file not opened for read");
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
        ValidateUtils.checkTrue(effectiveLength > 0L,
                "Non-positive effective copy data length: %d", effectiveLength);

        FileHandle dstHandle = inPlaceCopy ? srcHandle : validateHandle(writeHandle, wh, FileHandle.class);
        int dstAccess = dstHandle.getAccessMask();
        if ((dstAccess & SftpConstants.ACE4_WRITE_DATA) != SftpConstants.ACE4_WRITE_DATA) {
            throw new AccessDeniedException(
                    srcHandle.toString(), srcHandle.toString(), "Source handle not opened for write");
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
                throw new IllegalArgumentException(
                        "Write range end [" + writeOffset + "-" + maxWrite + "]"
                                                   + " overlaps with read range [" + readOffset + "-" + maxRead + "]");
            } else if (maxRead > writeOffset) {
                throw new IllegalArgumentException(
                        "Read range end [" + readOffset + "-" + maxRead + "]"
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

    @Override
    protected void doReadDir(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Handle h = handles.get(handle);
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doReadDir({})[id={}] SSH_FXP_READDIR (handle={}[{}])", session, id, handle, h);
        }

        Buffer reply = null;
        try {
            DirectoryHandle dh = validateHandle(handle, h, DirectoryHandle.class);
            if (dh.isDone()) {
                sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_EOF, "Directory reading is done");
                return;
            }

            Path file = dh.getFile();
            LinkOption[] options = getPathResolutionLinkOption(SftpConstants.SSH_FXP_READDIR, "", file);
            Boolean status = IoUtils.checkFileExists(file, options);
            if (status == null) {
                throw new AccessDeniedException(
                        file.toString(), file.toString(), "Cannot determine existence of read-dir");
            }

            if (!status) {
                throw new NoSuchFileException(file.toString(), file.toString(), "Non-existent directory");
            } else if (!Files.isDirectory(file, options)) {
                throw new NotDirectoryException(file.toString());
            } else if (!Files.isReadable(file)) {
                throw new AccessDeniedException(file.toString(), file.toString(), "Not readable");
            }

            SftpEventListener listener = getSftpEventListenerProxy();
            listener.readingEntries(session, handle, dh);

            if (dh.isSendDot() || dh.isSendDotDot() || dh.hasNext()) {
                // There is at least one file in the directory or we need to send the "..".
                // Send only a few files at a time to not create packets of a too
                // large size or have a timeout to occur.

                reply = prepareReply(buffer);
                reply.putByte((byte) SftpConstants.SSH_FXP_NAME);
                reply.putInt(id);

                int lenPos = reply.wpos();
                reply.putInt(0);

                int maxDataSize = SftpModuleProperties.MAX_READDIR_DATA_SIZE.getRequired(session);
                int count = doReadDir(id, handle, dh, reply, maxDataSize, IoUtils.getLinkOptions(false));
                BufferUtils.updateLengthPlaceholder(reply, lenPos, count);
                if ((!dh.isSendDot()) && (!dh.isSendDotDot()) && (!dh.hasNext())) {
                    dh.markDone();
                }

                Boolean indicator = SftpHelper.indicateEndOfNamesList(reply, getVersion(), session, dh.isDone());
                if (debugEnabled) {
                    log.debug("doReadDir({})({})[{}] - seding {} entries - eol={}", session, handle, h, count, indicator);
                }
            } else {
                // empty directory
                dh.markDone();
                sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_EOF, "Empty directory");
                return;
            }

            Objects.requireNonNull(reply, "No reply buffer created");
        } catch (IOException | RuntimeException | Error e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_READDIR, handle);
            return;
        }

        send(reply);
    }

    @Override
    protected String doOpenDir(int id, String path, Path p, LinkOption... options) throws IOException {
        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw signalOpenFailure(id, path, p, true,
                    new AccessDeniedException(p.toString(), p.toString(), "Cannot determine open-dir existence"));
        }

        if (!status) {
            throw signalOpenFailure(id, path, p, true,
                    new NoSuchFileException(path, path, "Referenced target directory N/A"));
        } else if (!Files.isDirectory(p, options)) {
            throw signalOpenFailure(id, path, p, true, new NotDirectoryException(path));
        } else if (!Files.isReadable(p)) {
            throw signalOpenFailure(id, path, p, true,
                    new AccessDeniedException(p.toString(), p.toString(), "Not readable"));
        } else {
            String handle;
            try {
                synchronized (handles) {
                    handle = generateFileHandle(p);
                    DirectoryHandle dirHandle = new DirectoryHandle(this, p, handle);
                    handles.put(handle, dirHandle);
                }
            } catch (IOException e) {
                throw signalOpenFailure(id, path, p, true, e);
            }

            return handle;
        }
    }

    @Override
    protected void doFSetStat(int id, String handle, Map<String, ?> attrs) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doFsetStat({})[id={}] SSH_FXP_FSETSTAT (handle={}[{}], attrs={})",
                    getServerSession(), id, handle, h, attrs);
        }

        Handle fileHandle = validateHandle(handle, h, Handle.class);
        Path path = fileHandle.getFile();
        boolean followLinks = resolvePathResolutionFollowLinks(
                SftpConstants.SSH_FXP_FSETSTAT, "", path);
        doSetAttributes(fileHandle.getFile(), attrs, followLinks);
    }

    @Override
    protected Map<String, Object> doFStat(int id, String handle, int flags) throws IOException {
        Handle h = handles.get(handle);
        if (log.isDebugEnabled()) {
            log.debug("doFStat({})[id={}] SSH_FXP_FSTAT (handle={}[{}], flags=0x{})",
                    getServerSession(), id, handle, h, Integer.toHexString(flags));
        }

        Handle fileHandle = validateHandle(handle, h, Handle.class);
        return resolveFileAttributes(fileHandle.getFile(), flags, IoUtils.getLinkOptions(true));
    }

    @Override
    protected void doWrite(
            int id, String handle, long offset, int length, byte[] data, int doff, int remaining)
            throws IOException {
        Handle h = handles.get(handle);
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
            throw new IllegalStateException(
                    "Not enough buffer data for writing to " + fh
                                            + ": required=" + length + ", available=" + remaining);
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.writing(session, handle, fh, offset, data, doff, length);
        try {
            if (fh.isOpenAppend()) {
                fh.append(data, doff, length);
            } else {
                fh.write(data, doff, length, offset);
            }
        } catch (IOException | RuntimeException | Error e) {
            listener.written(session, handle, fh, offset, data, doff, length, e);
            throw e;
        }
        listener.written(session, handle, fh, offset, data, doff, length, null);
    }

    @Override
    protected int doRead(
            int id, String handle, long offset, int length, byte[] data, int doff)
            throws IOException {
        Handle h = handles.get(handle);
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
            readLen = fh.read(data, doff, length, offset);
        } catch (IOException | RuntimeException | Error e) {
            listener.read(session, handle, fh, offset, data, doff, length, -1, e);
            throw e;
        }
        listener.read(session, handle, fh, offset, data, doff, length, readLen, null);
        return readLen;
    }

    @Override
    protected void doClose(int id, String handle) throws IOException {
        Handle h = handles.remove(handle);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doClose({})[id={}] SSH_FXP_CLOSE (handle={}[{}])", session, id, handle, h);
        }

        Handle nodeHandle = validateHandle(handle, h, Handle.class);
        SftpEventListener listener = getSftpEventListenerProxy();
        try {
            listener.closing(session, handle, nodeHandle);
            nodeHandle.close();
            listener.closed(session, handle, nodeHandle, null);
        } catch (IOException | RuntimeException | Error e) {
            listener.closed(session, handle, nodeHandle, e);
            throw e;
        } finally {
            nodeHandle.clearAttributes();
        }
    }

    @Override
    protected String doOpen(
            int id, String path, int pflags, int access, Map<String, Object> attrs)
            throws IOException {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doOpen({})[id={}] SSH_FXP_OPEN (path={}, access=0x{}, pflags=0x{}, attrs={})",
                    session, id, path, Integer.toHexString(access), Integer.toHexString(pflags), attrs);
        }

        Path file = resolveFile(path);
        int curHandleCount = handles.size();
        int maxHandleCount = SftpModuleProperties.MAX_OPEN_HANDLES_PER_SESSION.getRequired(session);
        if (curHandleCount > maxHandleCount) {
            throw signalOpenFailure(id, path, file, false,
                    new SftpException(
                            SftpConstants.SSH_FX_NO_SPACE_ON_FILESYSTEM,
                            "Too many open handles: current=" + curHandleCount + ", max.=" + maxHandleCount));
        }

        String handle;
        try {
            synchronized (handles) {
                handle = generateFileHandle(file);
                FileHandle fileHandle = new FileHandle(this, file, handle, pflags, access, attrs);
                handles.put(handle, fileHandle);
            }
        } catch (IOException e) {
            throw signalOpenFailure(id, path, file, false, e);
        }

        return handle;
    }

    // we stringify our handles and treat them as such on decoding as well as it is easier to use as a map key
    // NOTE: assume handles map is locked
    protected String generateFileHandle(Path file) throws IOException {
        // use several rounds in case the file handle size is relatively small so we might get conflicts
        ServerSession session = getServerSession();
        boolean traceEnabled = log.isTraceEnabled();
        for (int index = 0; index < maxFileHandleRounds; index++) {
            randomizer.fill(workBuf, 0, fileHandleSize);
            String handle = BufferUtils.toHex(
                    workBuf, 0, fileHandleSize, BufferUtils.EMPTY_HEX_SEPARATOR);

            if (handles.containsKey(handle)) {
                if (traceEnabled) {
                    log.trace("generateFileHandle({})[{}] handle={} in use at round {}",
                            session, file, handle, index);
                }
                continue;
            }

            if (traceEnabled) {
                log.trace("generateFileHandle({})[{}] {}", session, file, handle);
            }
            return handle;
        }

        throw new StreamCorruptedException("Failed to generate a unique file handle for " + file);
    }

    @Override
    protected void doInit(Buffer buffer, int id) throws IOException {
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doInit({})[id={}] SSH_FXP_INIT (version={})", session, id, id);
        }

        Map.Entry<Integer, String> negotiated = checkVersionCompatibility(
                buffer, id, id, SftpConstants.SSH_FX_OP_UNSUPPORTED);
        if (negotiated == null) { // i.e. validation failed
            return;
        }

        version = negotiated.getKey();
        while (buffer.available() > 0) {
            String name = buffer.getString();
            byte[] data = buffer.getBytes();
            extensions.put(name, data);
        }

        buffer = prepareReply(buffer);

        buffer.putByte((byte) SftpConstants.SSH_FXP_VERSION);
        buffer.putInt(version);
        appendExtensions(buffer, negotiated.getValue());

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.initialized(session, version);

        send(buffer);
    }

    @Override
    protected Buffer prepareReply(Buffer buffer) {
        buffer.clear();
        buffer.putInt(0); // reserve space for actual packet length
        return buffer;
    }

    @Override
    protected void send(Buffer buffer) throws IOException {
        BufferUtils.updateLengthPlaceholder(buffer, 0);
        out.writeBuffer(buffer);
    }

    @Override
    public void destroy(ChannelSession channel) {
        if (closed.getAndSet(true)) {
            return; // ignore if already closed
        }

        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("destroy({}) - mark as closed", session);
        }

        try {
            SftpEventListener listener = getSftpEventListenerProxy();
            listener.destroying(session);
        } catch (Exception e) {
            warn("destroy({}) Failed ({}) to announce destruction event: {}",
                    session, e.getClass().getSimpleName(), e.getMessage(), e);
        }

        // if thread has not completed, cancel it
        if ((pendingFuture != null) && (!pendingFuture.isDone())) {
            boolean result = pendingFuture.cancel(true);
            // TODO consider waiting some reasonable (?) amount of time for cancellation
            if (debugEnabled) {
                log.debug("destroy(" + session + ") - cancel pending future=" + result);
            }
        }

        pendingFuture = null;

        CloseableExecutorService executors = getExecutorService();
        if ((executors != null) && (!executors.isShutdown())) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (debugEnabled) {
                log.debug("destroy(" + session + ") - shutdown executor service - runners count=" + runners.size());
            }
        }
        this.executorService = null;

        try {
            fileSystem.close();
        } catch (UnsupportedOperationException e) {
            if (debugEnabled) {
                log.debug("destroy(" + session + ") closing the file system is not supported");
            }
        } catch (IOException e) {
            if (debugEnabled) {
                log.warn("destroy(" + session + ")"
                         + " failed (" + e.getClass().getSimpleName() + ")"
                         + " to close file system: " + e.getMessage(),
                        e);
            }
        }
    }

    protected void closeAllHandles() {
        boolean debugEnabled = log.isDebugEnabled();
        ServerSession session = getServerSession();
        SftpEventListener listener = getSftpEventListenerProxy();
        for (Map.Entry<String, Handle> fe : handles.entrySet()) {
            String id = fe.getKey();
            Handle handle = fe.getValue();
            try {
                if (debugEnabled) {
                    log.debug("closeAllHandles({}) exiting pending handle {} [{}]", session, id, handle);
                }

                listener.exiting(session, handle);
            } catch (IOException | RuntimeException e) {
                log.warn("closeAllHandles({}) failed ({}) to inform listener of exit for handle={}[{}]: {}",
                        session, e.getClass().getSimpleName(), id, handle, e.getMessage());
            }

            try {
                handle.close();
                if (debugEnabled) {
                    log.debug("closeAllHandles({}) closed pending handle {} [{}]", session, id, handle);
                }
            } catch (IOException | RuntimeException e) {
                log.warn("closeAllHandles({}) failed ({}) to close handle={}[{}]: {}",
                        session, e.getClass().getSimpleName(), id, handle, e.getMessage());
            } finally {
                handle.clearAttributes();
            }
        }
        handles.clear();
    }
}
