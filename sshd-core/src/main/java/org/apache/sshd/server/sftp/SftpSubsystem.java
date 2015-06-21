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
package org.apache.sshd.server.sftp;

import static org.apache.sshd.common.sftp.SftpConstants.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
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
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.buffer.Buffer;
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

    /**
     * Force the use of a given sftp version
     */
    public static final String SFTP_VERSION = "sftp-version";

    public static final int LOWER_SFTP_IMPL = SFTP_V3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = SFTP_V6; //  .. up to
    public static final String ALL_SFTP_IMPL;
    public static final int  MAX_PACKET_LENGTH = 1024 * 16;

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

    private ExitCallback callback;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private Environment env;
    private ServerSession session;
    private boolean closed = false;
	private ExecutorService executors;
	private boolean shutdownExecutor;
	private Future<?> pendingFuture;

    private FileSystem fileSystem = FileSystems.getDefault();
    private Path defaultDir = fileSystem.getPath(System.getProperty("user.dir"));

    private int version;
    private final Map<String, byte[]> extensions = new HashMap<>();
    private final Map<String, Handle> handles = new HashMap<>();

    private final UnsupportedAttributePolicy unsupportedAttributePolicy;

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

    protected static class DirectoryHandle extends Handle implements Iterator<Path> {
        private boolean done;
        // the directory should be read once at "open directory"
        private DirectoryStream<Path> ds;
        private Iterator<Path> fileList;

        public DirectoryHandle(Path file) throws IOException {
            super(file);
            ds = Files.newDirectoryStream(file);
            fileList = ds.iterator();
        }

        public boolean isDone() {
            return done;
        }

        public void setDone(boolean done) {
            this.done = done;
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

        public void clearFileList() {
            // allow the garbage collector to do the job
            fileList = null;
        }

        @Override
        public void close() throws IOException {
            ds.close();
        }
    }

    protected class FileHandle extends Handle {
        private final FileChannel channel;
        private long pos;
        private final List<FileLock> locks = new ArrayList<>();

        public FileHandle(Path file, int flags, int access, Map<String, Object> attrs) throws IOException {
            super(file);
            Set<OpenOption> options = new HashSet<>();
            if ((access & ACE4_READ_DATA) != 0 || (access & ACE4_READ_ATTRIBUTES) != 0) {
                options.add(StandardOpenOption.READ);
            }
            if ((access & ACE4_WRITE_DATA) != 0 || (access & ACE4_WRITE_ATTRIBUTES) != 0) {
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

    public final UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return unsupportedAttributePolicy;
    }

    @Override
    public void setSession(ServerSession session) {
        this.session = session;
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
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("process(length={}, type={}, id={})",
                      new Object[] { Integer.valueOf(length), Integer.valueOf(type), Integer.valueOf(id) });
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
                sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command " + type + " is unsupported or not implemented");
        }
    }

    protected void doExtended(Buffer buffer, int id) throws IOException {
        String extension = buffer.getString();
        switch (extension) {
        case "text-seek":
            doTextSeek(buffer, id);
            break;
        case "version-select":
            doVersionSelect(buffer, id);
            break;
        default:
            log.info("Received unsupported SSH_FXP_EXTENDED({})", extension);
            sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_EXTENDED(" + extension + ") is unsupported or not implemented");
            break;
        }
    }

    protected void doTextSeek(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long line = buffer.getLong();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_EXTENDED(text-seek) (handle={}, line={})", handle, Long.valueOf(line));
        }

        // TODO : implement text-seek
        sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_EXTENDED(text-seek) is unsupported or not implemented");
    }

    protected void doVersionSelect(Buffer buffer, int id) throws IOException {
        String ver = buffer.getString();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_EXTENDED(version-select) (version={})", Integer.valueOf(version));
        }
        
        if (GenericUtils.length(ver) == 1) {
            char digit = ver.charAt(0);
            if ((digit >= '0') && (digit <= '9')) {
                int value = digit - '0';
                String all = checkVersionCompatibility(id, value, SSH_FX_FAILURE);
                if (GenericUtils.isEmpty(all)) {    // validation failed
                    return;
                }

                version = value;
                sendStatus(id, SSH_FX_OK, "");
                return;
            }
        }

        sendStatus(id, SSH_FX_FAILURE, "Unsupported version " + ver);
    }

    /**
     * Checks if a proposed version is within supported range. <B>Note:</B>
     * if the user forced a specific value via the {@link #SFTP_VERSION}
     * property, then it is used to validate the proposed value
     * @param id The SSH message ID to be used to send the failure message
     * if required
     * @param proposed The proposed version value
     * @param failureOpcode The failure opcode to send if validation fails
     * @return A {@link String} of comma separated values representing all
     * the supported version - {@code null} if validation failed and an
     * appropriate status message was sent
     * @throws IOException If failed to send the failure status message
     */
    protected String checkVersionCompatibility(int id, int proposed, int failureOpcode) throws IOException {
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
                      new Object[] { Integer.valueOf(id), Integer.valueOf(proposed), available });
        }

        if ((proposed < low) || (proposed > hig)) {
            sendStatus(id, failureOpcode, "Proposed version (" + proposed + ") not in supported range: " + available);
            return null;
        }

        return available;
    }

    protected void doBlock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        int mask = buffer.getInt();
        
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_BLOCK (handle={}, offset={}, length={}, mask=0x{})",
                      new Object[] { handle, Long.valueOf(offset), Long.valueOf(length), Integer.toHexString(mask) });
        }

        try {
            Handle p = handles.get(handle);
            if (!(p instanceof FileHandle)) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                return;
            }
            FileHandle fileHandle = (FileHandle) p;
            fileHandle.lock(offset, length, mask);
            sendStatus(id, SSH_FX_OK, "");
        } catch (IOException | OverlappingFileLockException e) {
            sendStatus(id, e);
        }
    }

    protected void doUnblock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_UNBLOCK (handle={}, offset={}, length={})",
                      new Object[] { handle, Long.valueOf(offset), Long.valueOf(length) });
        }

        try {
            Handle p = handles.get(handle);
            if (!(p instanceof FileHandle)) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                return;
            }
            FileHandle fileHandle = (FileHandle) p;
            boolean found = fileHandle.unlock(offset, length);
            sendStatus(id, found ? SSH_FX_OK : SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK, "");
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doLink(Buffer buffer, int id) throws IOException {
        String targetpath = buffer.getString();
        String linkpath = buffer.getString();
        boolean symLink = buffer.getBoolean();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_LINK (linkpath={}, targetpath={}, symlink={})",
                      new Object[] { linkpath, targetpath, Boolean.valueOf(symLink) });
        }

        try {
            Path link = resolveFile(linkpath);
            Path target = fileSystem.getPath(targetpath);
            if (symLink) {
                Files.createSymbolicLink(link, target);
            } else {
                Files.createLink(link, target);
            }
            sendStatus(id, SSH_FX_OK, "");
        } catch (UnsupportedOperationException e) {
            sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_SYMLINK is unsupported or not implemented");
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doSymLink(Buffer buffer, int id) throws IOException {
        String targetpath = buffer.getString();
        String linkpath = buffer.getString();
        log.debug("Received SSH_FXP_SYMLINK (linkpath={}, targetpath={})", linkpath, targetpath);
        try {
            Path link = resolveFile(linkpath);
            Path target = fileSystem.getPath(targetpath);
            Files.createSymbolicLink(link, target);
            sendStatus(id, SSH_FX_OK, "");
        } catch (UnsupportedOperationException e) {
            sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_SYMLINK is unsupported or not implemented");
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doReadLink(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        log.debug("Received SSH_FXP_READLINK (path={})", path);
        try {
            Path f = resolveFile(path);
            String l = Files.readSymbolicLink(f).toString();
            sendLink(id, l);
        } catch (UnsupportedOperationException e) {
            sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command SSH_FXP_READLINK is unsupported or not implemented");
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doRename(Buffer buffer, int id) throws IOException {
        String oldPath = buffer.getString();
        String newPath = buffer.getString();
        int flags = 0;
        if (version >= SFTP_V5) {
            flags = buffer.getInt();
        }
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_RENAME (oldPath={}, newPath={}, flags=0x{})",
                       new Object[] { oldPath, newPath, Integer.toHexString(flags) });
        }
        try {
            List<CopyOption> opts = new ArrayList<>();
            if ((flags & SSH_FXP_RENAME_ATOMIC) != 0) {
                opts.add(StandardCopyOption.ATOMIC_MOVE);
            }
            if ((flags & SSH_FXP_RENAME_OVERWRITE) != 0) {
                opts.add(StandardCopyOption.REPLACE_EXISTING);
            }
            Path o = resolveFile(oldPath);
            Path n = resolveFile(newPath);
            Files.move(o, n, opts.toArray(new CopyOption[opts.size()]));
            sendStatus(id, SSH_FX_OK, "");
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_STAT (path={}, flags={})", path, "0x" + Integer.toHexString(flags));
        }
        try {
            Path p = resolveFile(path);
            sendAttrs(id, p, flags, true);
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doRealPath(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        log.debug("Received SSH_FXP_REALPATH (path={})", path);
        path = GenericUtils.trimToEmpty(path);
        if (GenericUtils.isEmpty(path)) {
            path = ".";
        }

        try {
            if (version < SFTP_V6) {
                Path f = resolveFile(path);
                Path abs = f.toAbsolutePath();
                Path p = abs.normalize();
                Boolean status = IoUtils.checkFileExists(p, IoUtils.EMPTY_LINK_OPTIONS);
                if (status == null) {
                    p = handleUnknownRealPathStatus(path, abs, p);
                } else if (!status.booleanValue()) {
                    throw new FileNotFoundException(p.toString());
                }
                sendPath(id, p, Collections.<String, Object>emptyMap());
            } else {
                // Read control byte
                int control = 0;
                if (buffer.available() > 0) {
                    control = buffer.getByte();
                }
                List<String> paths = new ArrayList<>();
                while (buffer.available() > 0) {
                    paths.add(buffer.getString());
                }
                // Resolve path
                Path p = resolveFile(path);
                for (String p2 : paths) {
                    p = p.resolve(p2);
                }
                p = p.toAbsolutePath().normalize();

                Map<String, Object> attrs = Collections.emptyMap();
                if (control == SSH_FXP_REALPATH_STAT_IF) {
                    try {
                        attrs = getAttributes(p, false);
                    } catch (IOException e) {
                        // ignore
                    }
                } else if (control == SSH_FXP_REALPATH_STAT_ALWAYS) {
                    attrs = getAttributes(p, false);
                }
                sendPath(id, p, attrs);
            }
        } catch (IOException e) {
            sendStatus(id, e);
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
        log.debug("Received SSH_FXP_RMDIR (path={})", path);
        // attrs
        try {
            Path p = resolveFile(path);
            if (Files.isDirectory(p, IoUtils.getLinkOptions(false))) {
                Files.delete(p);
                sendStatus(id, SSH_FX_OK, "");
            } else {
                sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doMakeDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);

        log.debug("Received SSH_FXP_MKDIR (path={})", path);
        // attrs
        try {
            Path            p = resolveFile(path);
            LinkOption[]    options = IoUtils.getLinkOptions(false);
            Boolean         status = IoUtils.checkFileExists(p, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot make-directory existence for " + p);
            }
            if (status.booleanValue()) {
                if (Files.isDirectory(p, options)) {
                    sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, p.toString());
                } else {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
                }
            } else {
                Files.createDirectory(p);
                setAttributes(p, attrs);
                sendStatus(id, SSH_FX_OK, "");
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doRemove(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        log.debug("Received SSH_FXP_REMOVE (path={})", path);
        try {
            Path            p = resolveFile(path);
            LinkOption[]    options = IoUtils.getLinkOptions(false);
            Boolean         status = IoUtils.checkFileExists(p, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot determine existence of remove candidate: " + p);
            }
            if (!status.booleanValue()) {
                sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
            } else if (Files.isDirectory(p, options)) {
                sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
            } else {
                Files.delete(p);
                sendStatus(id, SSH_FX_OK, "");
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doReadDir(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        log.debug("Received SSH_FXP_READDIR (handle={})", handle);
        Handle p = handles.get(handle);
        try {
            if (!(p instanceof DirectoryHandle)) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                return;
            }
            
            if (((DirectoryHandle) p).isDone()) {
                sendStatus(id, SSH_FX_EOF, "", "");
                return;
            }

            Path            file = p.getFile();
            LinkOption[]    options = IoUtils.getLinkOptions(false);
            Boolean         status = IoUtils.checkFileExists(file, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot determine existence of read-dir for " + file);
            }

            if (!status.booleanValue()) {
                sendStatus(id, SSH_FX_NO_SUCH_FILE, file.toString());
            } else if (!Files.isDirectory(file, options)) {
                sendStatus(id, SSH_FX_NOT_A_DIRECTORY, file.toString());
            } else if (!Files.isReadable(file)) {
                sendStatus(id, SSH_FX_PERMISSION_DENIED, file.toString());
            } else {
                DirectoryHandle dh = (DirectoryHandle) p;
                if (dh.hasNext()) {
                    // There is at least one file in the directory.
                    // Send only a few files at a time to not create packets of a too
                    // large size or have a timeout to occur.
                    sendName(id, dh);
                    if (!dh.hasNext()) {
                        // if no more files to send
                        dh.setDone(true);
                        dh.clearFileList();
                    }
                } else {
                    // empty directory
                    dh.setDone(true);
                    dh.clearFileList();
                    sendStatus(id, SSH_FX_EOF, "", "");
                }
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doOpenDir(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        log.debug("Received SSH_FXP_OPENDIR (path={})", path);
        try {
            Path            p = resolveFile(path);
            LinkOption[]    options = IoUtils.getLinkOptions(false);
            Boolean         status = IoUtils.checkFileExists(p, options);
            if (status == null) {
                throw new AccessDeniedException("Cannot determine open-dir existence of " + p);
            }

            if (!status.booleanValue()) {
                sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
            } else if (!Files.isDirectory(p, options)) {
                sendStatus(id, SSH_FX_NOT_A_DIRECTORY, path);
            } else if (!Files.isReadable(p)) {
                sendStatus(id, SSH_FX_PERMISSION_DENIED, path);
            } else {
                String handle = UUID.randomUUID().toString();
                handles.put(handle, new DirectoryHandle(p));
                sendHandle(id, handle);
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doFSetStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        log.debug("Received SSH_FXP_FSETSTAT (handle={}, attrs={})", handle, attrs);
        try {
            Handle p = handles.get(handle);
            if (p == null) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
            } else {
                setAttributes(p.getFile(), attrs);
                sendStatus(id, SSH_FX_OK, "");
            }
        } catch (IOException | UnsupportedOperationException e) {
            sendStatus(id, e);
        }
    }

    protected void doSetStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        log.debug("Received SSH_FXP_SETSTAT (path={}, attrs={})", path, attrs);
        try {
            Path p = resolveFile(path);
            setAttributes(p, attrs);
            sendStatus(id, SSH_FX_OK, "");
        } catch (IOException | UnsupportedOperationException e) {
            sendStatus(id, e);
        }
    }

    protected void doFStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_FSTAT (handle={}, flags={})", handle, "0x" + Integer.toHexString(flags));
        }
        try {
            Handle p = handles.get(handle);
            if (p == null) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
            } else {
                sendAttrs(id, p.getFile(), flags, true);
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doLStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SSH_FILEXFER_ATTR_ALL;
        if (version >= SFTP_V4) {
            flags = buffer.getInt();
        }
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_LSTAT (path={}, flags={})", path, "0x" + Integer.toHexString(flags));
        }
        try {
            Path p = resolveFile(path);
            sendAttrs(id, p, flags, false);
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doWrite(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int length = buffer.getInt();
        if (length < 0) {
            throw new IllegalStateException();
        }
        if (buffer.available() < length) {
            throw new BufferUnderflowException();
        }
        byte[] data = buffer.array();
        int doff = buffer.rpos();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_WRITE (handle={}, offset={}, data=byte[{}])",
                      new Object[] { handle, Long.valueOf(offset), Integer.valueOf(length) });
        }
        try {
            Handle p = handles.get(handle);
            if (!(p instanceof FileHandle)) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
            } else {
                FileHandle fh = (FileHandle) p;
                fh.write(data, doff, length, offset);
                sendStatus(id, SSH_FX_OK, "");
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doRead(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int len = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_READ (handle={}, offset={}, length={})",
                      new Object[]{handle, Long.valueOf(offset), Integer.valueOf(len) });
        }
        try {
            Handle p = handles.get(handle);
            if (!(p instanceof FileHandle)) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
            } else {
                FileHandle fh = (FileHandle) p;
                Buffer buf = new ByteArrayBuffer(len + 9);
                buf.putByte((byte) SSH_FXP_DATA);
                buf.putInt(id);
                int pos = buf.wpos();
                buf.putInt(0);
                len = fh.read(buf.array(), buf.wpos(), len, offset);
                if (len >= 0) {
                    buf.wpos(pos);
                    buf.putInt(len);
                    buf.wpos(pos + 4 + len);
                    send(buf);
                } else {
                    sendStatus(id, SSH_FX_EOF, "");
                }
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doClose(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        log.debug("Received SSH_FXP_CLOSE (handle={})", handle);
        try {
            Handle h = handles.get(handle);
            if (h == null) {
                sendStatus(id, SSH_FX_INVALID_HANDLE, handle, "");
            } else {
                handles.remove(handle);
                h.close();
                sendStatus(id, SSH_FX_OK, "", "");
            }
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doOpen(Buffer buffer, int id) throws IOException {
        int maxHandleCount = FactoryManagerUtils.getIntProperty(session, MAX_OPEN_HANDLES_PER_SESSION, Integer.MAX_VALUE);
        if (handles.size() > maxHandleCount) {
            sendStatus(id, SSH_FX_FAILURE, "Too many open handles");
            return;
        }

        String path = buffer.getString();
        int access = 0;
        if (version >= SFTP_V5) {
            access = buffer.getInt();
        }
        int pflags = buffer.getInt();
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
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_OPEN (path={}, access=0x{}, pflags=0x{}, attrs={})",
                      new Object[]{path, Integer.toHexString(access), Integer.toHexString(pflags), attrs});
        }
        try {
            Path file = resolveFile(path);
            String handle = UUID.randomUUID().toString();
            handles.put(handle, new FileHandle(file, pflags, access, attrs));
            sendHandle(id, handle);
        } catch (IOException e) {
            sendStatus(id, e);
        }
    }

    protected void doInit(Buffer buffer, int id) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received SSH_FXP_INIT (version={})", Integer.valueOf(id));
        }

        String all = checkVersionCompatibility(id, id, SSH_FX_OP_UNSUPPORTED);
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

        // newline
        buffer.putString("newline");
        buffer.putString(System.getProperty("line.separator"));

        // versions
        buffer.putString("versions");
        buffer.putString(all);

        // supported
        buffer.putString("supported");
        buffer.putInt(5 * 4); // length of 5 integers
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

        // supported2
        buffer.putString("supported2");
        buffer.putInt(8 * 4); // length of 7 integers + 2 shorts
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
        // attrib-extension-count
        buffer.putInt(0);
        // extension-count
        buffer.putInt(0);

        /*
        buffer.putString("acl-supported");
        buffer.putInt(4);
        // capabilities
        buffer.putInt(0);
        */

        send(buffer);
    }

    protected void sendHandle(int id, String handle) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        send(buffer);
    }

    protected void sendAttrs(int id, Path file, int flags, boolean followLinks) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, file, flags, followLinks);
        send(buffer);
    }

    protected void sendPath(int id, Path f, Map<String, Object> attrs) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);

        String originalPath = f.toString();
        //in case we are running on Windows
        String unixPath = originalPath.replace(File.separatorChar, '/');
        //normalize the given path, use *nix style separator
        String normalizedPath = SelectorUtils.normalizePath(unixPath, "/");
        if (normalizedPath.length() == 0) {
            normalizedPath = "/";
        }
        buffer.putString(normalizedPath, StandardCharsets.UTF_8);

        if (version == SFTP_V3) {
            f = resolveFile(normalizedPath);
            buffer.putString(getLongName(f, attrs), StandardCharsets.UTF_8); // Format specified in the specs
            buffer.putInt(0);
        } else if (version >= SFTP_V4) {
            writeAttrs(buffer, attrs);
        } else {
            throw new IllegalStateException("sendPath(" + f + ") unsupported version: " + version);
        }
        send(buffer);
    }

    protected void sendLink(int id, String link) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);
        //normalize the given path, use *nix style separator
        buffer.putString(link);
        buffer.putString(link);
        buffer.putInt(0);
        send(buffer);
    }

    protected void sendName(int id, Iterator<Path> files) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        int wpos = buffer.wpos();
        buffer.putInt(0);
        int nb = 0;
        while (files.hasNext() && (buffer.wpos() < MAX_PACKET_LENGTH)) {
            Path    f = files.next();
            String  shortName = getShortName(f);
            buffer.putString(shortName, StandardCharsets.UTF_8);
            if (version == SFTP_V3) {
                String  longName = getLongName(f);
                buffer.putString(longName, StandardCharsets.UTF_8); // Format specified in the specs
                if (log.isTraceEnabled()) {
                    log.trace("sendName(id=" + id + ")[" + nb + "] - " + shortName + " [" + longName + "]");
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("sendName(id=" + id + ")[" + nb + "] - " + shortName);
                }
            }
            writeAttrs(buffer, f, SSH_FILEXFER_ATTR_ALL, false);
            nb++;
        }

        int oldpos = buffer.wpos();
        buffer.wpos(wpos);
        buffer.putInt(nb);
        buffer.wpos(oldpos);
        send(buffer);
    }

    private String getLongName(Path f) throws IOException {
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

    private String getLongName(Path f, Map<String, Object> attributes) throws IOException {
        String username;
        if (attributes.containsKey("owner")) {
            username = attributes.get("owner").toString();
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
            group = attributes.get("group").toString();
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

    protected void writeAttrs(Buffer buffer, Path file, int flags, boolean followLinks) throws IOException {
        LinkOption[]    options = IoUtils.getLinkOptions(followLinks);
        Boolean         status = IoUtils.checkFileExists(file, options);
        Map<String, Object> attributes;
        if (status == null) {
            attributes = handleUnknownStatusFileAttributes(file, flags, followLinks);
        } else if (!status.booleanValue()) {
            throw new FileNotFoundException(file.toString());
        } else {
            attributes = getAttributes(file, flags, followLinks);
        }

        writeAttrs(buffer, attributes);
    }

    protected void writeAttrs(Buffer buffer, Map<String, Object> attributes) throws IOException {
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
                buffer.putString(attributes.get("owner").toString(), StandardCharsets.UTF_8);
                buffer.putString(attributes.get("group").toString(), StandardCharsets.UTF_8);
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

    protected void setAttributes(Path file, Map<String, Object>  attributes) throws IOException {
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
            byte type = buffer.getByte();
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

    protected void sendStatus(int id, Exception e) throws IOException {
        int substatus;
        if (e instanceof NoSuchFileException || e instanceof FileNotFoundException) {
            substatus = SSH_FX_NO_SUCH_FILE;
        } else if (e instanceof FileAlreadyExistsException) {
            substatus = SSH_FX_FILE_ALREADY_EXISTS;
        } else if (e instanceof DirectoryNotEmptyException) {
            substatus = SSH_FX_DIR_NOT_EMPTY;
        } else if (e instanceof AccessDeniedException) {
            substatus = SSH_FX_PERMISSION_DENIED;
        } else if (e instanceof OverlappingFileLockException) {
            substatus = SSH_FX_LOCK_CONFLICT;
        } else {
            substatus = SSH_FX_FAILURE;
        }
        sendStatus(id, substatus, e.toString());
    }

    protected void sendStatus(int id, int substatus, String msg) throws IOException {
        sendStatus(id, substatus, msg != null ? msg : "", "");
    }

    protected void sendStatus(int id, int substatus, String msg, String lang) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Send SSH_FXP_STATUS (substatus={}, lang={}, msg={})",
                      new Object[] { Integer.valueOf(substatus), lang, msg });
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putByte((byte) SSH_FXP_STATUS);
        buffer.putInt(id);
        buffer.putInt(substatus);
        buffer.putString(msg);
        buffer.putString(lang);
        send(buffer);
    }

    protected void send(Buffer buffer) throws IOException {
        DataOutputStream dos = new DataOutputStream(out);
        dos.writeInt(buffer.available());
        dos.write(buffer.array(), buffer.rpos(), buffer.available());
        dos.flush();
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
                // Ignore
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
