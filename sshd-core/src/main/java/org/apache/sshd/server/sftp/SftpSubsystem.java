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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Calendar;
import java.util.Collection;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem implements Command, Runnable, SessionAware, FileSystemAware {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static class Factory implements NamedFactory<Command> {

        public static final String NAME = "sftp";

    	private final ExecutorService	executors;
    	private final boolean shutdownExecutor;

    	public Factory() {
    		this(null);
    	}

        /**
         * @param executorService The {@link ExecutorService} to be used by
         *                        the {@link SftpSubsystem} command when starting execution. If
         *                        {@code null} then a single-threaded ad-hoc service is used.
         *                        <B>Note:</B> the service will <U>not</U> be shutdown when the
         *                        subsystem is closed - unless it is the ad-hoc service, which will be
         *                        shutdown regardless
         * @see Factory(ExecutorService, boolean)}
         */
        public Factory(ExecutorService executorService) {
        	this(executorService, false);
        }

        /**
         * @param executorService The {@link ExecutorService} to be used by
         *                        the {@link SftpSubsystem} command when starting execution. If
         *                        {@code null} then a single-threaded ad-hoc service is used.
         * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
         *                        will be called when subsystem terminates - unless it is the ad-hoc
         *                        service, which will be shutdown regardless
         */
        public Factory(ExecutorService executorService, boolean shutdownOnExit) {
        	executors = executorService;
        	shutdownExecutor = shutdownOnExit;
        }

        public ExecutorService getExecutorService() {
        	return executors;
        }
        
        public boolean isShutdownOnExit() {
        	return shutdownExecutor;
        }

        public Command create() {
            return new SftpSubsystem(getExecutorService(), isShutdownOnExit());
        }

        public String getName() {
            return NAME;
        }
    }

    //
    // File attributes
    //
    enum Attribute {
        Size,               // long
        Uid,                // int
        Owner,              // String
        Gid,                // int
        Group,              // String
        IsDirectory,        // boolean
        IsRegularFile,      // boolean
        IsSymbolicLink,     // boolean
        Permissions,        // EnumSet<Permission>
        CreationTime,       // long
        LastModifiedTime,   // long
        LastAccessTime,     // long
        NLink               // int
    }

    //
    // File permissions
    //
    enum Permission {
        UserRead,
        UserWrite,
        UserExecute,
        GroupRead,
        GroupWrite,
        GroupExecute,
        OthersRead,
        OthersWrite,
        OthersExecute
    }

    public enum UnsupportedAttributePolicy {
        Ignore,
        Warn,
        ThrowException
    }

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final String MAX_OPEN_HANDLES_PER_SESSION = "max-open-handles-per-session";

    public static final int LOWER_SFTP_IMPL = 3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = 3; //  .. up to
    public static final String ALL_SFTP_IMPL = "3";
    public static final int  MAX_PACKET_LENGTH = 1024 * 16;

    public static final int SSH_FXP_INIT =             1;
    public static final int SSH_FXP_VERSION =          2;
    public static final int SSH_FXP_OPEN =             3;
    public static final int SSH_FXP_CLOSE =            4;
    public static final int SSH_FXP_READ =             5;
    public static final int SSH_FXP_WRITE =            6;
    public static final int SSH_FXP_LSTAT =            7;
    public static final int SSH_FXP_FSTAT =            8;
    public static final int SSH_FXP_SETSTAT =          9;
    public static final int SSH_FXP_FSETSTAT =        10;
    public static final int SSH_FXP_OPENDIR =         11;
    public static final int SSH_FXP_READDIR =         12;
    public static final int SSH_FXP_REMOVE =          13;
    public static final int SSH_FXP_MKDIR =           14;
    public static final int SSH_FXP_RMDIR =           15;
    public static final int SSH_FXP_REALPATH =        16;
    public static final int SSH_FXP_STAT =            17;
    public static final int SSH_FXP_RENAME =          18;
    public static final int SSH_FXP_READLINK =        19;
    public static final int SSH_FXP_SYMLINK =         20;
    public static final int SSH_FXP_STATUS =         101;
    public static final int SSH_FXP_HANDLE =         102;
    public static final int SSH_FXP_DATA =           103;
    public static final int SSH_FXP_NAME =           104;
    public static final int SSH_FXP_ATTRS =          105;
    public static final int SSH_FXP_EXTENDED =       200;
    public static final int SSH_FXP_EXTENDED_REPLY = 201;

    public static final int SSH_FX_OK =                0;
    public static final int SSH_FX_EOF =               1;
    public static final int SSH_FX_NO_SUCH_FILE =      2;
    public static final int SSH_FX_PERMISSION_DENIED = 3;
    public static final int SSH_FX_FAILURE =           4;
    public static final int SSH_FX_BAD_MESSAGE =       5;
    public static final int SSH_FX_NO_CONNECTION =     6;
    public static final int SSH_FX_CONNECTION_LOST =   7;
    public static final int SSH_FX_OP_UNSUPPORTED =    8;

    public static final int SSH_FX_FILE_ALREADY_EXISTS = 11; // Not in v3, but we need it

    public static final int SSH_FILEXFER_ATTR_SIZE =        0x00000001;
    public static final int SSH_FILEXFER_ATTR_UIDGID =      0x00000002;
    public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    public static final int SSH_FILEXFER_ATTR_ACMODTIME =   0x00000008; //v3 naming convention
    public static final int SSH_FILEXFER_ATTR_EXTENDED =    0x80000000;

    public static final int SSH_FXF_READ =   0x00000001;
    public static final int SSH_FXF_WRITE =  0x00000002;
    public static final int SSH_FXF_APPEND = 0x00000004;
    public static final int SSH_FXF_CREAT =  0x00000008;
    public static final int SSH_FXF_TRUNC =  0x00000010;
    public static final int SSH_FXF_EXCL =   0x00000020;

    public static final int S_IFMT =   0170000;  // bitmask for the file type bitfields
    public static final int S_IFSOCK = 0140000;  // socket
    public static final int S_IFLNK =  0120000;  // symbolic link
    public static final int S_IFREG =  0100000;  // regular file
    public static final int S_IFBLK =  0060000;  // block device
    public static final int S_IFDIR =  0040000;  // directory
    public static final int S_IFCHR =  0020000;  // character device
    public static final int S_IFIFO =  0010000;  // fifo
    public static final int S_ISUID =  0004000;  // set UID bit
    public static final int S_ISGID =  0002000;  // set GID bit
    public static final int S_ISVTX =  0001000;  // sticky bit
    public static final int S_IRUSR =  0000400;
    public static final int S_IWUSR =  0000200;
    public static final int S_IXUSR =  0000100;
    public static final int S_IRGRP =  0000040;
    public static final int S_IWGRP =  0000020;
    public static final int S_IXGRP =  0000010;
    public static final int S_IROTH =  0000004;
    public static final int S_IWOTH =  0000002;
    public static final int S_IXOTH =  0000001;


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
    private Map<String, Handle> handles = new HashMap<>();

    private UnsupportedAttributePolicy unsupportedAttributePolicy = UnsupportedAttributePolicy.Warn;

    protected static abstract class Handle implements java.io.Closeable {
        Path file;

        public Handle(Path file) {
            this.file = file;
        }

        public Path getFile() {
            return file;
        }

        public void close() throws IOException {
        }
    }

    protected static class DirectoryHandle extends Handle implements Iterator<Path> {
        boolean done;
        // the directory should be read once at "open directory"
        DirectoryStream<Path> ds;
        Iterator<Path> fileList = null;
        int fileIndex;

        public DirectoryHandle(Path file) throws IOException {
            super(file);
            ds = Files.newDirectoryStream(file);
            fileList = ds.iterator();
            fileIndex = 0;
        }

        public boolean isDone() {
            return done;
        }

        public void setDone(boolean done) {
            this.done = done;
        }

        public boolean hasNext() {
            return fileList.hasNext();
        }

        public Path next() {
            return fileList.next();
        }

        public void remove() {
            throw new UnsupportedOperationException();
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

    protected static class FileHandle extends Handle {
        SeekableByteChannel channel;

        public FileHandle(Path file, int flags) throws IOException {
            super(file);
            Set<OpenOption> options = new HashSet<>();
            if ((flags & SSH_FXF_READ) != 0) {
                options.add(StandardOpenOption.READ);
            }
            if ((flags & SSH_FXF_WRITE) != 0) {
                options.add(StandardOpenOption.WRITE);
            }
            if ((flags & SSH_FXF_APPEND) != 0) {
                options.add(StandardOpenOption.APPEND);
            }
            if ((flags & SSH_FXF_TRUNC) != 0) {
                options.add(StandardOpenOption.TRUNCATE_EXISTING);
            }
            channel = Files.newByteChannel(file, options);
        }

        public int read(byte[] data, long offset) throws IOException {
            channel.position(offset);
            return channel.read(ByteBuffer.wrap(data));
        }

        public void write(byte[] data, long offset) throws IOException {
            channel.position(offset);
            channel.write(ByteBuffer.wrap(data));
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    public SftpSubsystem() {
        this(null);
    }

    /**
     * @param executorService The {@link ExecutorService} to be used by
     *                        the {@link SftpSubsystem} command when starting execution. If
     *                        {@code null} then a single-threaded ad-hoc service is used.
     *                        <b>Note:</b> the service will <U>not</U> be shutdown when the
     *                        subsystem is closed - unless it is the ad-hoc service
     * @see #SftpSubsystem(ExecutorService, boolean)
     */
    public SftpSubsystem(ExecutorService executorService) {
        this(executorService, false);
    }

    /**
     * @param executorService The {@link ExecutorService} to be used by
     *                        the {@link SftpSubsystem} command when starting execution. If
     *                        {@code null} then a single-threaded ad-hoc service is used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when subsystem terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @see ThreadUtils#newSingleThreadExecutor(String)
     */
    public SftpSubsystem(ExecutorService executorService, boolean shutdownOnExit) {
        if ((executors = executorService) == null) {
            executors = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
            shutdownExecutor = true;    // we always close the ad-hoc executor service
        } else {
            shutdownExecutor = shutdownOnExit;
        }
    }

    public void setSession(ServerSession session) {
        this.session = session;
    }

    public void setFileSystem(FileSystem fileSystem) {
        this.fileSystem = fileSystem;
    }

    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    public void setInputStream(InputStream in) {
        this.in = in;
    }

    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    public void start(Environment env) throws IOException {
        this.env = env;
        try {
            pendingFuture = executors.submit(this);
        } catch (RuntimeException e) {    // e.g., RejectedExecutionException
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start command: " + e.getMessage(), e);
            throw new IOException(e);
        }
    }

    public void run() {
        DataInputStream dis = null;
        try {
            dis = new DataInputStream(in);
            while (true) {
                int length = dis.readInt();
                if (length < 5) {
                    throw new IllegalArgumentException();
                }
                Buffer buffer = new Buffer(length + 4);
                buffer.putInt(length);
                int nb = length;
                while (nb > 0) {
                    int l = dis.read(buffer.array(), buffer.wpos(), nb);
                    if (l < 0) {
                        throw new IllegalArgumentException();
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
        switch (type) {
            case SSH_FXP_INIT: {
                log.debug("Received SSH_FXP_INIT (version={})", id);
                // see https://filezilla-project.org/specs/draft-ietf-secsh-filexfer-02.txt - section 4 - Protocol Initialization
                if (length < 5) { // we don't care about extensions
                    throw new IllegalArgumentException("Incomplete SSH_FXP_INIT data: length=" + length);
                }
                version = id;
                if (version >= LOWER_SFTP_IMPL) {
                    version = Math.min(version, HIGHER_SFTP_IMPL);
                    buffer.clear();
                    buffer.putByte((byte) SSH_FXP_VERSION);
                    buffer.putInt(version);
                    send(buffer);
                } else {
                    // We only support version 3 (Version 1 and 2 are not common)
                    sendStatus(id, SSH_FX_OP_UNSUPPORTED, "SFTP server only support versions " + ALL_SFTP_IMPL);
                }

                break;
            }
            case SSH_FXP_OPEN: {
                if (session.getFactoryManager().getProperties() != null) {
                    String maxHandlesString = session.getFactoryManager().getProperties().get(MAX_OPEN_HANDLES_PER_SESSION);
                    if (maxHandlesString != null) {
                        int maxHandleCount = Integer.parseInt(maxHandlesString);
                        if (handles.size() > maxHandleCount) {
                            sendStatus(id, SSH_FX_FAILURE, "Too many open handles");
                            break;
                        }
                    }
                }

                String path = buffer.getString();
                int pflags = buffer.getInt();
                Map<Attribute, Object> attrs = readAttrs(buffer);
                log.debug("Received SSH_FXP_OPEN (path={}, pflags={}, attrs={})", new Object[] { path, pflags, attrs });
                try {
                    Path file = resolveFile(path);
                    if (Files.exists(file)) {
                        if ((pflags & SSH_FXF_READ) != 0 && !Files.isReadable(file)) {
                            sendStatus(id, SSH_FX_PERMISSION_DENIED, "Can not read " + path);
                            return;
                        }
                        if ((pflags & SSH_FXF_WRITE) != 0 && !Files.isWritable(file)) {
                            sendStatus(id, SSH_FX_PERMISSION_DENIED, "Can not write " + path);
                            return;
                        }
                        if (((pflags & SSH_FXF_CREAT) != 0) && ((pflags & SSH_FXF_EXCL) != 0)) {
                            sendStatus(id, SSH_FX_FAILURE, path);
                            return;
                        }
                    } else {
                        if (((pflags & SSH_FXF_CREAT) != 0)) {
                            Files.createFile(file);
                        } else {
                            sendStatus(id, SSH_FX_NO_SUCH_FILE, "No such file " + path);
                            return;
                        }
                    }
                    if (((pflags & SSH_FXF_CREAT) != 0)) {
                        setAttributes(file, attrs);
                    }
                    String handle = UUID.randomUUID().toString();
                    handles.put(handle, new FileHandle(file, pflags));
                    sendHandle(id, handle);
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage() == null ? "" : e.getMessage());
                }
                break;
            }
            case SSH_FXP_CLOSE: {
                String handle = buffer.getString();
                log.debug("Received SSH_FXP_CLOSE (handle={})", handle);
                try {
                    Handle h = handles.get(handle);
                    if (h == null) {
                        sendStatus(id, SSH_FX_FAILURE, handle, "");
                    } else {
                        handles.remove(handle);
                        h.close();
                        sendStatus(id, SSH_FX_OK, "", "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_READ: {
                String handle = buffer.getString();
                long offset = buffer.getLong();
                int len = buffer.getInt();
                log.debug("Received SSH_FXP_READ (handle={}, offset={}, length={})", new Object[] { handle, offset, len });
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof FileHandle)) {
                        sendStatus(id, SSH_FX_FAILURE, handle);
                    } else {
                        FileHandle fh = (FileHandle) p;
                        byte[] b = new byte[Math.min(len, Buffer.MAX_LEN)];
                        len = fh.read(b, offset);
                        if (len >= 0) {
                            Buffer buf = new Buffer(len + 5);
                            buf.putByte((byte) SSH_FXP_DATA);
                            buf.putInt(id);
                            buf.putBytes(b, 0, len);
                            send(buf);
                        } else {
                            sendStatus(id, SSH_FX_EOF, "");
                        }
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_WRITE: {
                String handle = buffer.getString();
                long offset = buffer.getLong();
                byte[] data = buffer.getBytes();
                log.debug("Received SSH_FXP_WRITE (handle={}, offset={}, data=byte[{}])", new Object[] { handle, offset, data.length });
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof FileHandle)) {
                        sendStatus(id, SSH_FX_FAILURE, handle);
                    } else {
                        FileHandle fh = (FileHandle) p;
                        fh.write(data, offset);
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_LSTAT: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_LSTAT (path={})", path);
                try {
                    Path p = resolveFile(path);
                    sendAttrs(id, p, false);
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_FSTAT: {
                String handle = buffer.getString();
                log.debug("Received SSH_FXP_FSTAT (handle={})", handle);
                try {
                    Handle p = handles.get(handle);
                    if (p == null) {
                        sendStatus(id, SSH_FX_FAILURE, handle);
                    } else {
                        sendAttrs(id, p.getFile(), true);
                    }
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_SETSTAT: {
                String path = buffer.getString();
                Map<Attribute, Object> attrs = readAttrs(buffer);
                log.debug("Received SSH_FXP_SETSTAT (path={}, attrs={})", path, attrs);
                try {
                    Path p = resolveFile(path);
                    setAttributes(p, attrs);
                    sendStatus(id, SSH_FX_OK, "");
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                } catch (UnsupportedOperationException e) {
                    sendStatus(id, SSH_FX_FAILURE, "");
                }
                break;
            }
            case SSH_FXP_FSETSTAT: {
                String handle = buffer.getString();
                Map<Attribute, Object> attrs = readAttrs(buffer);
                log.debug("Received SSH_FXP_FSETSTAT (handle={}, attrs={})", handle, attrs);
                try {
                    Handle p = handles.get(handle);
                    if (p == null) {
                        sendStatus(id, SSH_FX_FAILURE, handle);
                    } else {
                        setAttributes(p.getFile(), attrs);
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException | UnsupportedOperationException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_OPENDIR: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_OPENDIR (path={})", path);
                try {
                    Path p = resolveFile(path);
                    if (!Files.exists(p)) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
                    } else if (!Files.isDirectory(p)) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
                    } else if (!Files.isReadable(p)) {
                        sendStatus(id, SSH_FX_PERMISSION_DENIED, path);
                    } else {
                        String handle = UUID.randomUUID().toString();
                        handles.put(handle, new DirectoryHandle(p));
                        sendHandle(id, handle);
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_READDIR: {
                String handle = buffer.getString();
                log.debug("Received SSH_FXP_READDIR (handle={})", handle);
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof DirectoryHandle)) {
                        sendStatus(id, SSH_FX_FAILURE, handle);
                    } else if (((DirectoryHandle) p).isDone()) {
                        sendStatus(id, SSH_FX_EOF, "", "");
                    } else if (!Files.exists(p.getFile())) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.getFile().toString());
                    } else if (!Files.isDirectory(p.getFile())) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.getFile().toString());
                    } else if (!Files.isReadable(p.getFile())) {
                        sendStatus(id, SSH_FX_PERMISSION_DENIED, p.getFile().toString());
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
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_REMOVE: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_REMOVE (path={})", path);
                try {
                    Path p = resolveFile(path);
                    if (!Files.exists(p)) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
                    } else if (Files.isDirectory(p)) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
                    } else {
                        Files.delete(p);
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_MKDIR: {
                String path = buffer.getString();
                Map<Attribute, Object> attrs = readAttrs(buffer);

                log.debug("Received SSH_FXP_MKDIR (path={})", path);
                // attrs
                try {
                    Path p = resolveFile(path);
                    if (Files.exists(p)) {
                        if (Files.isDirectory(p)) {
                            sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, p.toString());
                        } else {
                            sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
                        }
                    } else {
                        Files.createDirectory(p);
                        setAttributes(p, attrs);
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (AccessDeniedException e) {
                    sendStatus(id, SSH_FX_PERMISSION_DENIED, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_RMDIR: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_RMDIR (path={})", path);
                // attrs
                try {
                    Path p = resolveFile(path);
                    if (Files.isDirectory(p)) {
                        Files.delete(p);
                        sendStatus(id, SSH_FX_OK, "");
                    } else {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.toString());
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_REALPATH: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_REALPATH (path={})", path);
                if (path.trim().length() == 0) {
                    path = ".";
                }
                try {
                    Path p = resolveFile(path).toAbsolutePath().normalize();
                    sendPath(id, p, false);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    e.printStackTrace();
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_STAT: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_STAT (path={})", path);
                try {
                    Path p = resolveFile(path);
                    sendAttrs(id, p, true);
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_RENAME: {
                String oldPath = buffer.getString();
                String newPath = buffer.getString();
                log.debug("Received SSH_FXP_RENAME (oldPath={}, newPath={})", oldPath, newPath);
                try {
                    Path o = resolveFile(oldPath);
                    Path n = resolveFile(newPath);
                    if (!Files.exists(o)) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, o.toString());
                    } else if (Files.exists(n)) {
                        sendStatus(id, SSH_FX_FAILURE, n.toString());
                    } else {
                        Files.move(o, n);
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_READLINK: {
                String path = buffer.getString();
                log.debug("Received SSH_FXP_READLINK (path={})", path);
                try {
                    Path f = resolveFile(path);
                    String l = Files.readSymbolicLink(f).toString();
                    sendLink(id, l);
                } catch (UnsupportedOperationException e) {
                    sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command " + type + " is unsupported or not implemented");
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_SYMLINK: {
                String linkpath = buffer.getString();
                String targetpath = buffer.getString();
                log.debug("Received SSH_FXP_SYMLINK (linkpath={}, targetpath={})", linkpath, targetpath);
                try {
                    Path link = resolveFile(linkpath);
                    Path target = fileSystem.getPath(targetpath);
                    Files.createSymbolicLink(link, target);
                    sendStatus(id, SSH_FX_OK, "");
                } catch (UnsupportedOperationException e) {
                    sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command " + type + " is unsupported or not implemented");
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            default: {
                log.error("Received: {}", type);
                sendStatus(id, SSH_FX_OP_UNSUPPORTED, "Command " + type + " is unsupported or not implemented");
                break;
            }
        }
    }

    protected void sendHandle(int id, String handle) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        send(buffer);
    }

    protected void sendAttrs(int id, Path file, boolean followLinks) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, file, followLinks);
        send(buffer);
    }

    protected void sendPath(int id, Path f) throws IOException {
        sendPath(id, f, true);
    }

    protected void sendPath(int id, Path f, boolean sendAttrs) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);
        //normalize the given path, use *nix style separator
        String normalizedPath = SelectorUtils.normalizePath(f.toString(), "/");
        if (normalizedPath.length() == 0) {
            normalizedPath = "/";
        }
        buffer.putString(normalizedPath);
        f = resolveFile(normalizedPath);
        if (f.getFileName() == null) {
            f = resolveFile(".");
        }
        buffer.putString(getLongName(f, sendAttrs)); // Format specified in the specs
        buffer.putInt(0);
        send(buffer);
    }

    protected void sendLink(int id, String link) throws IOException {
        Buffer buffer = new Buffer();
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
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        int wpos = buffer.wpos();
        buffer.putInt(0);
        int nb = 0;
        while (files.hasNext() && buffer.wpos() < MAX_PACKET_LENGTH) {
            Path f = files.next();
            buffer.putString(f.getFileName().toString());
            buffer.putString(getLongName(f)); // Format specified in the specs
            writeAttrs(buffer, f, false);
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
        Map<Attribute, Object> attributes;
        if (sendAttrs) {
            attributes = getAttributes(f, false);
        } else {
            attributes = new HashMap<>();
            attributes.put(Attribute.Owner, "owner");
            attributes.put(Attribute.Group, "group");
            attributes.put(Attribute.Size, (long) 0);
            attributes.put(Attribute.IsDirectory, false);
            attributes.put(Attribute.IsSymbolicLink, false);
            attributes.put(Attribute.IsRegularFile, false);
            attributes.put(Attribute.Permissions, EnumSet.noneOf(Permission.class));
            attributes.put(Attribute.LastModifiedTime, (long) 0);
        }
        String username = (String) attributes.get(Attribute.Owner);
        if (username.length() > 8) {
            username = username.substring(0, 8);
        } else {
            for (int i = username.length(); i < 8; i++) {
                username = username + " ";
            }
        }
        String group = (String) attributes.get(Attribute.Group);
        if (group.length() > 8) {
            group = group.substring(0, 8);
        } else {
            for (int i = group.length(); i < 8; i++) {
                group = group + " ";
            }
        }

        long length = (Long) attributes.get(Attribute.Size);
        String lengthString = String.format("%1$8s", length);

        boolean isDirectory = (Boolean) attributes.get(Attribute.IsDirectory);
        boolean isLink = (Boolean) attributes.get(Attribute.IsSymbolicLink);
        int perms = getPermissions(attributes);

        StringBuilder sb = new StringBuilder();
        sb.append(isDirectory ? "d" : isLink ? "l" : "-");
        sb.append((perms & S_IRUSR) != 0 ? "r" : "-");
        sb.append((perms & S_IWUSR) != 0 ? "w" : "-");
        sb.append((perms & S_IXUSR) != 0 ? "x" : "-");
        sb.append((perms & S_IRGRP) != 0 ? "r" : "-");
        sb.append((perms & S_IWGRP) != 0 ? "w" : "-");
        sb.append((perms & S_IXGRP) != 0 ? "x" : "-");
        sb.append((perms & S_IROTH) != 0 ? "r" : "-");
        sb.append((perms & S_IWOTH) != 0 ? "w" : "-");
        sb.append((perms & S_IXOTH) != 0 ? "x" : "-");
        sb.append("  ");
        sb.append(attributes.containsKey(Attribute.NLink)
                ? attributes.get(Attribute.NLink) : "1");
        sb.append(" ");
        sb.append(username);
        sb.append(" ");
        sb.append(group);
        sb.append(" ");
        sb.append(lengthString);
        sb.append(" ");
        sb.append(getUnixDate((Long) attributes.get(Attribute.LastModifiedTime)));
        sb.append(" ");
        sb.append(f.getFileName().toString());

        return sb.toString();
    }

    protected Map<Attribute, Object> getPermissions(int perms) {
        Map<Attribute, Object> attrs = new HashMap<>();
        if ((perms & S_IFMT) == S_IFREG) {
            attrs.put(Attribute.IsRegularFile, Boolean.TRUE);
        }
        if ((perms & S_IFMT) == S_IFDIR) {
            attrs.put(Attribute.IsDirectory, Boolean.TRUE);
        }
        if ((perms & S_IFMT) == S_IFLNK) {
            attrs.put(Attribute.IsSymbolicLink, Boolean.TRUE);
        }
        EnumSet<Permission> p = EnumSet.noneOf(Permission.class);
        if ((perms & S_IRUSR) != 0) {
            p.add(Permission.UserRead);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(Permission.UserWrite);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(Permission.UserExecute);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(Permission.GroupRead);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(Permission.GroupWrite);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(Permission.GroupExecute);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(Permission.OthersRead);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(Permission.OthersWrite);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(Permission.OthersExecute);
        }
        attrs.put(Attribute.Permissions, p);
        return attrs;
    }

    protected int getPermissions(Map<Attribute, Object> attributes) {
        boolean isReg = (Boolean) attributes.get(Attribute.IsRegularFile);
        boolean isDir = (Boolean) attributes.get(Attribute.IsDirectory);
        boolean isLnk = (Boolean) attributes.get(Attribute.IsSymbolicLink);
        int pf = 0;
        EnumSet<Permission> perms = (EnumSet<Permission>) attributes.get(Attribute.Permissions);
        for (Permission p : perms) {
            switch (p) {
                case UserRead:      pf |= S_IRUSR; break;
                case UserWrite:     pf |= S_IWUSR; break;
                case UserExecute:   pf |= S_IXUSR; break;
                case GroupRead:     pf |= S_IRGRP; break;
                case GroupWrite:    pf |= S_IWGRP; break;
                case GroupExecute:  pf |= S_IXGRP; break;
                case OthersRead:    pf |= S_IROTH; break;
                case OthersWrite:   pf |= S_IWOTH; break;
                case OthersExecute: pf |= S_IXOTH; break;
            }
        }
        pf |= isReg ? S_IFREG : 0;
        pf |= isDir ? S_IFDIR : 0;
        pf |= isLnk ? S_IFLNK : 0;
        return pf;
    }

    protected void writeAttrs(Buffer buffer, Path file, boolean followLinks) throws IOException {
        if (!Files.exists(file)) {
            throw new FileNotFoundException(file.toString());
        }
        Map<Attribute, Object> attributes = getAttributes(file, followLinks);
        boolean isReg = getBool((Boolean) attributes.get(Attribute.IsRegularFile));
        boolean isDir = getBool((Boolean) attributes.get(Attribute.IsDirectory));
        boolean isLnk = getBool((Boolean) attributes.get(Attribute.IsSymbolicLink));
        int flags = 0;
        if ((isReg || isLnk) && attributes.containsKey(Attribute.Size)) {
            flags |= SSH_FILEXFER_ATTR_SIZE;
        }
        if (attributes.containsKey(Attribute.Uid) && attributes.containsKey(Attribute.Gid)) {
            flags |= SSH_FILEXFER_ATTR_UIDGID;
        }
        if (attributes.containsKey(Attribute.Permissions)) {
            flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if (attributes.containsKey(Attribute.LastAccessTime) && attributes.containsKey(Attribute.LastModifiedTime)) {
            flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        }
        buffer.putInt(flags);
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong((Long) attributes.get(Attribute.Size));
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            buffer.putInt((Integer) attributes.get(Attribute.Uid));
            buffer.putInt((Integer) attributes.get(Attribute.Gid));
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            buffer.putInt(getPermissions(attributes));
        }
        if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            buffer.putInt(((Long) attributes.get(Attribute.LastAccessTime)) / 1000);
            buffer.putInt(((Long) attributes.get(Attribute.LastModifiedTime)) / 1000);
        }
    }

    protected boolean getBool(Boolean bool) {
        return bool != null && bool;
    }

    protected Map<Attribute, Object> getAttributes(Path file, boolean followLinks) throws IOException {
        String[] attrs = new String[] { "unix:*", "posix:*", "*" };
        Map<String, Object> a = null;
        for (String attr : attrs) {
            try {
                a = Files.readAttributes(
                        file, attr,
                        followLinks ? new LinkOption[0] : new LinkOption[]{LinkOption.NOFOLLOW_LINKS});
                break;
            } catch (UnsupportedOperationException e) {
                // Ignore
            }
        }
        if (a == null) {
            throw new IllegalStateException();
        }
        Map<Attribute, Object> map = new HashMap<>();
        map.put(Attribute.Size, a.get("size"));
        if (a.containsKey("uid")) {
            map.put(Attribute.Uid, a.get("uid"));
        }
        if (a.containsKey("owner")) {
            map.put(Attribute.Owner, ((UserPrincipal) a.get("owner")).getName());
        } else {
            map.put(Attribute.Owner, session.getUsername());
        }
        if (a.containsKey("gid")) {
            map.put(Attribute.Gid, a.get("gid"));
        }
        if (a.containsKey("group")) {
            map.put(Attribute.Group, ((GroupPrincipal) a.get("group")).getName());
        } else {
            map.put(Attribute.Group, session.getUsername());
        }
        if (a.containsKey("nlink")) {
            map.put(Attribute.NLink, a.get("nlink"));
        }
        map.put(Attribute.IsDirectory, a.get("isDirectory"));
        map.put(Attribute.IsRegularFile, a.get("isRegularFile"));
        map.put(Attribute.IsSymbolicLink, a.get("isSymbolicLink"));
        map.put(Attribute.CreationTime, ((FileTime) a.get("creationTime")).toMillis());
        map.put(Attribute.LastModifiedTime, ((FileTime) a.get("lastModifiedTime")).toMillis());
        map.put(Attribute.LastAccessTime, ((FileTime) a.get("lastAccessTime")).toMillis());
        if (a.containsKey("permissions")) {
            map.put(Attribute.Permissions, fromPerms((Set<PosixFilePermission>) a.get("permissions")));
        } else {
            EnumSet<Permission> p = EnumSet.noneOf(Permission.class);
            if (Files.isReadable(file)) {
                p.add(Permission.UserRead);
                p.add(Permission.GroupRead);
                p.add(Permission.OthersRead);
            }
            if (Files.isWritable(file)) {
                p.add(Permission.UserWrite);
                p.add(Permission.GroupWrite);
                p.add(Permission.OthersWrite);
            }
            if (Files.isExecutable(file)) {
                p.add(Permission.UserExecute);
                p.add(Permission.GroupExecute);
                p.add(Permission.OthersExecute);
            }
            map.put(Attribute.Permissions, p);
        }
        return map;
    }

    protected void setAttributes(Path file, Map<Attribute, Object>  attributes) throws IOException {
        Set<Attribute> unsupported = new HashSet<>();
        for (Attribute attribute : attributes.keySet()) {
            String name = null;
            Object value = attributes.get(attribute);
            switch (attribute) {
            case Size:             {
                long newSize = (Long) value;
                try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
                    channel.truncate(newSize);
                }
                continue;
            }
            case Uid:              name = "unix:uid"; break;
            case Gid:              name = "unix:gid"; break;
            case Owner:            name = "posix:owner"; value = toUser(file, (String) value); break;
            case Group:            name = "posix:group"; value = toGroup(file, (String) value); break;
            case Permissions:      name = "posix:permissions"; value = toPerms((EnumSet<Permission>) value); break;
            case CreationTime:     name = "basic:creationTime"; value = FileTime.fromMillis((Long) value); break;
            case LastModifiedTime: name = "basic:lastModifiedTime"; value = FileTime.fromMillis((Long) value); break;
            case LastAccessTime:   name = "basic:lastAccessTime"; value = FileTime.fromMillis((Long) value); break;
            }
            if (name != null && value != null) {
                try {
                    Files.setAttribute(file, name, value, LinkOption.NOFOLLOW_LINKS);
                } catch (UnsupportedOperationException e) {
                    unsupported.add(attribute);
                }
            }
        }
        handleUnsupportedAttributes(unsupported);
    }

    protected void handleUnsupportedAttributes(Collection<Attribute> attributes) {
        if (!attributes.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Attribute attr : attributes) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(attr.name());
            }
            switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("Unsupported attributes: " + sb.toString());
                break;
            case ThrowException:
                throw new UnsupportedOperationException("Unsupported attributes: " + sb.toString());
            }
        }
    }


    private EnumSet<Permission> fromPerms(Set<PosixFilePermission> perms) {
        EnumSet<Permission> p = EnumSet.noneOf(Permission.class);
        for (PosixFilePermission perm : perms) {
            switch (perm) {
            case OWNER_READ:     p.add(Permission.UserRead); break;
            case OWNER_WRITE:    p.add(Permission.UserWrite); break;
            case OWNER_EXECUTE:  p.add(Permission.UserExecute); break;
            case GROUP_READ:     p.add(Permission.GroupRead); break;
            case GROUP_WRITE:    p.add(Permission.GroupWrite); break;
            case GROUP_EXECUTE:  p.add(Permission.GroupExecute); break;
            case OTHERS_READ:    p.add(Permission.OthersRead); break;
            case OTHERS_WRITE:   p.add(Permission.OthersWrite); break;
            case OTHERS_EXECUTE: p.add(Permission.OthersExecute); break;
            }
        }
        return p;
    }

    private GroupPrincipal toGroup(Path file, String name) throws IOException {
        UserPrincipalLookupService lookupService = file.getFileSystem().getUserPrincipalLookupService();
        return lookupService.lookupPrincipalByGroupName(name);
    }

    private UserPrincipal toUser(Path file, String name) throws IOException {
        UserPrincipalLookupService lookupService = file.getFileSystem().getUserPrincipalLookupService();
        return lookupService.lookupPrincipalByName(name);
    }

    private Set<PosixFilePermission> toPerms(EnumSet<Permission> perms) {
        Set<PosixFilePermission> set = new HashSet<>();
        for (Permission p : perms) {
            switch (p) {
            case UserRead:      set.add(PosixFilePermission.OWNER_READ); break;
            case UserWrite:     set.add(PosixFilePermission.OWNER_WRITE); break;
            case UserExecute:   set.add(PosixFilePermission.OWNER_EXECUTE); break;
            case GroupRead:     set.add(PosixFilePermission.GROUP_READ); break;
            case GroupWrite:    set.add(PosixFilePermission.GROUP_WRITE); break;
            case GroupExecute:  set.add(PosixFilePermission.GROUP_EXECUTE); break;
            case OthersRead:    set.add(PosixFilePermission.OTHERS_READ); break;
            case OthersWrite:   set.add(PosixFilePermission.OTHERS_WRITE); break;
            case OthersExecute: set.add(PosixFilePermission.OTHERS_EXECUTE); break;
            }
        }
        return set;
    }

    protected Map<Attribute, Object> readAttrs(Buffer buffer) throws IOException {
        Map<Attribute, Object> attrs = new HashMap<>();
        int flags = buffer.getInt();
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            attrs.put(Attribute.Size, buffer.getLong());
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            attrs.put(Attribute.Uid, buffer.getInt());
            attrs.put(Attribute.Gid, buffer.getInt());
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            attrs.putAll(getPermissions(buffer.getInt()));
        }
        if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            attrs.put(Attribute.LastAccessTime, ((long) buffer.getInt()) * 1000);
            attrs.put(Attribute.LastModifiedTime, ((long) buffer.getInt()) * 1000);
        }
        return attrs;
    }

    protected void sendStatus(int id, int substatus, String msg) throws IOException {
        sendStatus(id, substatus, msg, "");
    }

    protected void sendStatus(int id, int substatus, String msg, String lang) throws IOException {
        log.debug("Send SSH_FXP_STATUS (substatus={}, msg={})", substatus, msg);
        Buffer buffer = new Buffer();
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

            if ((executors != null) && shutdownExecutor) {
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
        return defaultDir.resolve(path);
//    	return this.fileSystem.getPath(path);
    }

    private final static String[] MONTHS = { "Jan", "Feb", "Mar", "Apr", "May",
            "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /**
     * Get unix style date string.
     */
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

}
