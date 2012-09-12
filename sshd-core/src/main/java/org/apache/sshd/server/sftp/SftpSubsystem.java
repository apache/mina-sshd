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

import java.io.*;
import java.util.*;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.server.*;
import org.apache.sshd.server.FileSystemView;
import org.apache.sshd.server.SshFile;
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

        public Factory() {
        }

        public Command create() {
            return new SftpSubsystem();
        }

        public String getName() {
            return "sftp";
        }
    }

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final String MAX_OPEN_HANDLES_PER_SESSION = "max-open-handles-per-session";

    public static final int LOWER_SFTP_IMPL = 3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = 3; //  .. up to
    public static final String ALL_SFTP_IMPL = "3";
    public static final int  MAX_PACKET_LENGTH = 1024 * 16;

    public static final int SSH_FXP_INIT = 1;
    public static final int SSH_FXP_VERSION = 2;
    public static final int SSH_FXP_OPEN = 3;
    public static final int SSH_FXP_CLOSE = 4;
    public static final int SSH_FXP_READ = 5;
    public static final int SSH_FXP_WRITE = 6;
    public static final int SSH_FXP_LSTAT = 7;
    public static final int SSH_FXP_FSTAT = 8;
    public static final int SSH_FXP_SETSTAT = 9;
    public static final int SSH_FXP_FSETSTAT = 10;
    public static final int SSH_FXP_OPENDIR = 11;
    public static final int SSH_FXP_READDIR = 12;
    public static final int SSH_FXP_REMOVE = 13;
    public static final int SSH_FXP_MKDIR = 14;
    public static final int SSH_FXP_RMDIR = 15;
    public static final int SSH_FXP_REALPATH = 16;
    public static final int SSH_FXP_STAT = 17;
    public static final int SSH_FXP_RENAME = 18;
    public static final int SSH_FXP_READLINK = 19;
    public static final int SSH_FXP_LINK = 21;
    public static final int SSH_FXP_BLOCK = 22;
    public static final int SSH_FXP_UNBLOCK = 23;

    public static final int SSH_FXP_STATUS = 101;
    public static final int SSH_FXP_HANDLE = 102;
    public static final int SSH_FXP_DATA = 103;
    public static final int SSH_FXP_NAME = 104;
    public static final int SSH_FXP_ATTRS = 105;

    public static final int SSH_FXP_EXTENDED = 200;
    public static final int SSH_FXP_EXTENDED_REPLY = 201;

    public static final int SSH_FX_OK = 0;
    public static final int SSH_FX_EOF = 1;
    public static final int SSH_FX_NO_SUCH_FILE = 2;
    public static final int SSH_FX_PERMISSION_DENIED = 3;
    public static final int SSH_FX_FAILURE = 4;
    public static final int SSH_FX_BAD_MESSAGE = 5;
    public static final int SSH_FX_NO_CONNECTION = 6;
    public static final int SSH_FX_CONNECTION_LOST = 7;
    public static final int SSH_FX_OP_UNSUPPORTED = 8;
    public static final int SSH_FX_INVALID_HANDLE = 9;
    public static final int SSH_FX_NO_SUCH_PATH = 10;
    public static final int SSH_FX_FILE_ALREADY_EXISTS = 11;
    public static final int SSH_FX_WRITE_PROTECT = 12;
    public static final int SSH_FX_NO_MEDIA = 13;
    public static final int SSH_FX_NO_SPACE_ON_FILESYSTEM = 14;
    public static final int SSH_FX_QUOTA_EXCEEDED = 15;
    public static final int SSH_FX_UNKNOWN_PRINCIPAL = 16;
    public static final int SSH_FX_LOCK_CONFLICT = 17;
    public static final int SSH_FX_DIR_NOT_EMPTY = 18;
    public static final int SSH_FX_NOT_A_DIRECTORY = 19;
    public static final int SSH_FX_INVALID_FILENAME = 20;
    public static final int SSH_FX_LINK_LOOP = 21;
    public static final int SSH_FX_CANNOT_DELETE = 22;
    public static final int SSH_FX_INVALID_PARAMETER = 23;
    public static final int SSH_FX_FILE_IS_A_DIRECTORY = 24;
    public static final int SSH_FX_BYTE_RANGE_LOCK_CONFLICT = 25;
    public static final int SSH_FX_BYTE_RANGE_LOCK_REFUSED = 26;
    public static final int SSH_FX_DELETE_PENDING = 27;
    public static final int SSH_FX_FILE_CORRUPT = 28;
    public static final int SSH_FX_OWNER_INVALID = 29;
    public static final int SSH_FX_GROUP_INVALID = 30;
    public static final int SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31;

    public static final int SSH_FILEXFER_ATTR_SIZE = 0x00000001;
    public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    public static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008; //v3 naming convention
    public static final int SSH_FILEXFER_ATTR_ACCESSTIME = 0x00000008;
    public static final int SSH_FILEXFER_ATTR_CREATETIME = 0x00000010;
    public static final int SSH_FILEXFER_ATTR_MODIFYTIME = 0x00000020;
    public static final int SSH_FILEXFER_ATTR_ACL = 0x00000040;
    public static final int SSH_FILEXFER_ATTR_OWNERGROUP = 0x00000080;
    public static final int SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 0x00000100;
    public static final int SSH_FILEXFER_ATTR_BITS = 0x00000200;
    public static final int SSH_FILEXFER_ATTR_ALLOCATION_SIZE = 0x00000400;
    public static final int SSH_FILEXFER_ATTR_TEXT_HINT = 0x00000800;
    public static final int SSH_FILEXFER_ATTR_MIME_TYPE = 0x00001000;
    public static final int SSH_FILEXFER_ATTR_LINK_COUNT = 0x00002000;
    public static final int SSH_FILEXFER_ATTR_UNTRANSLATED_NAME = 0x00004000;
    public static final int SSH_FILEXFER_ATTR_CTIME = 0x00008000;
    public static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

    public static final int SSH_FILEXFER_TYPE_REGULAR = 1;
    public static final int SSH_FILEXFER_TYPE_DIRECTORY = 2;
    public static final int SSH_FILEXFER_TYPE_SYMLINK = 3;
    public static final int SSH_FILEXFER_TYPE_SPECIAL = 4;
    public static final int SSH_FILEXFER_TYPE_UNKNOWN = 5;
    public static final int SSH_FILEXFER_TYPE_SOCKET = 6;
    public static final int SSH_FILEXFER_TYPE_CHAR_DEVICE = 7;
    public static final int SSH_FILEXFER_TYPE_BLOCK_DEVICE = 8;
    public static final int SSH_FILEXFER_TYPE_FIFO = 9;


    public static final int SSH_FXF_ACCESS_DISPOSITION = 0x00000007;
    public static final int SSH_FXF_CREATE_NEW = 0x00000000;
    public static final int SSH_FXF_CREATE_TRUNCATE = 0x00000001;
    public static final int SSH_FXF_OPEN_EXISTING = 0x00000002;
    public static final int SSH_FXF_OPEN_OR_CREATE = 0x00000003;
    public static final int SSH_FXF_TRUNCATE_EXISTING = 0x00000004;
    public static final int SSH_FXF_APPEND_DATA = 0x00000008;
    public static final int SSH_FXF_APPEND_DATA_ATOMIC = 0x00000010;
    public static final int SSH_FXF_TEXT_MODE = 0x00000020;
    public static final int SSH_FXF_BLOCK_READ = 0x00000040;
    public static final int SSH_FXF_BLOCK_WRITE = 0x00000080;
    public static final int SSH_FXF_BLOCK_DELETE = 0x00000100;
    public static final int SSH_FXF_BLOCK_ADVISORY = 0x00000200;
    public static final int SSH_FXF_NOFOLLOW = 0x00000400;
    public static final int SSH_FXF_DELETE_ON_CLOSE = 0x00000800;
    public static final int SSH_FXF_ACCESS_AUDIT_ALARM_INFO = 0x00001000;
    public static final int SSH_FXF_ACCESS_BACKUP = 0x00002000;
    public static final int SSH_FXF_BACKUP_STREAM = 0x00004000;
    public static final int SSH_FXF_OVERRIDE_OWNER = 0x00008000;

    public static final int SSH_FXF_READ = 0x00000001;
    public static final int SSH_FXF_WRITE = 0x00000002;
    public static final int SSH_FXF_APPEND = 0x00000004;
    public static final int SSH_FXF_CREAT = 0x00000008;
    public static final int SSH_FXF_TRUNC = 0x00000010;
    public static final int SSH_FXF_EXCL = 0x00000020;
    public static final int SSH_FXF_TEXT = 0x00000040;

    public static final int ACE4_READ_DATA = 0x00000001;
    public static final int ACE4_LIST_DIRECTORY = 0x00000001;
    public static final int ACE4_WRITE_DATA = 0x00000002;
    public static final int ACE4_ADD_FILE = 0x00000002;
    public static final int ACE4_APPEND_DATA = 0x00000004;
    public static final int ACE4_ADD_SUBDIRECTORY = 0x00000004;
    public static final int ACE4_READ_NAMED_ATTRS = 0x00000008;
    public static final int ACE4_WRITE_NAMED_ATTRS = 0x00000010;
    public static final int ACE4_EXECUTE = 0x00000020;
    public static final int ACE4_DELETE_CHILD = 0x00000040;
    public static final int ACE4_READ_ATTRIBUTES = 0x00000080;
    public static final int ACE4_WRITE_ATTRIBUTES = 0x00000100;
    public static final int ACE4_DELETE = 0x00010000;
    public static final int ACE4_READ_ACL = 0x00020000;
    public static final int ACE4_WRITE_ACL = 0x00040000;
    public static final int ACE4_WRITE_OWNER = 0x00080000;

    public static final int S_IRUSR = 0000400;
    public static final int S_IWUSR = 0000200;
    public static final int S_IXUSR = 0000100;
    public static final int S_IRGRP = 0000040;
    public static final int S_IWGRP = 0000020;
    public static final int S_IXGRP = 0000010;
    public static final int S_IROTH = 0000004;
    public static final int S_IWOTH = 0000002;
    public static final int S_IXOTH = 0000001;
    public static final int S_ISUID = 0004000;
    public static final int S_ISGID = 0002000;
    public static final int S_ISVTX = 0001000;


    private ExitCallback callback;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private Environment env;
    private ServerSession session;
    private boolean closed = false;

    private FileSystemView root;

    private int version;
    private Map<String, Handle> handles = new HashMap<String, Handle>();

    
    protected static int mapV4ToV3(int code) {
        switch (code) {
            case SSH_FX_INVALID_HANDLE:
                return SSH_FX_FAILURE;
            case SSH_FX_NO_SUCH_PATH:
                return SSH_FX_NO_SUCH_FILE;
            case SSH_FX_FILE_ALREADY_EXISTS:
                return SSH_FX_FAILURE;
            case SSH_FX_WRITE_PROTECT:
                return SSH_FX_PERMISSION_DENIED;
            case SSH_FX_NO_MEDIA:
                return SSH_FX_FAILURE;
            default:
                return code;
        }
    }
    
    protected static int mapV5ToV4(int code) {
        switch (code) {
            case SSH_FX_NO_SPACE_ON_FILESYSTEM:
                return SSH_FX_FAILURE;
            case SSH_FX_QUOTA_EXCEEDED:
                return SSH_FX_FAILURE;
            case SSH_FX_UNKNOWN_PRINCIPAL:
                return SSH_FX_FAILURE;
            case SSH_FX_LOCK_CONFLICT:
                return SSH_FX_FAILURE;
            default:
                return code;
        }
    }

    protected static int mapV6ToV5(int code) {
        switch (code) {
            case SSH_FX_DIR_NOT_EMPTY:
                return SSH_FX_FAILURE;
            case SSH_FX_NOT_A_DIRECTORY:
                return SSH_FX_NO_SUCH_FILE;
            case SSH_FX_INVALID_FILENAME:
                return SSH_FX_NO_SUCH_FILE;
            case SSH_FX_LINK_LOOP:
                return SSH_FX_FAILURE;
            case SSH_FX_CANNOT_DELETE:
                return SSH_FX_PERMISSION_DENIED;
            case SSH_FX_INVALID_PARAMETER:
                return SSH_FX_FAILURE;
            case SSH_FX_FILE_IS_A_DIRECTORY:
                return SSH_FX_NO_SUCH_FILE;
            case SSH_FX_BYTE_RANGE_LOCK_CONFLICT:
                return SSH_FX_FAILURE;
            case SSH_FX_BYTE_RANGE_LOCK_REFUSED:
                return SSH_FX_FAILURE;
            case SSH_FX_DELETE_PENDING:
                return SSH_FX_FAILURE;
            case SSH_FX_FILE_CORRUPT:
                return SSH_FX_FAILURE;
            case SSH_FX_OWNER_INVALID:
                return SSH_FX_PERMISSION_DENIED;
            case SSH_FX_GROUP_INVALID:
                return SSH_FX_PERMISSION_DENIED;
            case SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK:
                return SSH_FX_FAILURE;
            default:
                return code;
        }
    }
    
    protected static int mapToVersion(int code, int version) {
        int mappedCode = code;
        if (version < 6) {
            mappedCode = mapV6ToV5(mappedCode);
        }
        if (version < 5) {
            mappedCode = mapV5ToV4(mappedCode);
        }
        if (version < 4) {
            mappedCode = mapV4ToV3(mappedCode);
        }
        return mappedCode;
    }
    
    protected int mapToVersion(int code) {
        return mapToVersion(code, version);
    }

    protected static abstract class Handle {
        SshFile file;

        public Handle(SshFile file) {
            this.file = file;
        }

        public SshFile getFile() {
            return file;
        }

        public void close() throws IOException {
            file.handleClose();
        }

    }

    protected static class DirectoryHandle extends Handle implements Iterator<SshFile> {
        boolean done;
        // the directory should be read once at "open directory"
        List<SshFile> fileList = null;
        int fileIndex;

        public DirectoryHandle(SshFile file) {
            super(file);
            fileList = file.listSshFiles();
            fileIndex = 0;
        }

        public boolean isDone() {
            return done;
        }

        public void setDone(boolean done) {
            this.done = done;
        }

        public boolean hasNext() {
            return fileIndex < fileList.size();
        }

        public SshFile next() {
            SshFile f = fileList.get(fileIndex);
            fileIndex++;
            return f;
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }

        public void clearFileList() {
            // allow the garbage collector to do the job
            fileList = null;
        }
    }

    protected static class FileHandle extends Handle {
        int flags;
        OutputStream output;
        long outputPos;
        InputStream input;
        long inputPos;

        public FileHandle(SshFile sshFile, int flags) {
            super(sshFile);
            this.flags = flags;
        }

        public int getFlags() {
            return flags;
        }
        
        public int read(byte[] data, long offset) throws IOException {
            if (input != null && offset != inputPos) {
                IoUtils.closeQuietly(input);
                input = null;
            }
            if (input == null) {
                input = file.createInputStream(offset);
                inputPos = offset;
            }
            int read = input.read(data);
            inputPos += read;
            return read;
        }

        public void write(byte[] data, long offset) throws IOException {
            if (output != null && offset != outputPos) {
                IoUtils.closeQuietly(output);
                output = null;
            }
            if (output == null) {
                output = file.createOutputStream(offset);
            }
            output.write(data);
            outputPos += data.length;
        }

        @Override
        public void close() throws IOException {
            IoUtils.closeQuietly(output, input);
            output = null;
            input = null;
            super.close();
        }
    }

    public SftpSubsystem() {}

    public void setSession(ServerSession session) {
        this.session = session;
    }

    public void setFileSystemView(FileSystemView view) {
        this.root = view;
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
        new Thread(this).start();
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
            if (!closed && !(t instanceof EOFException)) { // Ignore han
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
            dis = null;

            callback.onExit(0);
        }
    }

    protected void process(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        switch (type) {
            case SSH_FXP_INIT: {
                if (length != 5) {
                    throw new IllegalArgumentException();
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

                if (version <= 4) {
                    String path = buffer.getString();
                    int pflags = buffer.getInt();
                    // attrs
                    try {
                        SshFile file = resolveFile(path);
                        if (file.doesExist()) {
                            if (((pflags & SSH_FXF_CREAT) != 0) && ((pflags & SSH_FXF_EXCL) != 0)) {
                                sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                                return;
                            }
                        } else {
                            if (((pflags & SSH_FXF_CREAT) != 0)) {
                                if (!file.isWritable()) {
                                    sendStatus(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                                    return;
                                }
                                file.create();
                            }
                        }
                        String acc = ((pflags & (SSH_FXF_READ | SSH_FXF_WRITE)) != 0 ? "r" : "") +
                                ((pflags & SSH_FXF_WRITE) != 0 ? "w" : "");
                        if ((pflags & SSH_FXF_TRUNC) != 0) {
                            file.truncate();
                        }
                        String handle = UUID.randomUUID().toString();
                        handles.put(handle, new FileHandle(file, pflags)); // handle flags conversion
                        sendHandle(id, handle);
                    } catch (IOException e) {
                        sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                    }
                } else {
                    String path = buffer.getString();
                    int acc = buffer.getInt();
                    int flags = buffer.getInt();
                    // attrs
                    try {
                        SshFile file = resolveFile(path);
                        switch (flags & SSH_FXF_ACCESS_DISPOSITION) {
                            case SSH_FXF_CREATE_NEW: {
                                if (file.doesExist()) {
                                    sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                                    return;
                                } else if (!file.isWritable()) {
                                    sendStatus(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                                }
                                file.create();
                                break;
                            }
                            case SSH_FXF_CREATE_TRUNCATE: {
                                if (file.doesExist()) {
                                    sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                                    return;
                                } else if (!file.isWritable()) {
                                    sendStatus(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                                }
                                file.truncate();
                                break;
                            }
                            case SSH_FXF_OPEN_EXISTING: {
                                if (!file.doesExist()) {
                                    if (!file.getParentFile().doesExist()) {
                                        sendStatus(id, SSH_FX_NO_SUCH_PATH, path);
                                    } else {
                                        sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
                                    }
                                    return;
                                }
                                break;
                            }
                            case SSH_FXF_OPEN_OR_CREATE: {
                                if (!file.doesExist()) {
                                    file.create();
                                }
                                break;
                            }
                            case SSH_FXF_TRUNCATE_EXISTING: {
                                if (!file.doesExist()) {
                                    if (!file.getParentFile().doesExist()) {
                                        sendStatus(id, SSH_FX_NO_SUCH_PATH, path);
                                    } else {
                                        sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
                                    }
                                    return;
                                }
                                file.truncate();
                                break;
                            }
                            default:
                                throw new IllegalArgumentException("Unsupported open mode: " + flags);
                        }
                        String handle = UUID.randomUUID().toString();
                        handles.put(handle, new FileHandle(file, flags));
                        sendHandle(id, handle);
                    } catch (IOException e) {
                        sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                    }
                }
                break;
            }
            case SSH_FXP_CLOSE: {
                String handle = buffer.getString();
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
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_READ: {
                String handle = buffer.getString();
                long offset = buffer.getLong();
                int len = buffer.getInt();
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof FileHandle)) {
                        sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                    } else {
                        FileHandle fh = (FileHandle) p;
                        byte[] b = new byte[Math.min(len, 1024 * 32)];
                        len = fh.read(b, offset);
                        if (len >= 0) {
                            Buffer buf = new Buffer(len + 5);
                            buf.putByte((byte) SSH_FXP_DATA);
                            buf.putInt(id);
                            buf.putBytes(b, 0, len);
                            if (version >= 6) {
                                buf.putBoolean(len == 0);
                            }
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
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof FileHandle)) {
                        sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                    } else {
                        FileHandle fh = (FileHandle) p;
                        fh.write(data, offset);
                        SshFile sshFile = fh.getFile();

                        sshFile.setLastModified(new Date().getTime());
                        
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_LSTAT:
            case SSH_FXP_STAT: {
                String path = buffer.getString();
                try {
                    SshFile p = resolveFile(path);
                    sendAttrs(id, p);
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_FSTAT: {
                String handle = buffer.getString();
                try {
                    Handle p = handles.get(handle);
                    if (p == null) {
                        sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                    } else {
                        sendAttrs(id, p.getFile());
                    }
                } catch (FileNotFoundException e) {
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_OPENDIR: {
                String path = buffer.getString();
                try {
                    SshFile p = resolveFile(path);
                    if (!p.doesExist()) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, path);
                    } else if (!p.isDirectory()) {
                        sendStatus(id, SSH_FX_NOT_A_DIRECTORY, path);
                    } else if (!p.isReadable()) {
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
                try {
                    Handle p = handles.get(handle);
                    if (!(p instanceof DirectoryHandle)) {
                        sendStatus(id, SSH_FX_INVALID_HANDLE, handle);
                    } else if (((DirectoryHandle) p).isDone()) {
                        sendStatus(id, SSH_FX_EOF, "", "");
                    } else if (!p.getFile().doesExist()) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.getFile().getAbsolutePath());
                    } else if (!p.getFile().isDirectory()) {
                        sendStatus(id, SSH_FX_NOT_A_DIRECTORY, p.getFile().getAbsolutePath());
                    } else if (!p.getFile().isReadable()) {
                        sendStatus(id, SSH_FX_PERMISSION_DENIED, p.getFile().getAbsolutePath());
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
                try {
                    SshFile p = resolveFile(path);
                    if (!p.doesExist()) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, p.getAbsolutePath());
                    } else if (p.isDirectory()) {
                        sendStatus(id, SSH_FX_FILE_IS_A_DIRECTORY, p.getAbsolutePath());
                    } else if (!p.delete()) {
                        sendStatus(id, SSH_FX_FAILURE, "Failed to delete file");
                    } else {
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_MKDIR: {
                String path = buffer.getString();
                // attrs
                try {
                    SshFile p = resolveFile(path);
                    if (p.doesExist()) {
                        if (p.isDirectory()) {
                            sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, p.getAbsolutePath());
                        } else {
                            sendStatus(id, SSH_FX_NOT_A_DIRECTORY, p.getAbsolutePath());
                        }
                    } else if (!p.isWritable()) {
                        sendStatus(id, SSH_FX_PERMISSION_DENIED, p.getAbsolutePath());
                    } else if (!p.mkdir()) {
                        throw new IOException("Error creating dir " + path);
                    } else {
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_RMDIR: {
                String path = buffer.getString();
                // attrs
                try {
                    SshFile p = resolveFile(path);
                    if (p.isDirectory()) {
                        if (p.doesExist()) {
                            if (p.listSshFiles().size() == 0) {
                                if (p.delete()) {
                                    sendStatus(id, SSH_FX_OK, "");
                                } else {
                                    sendStatus(id, SSH_FX_FAILURE, "Unable to delete directory " + path);
                                }
                            } else {
                                sendStatus(id, SSH_FX_DIR_NOT_EMPTY, path);
                            }
                        } else {
                            sendStatus(id, SSH_FX_NO_SUCH_PATH, path);
                        }
                    } else {
                        sendStatus(id, SSH_FX_NOT_A_DIRECTORY, p.getAbsolutePath());
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_REALPATH: {
                String path = buffer.getString();
                if (path.trim().length() == 0) {
                    path = ".";
                }
                // TODO: handle optional args
                try {
                    SshFile p = resolveFile(path);
                    sendPath(id, p);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                    sendStatus(id, SSH_FX_NO_SUCH_FILE, e.getMessage());
                } catch (IOException e) {
                    e.printStackTrace();
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_RENAME: {
                String oldPath = buffer.getString();
                String newPath = buffer.getString();
                try {
                    SshFile o = resolveFile(oldPath);
                    SshFile n = resolveFile(newPath);
                    if (!o.doesExist()) {
                        sendStatus(id, SSH_FX_NO_SUCH_FILE, o.getAbsolutePath());
                    } else if (n.doesExist()) {
                        sendStatus(id, SSH_FX_FILE_ALREADY_EXISTS, n.getAbsolutePath());
                    } else if (!o.move(n)) {
                        sendStatus(id, SSH_FX_FAILURE, "Failed to rename file");
                    } else {
                        sendStatus(id, SSH_FX_OK, "");
                    }
                } catch (IOException e) {
                    sendStatus(id, SSH_FX_FAILURE, e.getMessage());
                }
                break;
            }
            case SSH_FXP_SETSTAT:
            case SSH_FXP_FSETSTAT: {
                // This is required for WinSCP / Cyberduck to upload properly
                // Blindly reply "OK"
                // TODO implement it
                sendStatus(id, SSH_FX_OK, "");
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

    protected void sendAttrs(int id, SshFile file) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, file);
        send(buffer);
    }

    protected void sendAttrs(int id, SshFile file, int flags) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, file, flags);
        send(buffer);
    }


    protected void sendPath(int id, SshFile f) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1);
        //normalize the given path, use *nix style separator
        String normalizedPath = SelectorUtils.normalizePath(f.getAbsolutePath(), "/");
        if (normalizedPath.length() == 0) {
            normalizedPath = "/";
        }
        buffer.putString(normalizedPath);
        f = resolveFile(normalizedPath);
        if (f.getName().length() == 0) {
            f = resolveFile(".");
        }
        if (version <= 3) {
            buffer.putString(getLongName(f)); // Format specified in the specs
            buffer.putInt(0);
        } else {
            buffer.putString(f.getName()); // Supposed to be UTF-8
            writeAttrs(buffer, f);
        }
        send(buffer);
    }

    protected void sendName(int id, Iterator<SshFile> files) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        int wpos = buffer.wpos();
        buffer.putInt(0);
        int nb = 0;
        while (files.hasNext() && buffer.wpos() < MAX_PACKET_LENGTH) {
            SshFile f = files.next();
            buffer.putString(f.getName());
            if (version <= 3) {
                buffer.putString(getLongName(f)); // Format specified in the specs
            } else {
                buffer.putString(f.getName()); // Supposed to be UTF-8
            }
            writeAttrs(buffer, f);
            nb++;
        }
        int oldpos = buffer.wpos();
        buffer.wpos(wpos);
        buffer.putInt(nb);
        buffer.wpos(oldpos);
        send(buffer);
    }

    private String getLongName(SshFile f) {
        String username = f.getOwner();
        if (username.length() > 8) {
            username = username.substring(0, 8);
        } else {
            for (int i = username.length(); i < 8; i++) {
                username = username + " ";
            }
        }

        long length = f.getSize();
        String lengthString = String.format("%1$8s", length);

        StringBuilder sb = new StringBuilder();
        sb.append((f.isDirectory() ? "d" : "-"));
        sb.append((f.isReadable() ? "r" : "-"));
        sb.append((f.isWritable() ? "w" : "-"));
        sb.append((f.isExecutable() ? "x" : "-"));
        sb.append((f.isReadable() ? "r" : "-"));
        sb.append((f.isWritable() ? "w" : "-"));
        sb.append((f.isExecutable() ? "x" : "-"));
        sb.append((f.isReadable() ? "r" : "-"));
        sb.append((f.isWritable() ? "w" : "-"));
        sb.append((f.isExecutable() ? "x" : "-"));
        sb.append(" ");
        sb.append("  1");
        sb.append(" ");
        sb.append(username);
        sb.append(" ");
        sb.append(username);
        sb.append(" ");
        sb.append(lengthString);
        sb.append(" ");
        sb.append(getUnixDate(f.getLastModified()));
        sb.append(" ");
        sb.append(f.getName());

        return sb.toString();
    }

    protected void writeAttrs(Buffer buffer, SshFile file) throws IOException {
        writeAttrs(buffer, file, 0);
    }


    protected void writeAttrs(Buffer buffer, SshFile file, int flags) throws IOException {
        if (!file.doesExist()) {
            throw new FileNotFoundException(file.getAbsolutePath());
        }
        if (version >= 4) {
            long size = file.getSize();
            String username = session.getUsername();
            long lastModif = file.getLastModified();
            int p = 0;
            if (file.isReadable()) {
                p |= S_IRUSR;
            }
            if (file.isWritable()) {
                p |= S_IWUSR;
            }
            if (file.isExecutable()) {
                p |= S_IXUSR;
            }
            if (file.isFile()) {
                buffer.putInt(SSH_FILEXFER_ATTR_PERMISSIONS);
                buffer.putByte((byte) SSH_FILEXFER_TYPE_REGULAR);
                buffer.putInt(p);
            } else if (file.isDirectory()) {
                buffer.putInt(SSH_FILEXFER_ATTR_PERMISSIONS);
                buffer.putByte((byte) SSH_FILEXFER_TYPE_DIRECTORY);
                buffer.putInt(p);
            } else {
                buffer.putInt(0);
                buffer.putByte((byte) SSH_FILEXFER_TYPE_UNKNOWN);
            }
        } else {
            int p = 0;
            if (file.isFile()) {
                p |= 0100000;
            }
            if (file.isDirectory()) {
                p |= 0040000;
            }
            if (file.isReadable()) {
                p |= 0000400;
            }
            if (file.isWritable()) {
                p |= 0000200;
            }
            if (file.isExecutable()) {
                p |= 0000100;
            }
            if (file.isFile()) {
                buffer.putInt(SSH_FILEXFER_ATTR_SIZE| SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
                buffer.putLong(file.getSize());
                buffer.putInt(p);
                buffer.putInt(file.getLastModified()/1000);
                buffer.putInt(file.getLastModified()/1000);
            } else if (file.isDirectory()) {
                buffer.putInt(SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
                buffer.putInt(p);
                buffer.putInt(file.getLastModified()/1000);
                buffer.putInt(file.getLastModified()/1000);
            } else {
                buffer.putInt(0);
            }
        }
    }

    protected void sendStatus(int id, int substatus, String msg) throws IOException {
        sendStatus(id, mapToVersion(substatus), msg, "");
    }

    protected void sendStatus(int id, int substatus, String msg, String lang) throws IOException {
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
        closed = true;
    }

    private SshFile resolveFile(String path) {
    	return this.root.getFile(path);
    }

    private final static String[] MONTHS = { "Jan", "Feb", "Mar", "Apr", "May",
            "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /**
     * Get unix style date string.
     */
    private final static String getUnixDate(long millis) {
        if (millis < 0) {
            return "------------";
        }

        StringBuffer sb = new StringBuffer(16);
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
