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
package org.apache.sshd.sftp.subsystem;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ThreadUtils;
import org.apache.sshd.server.*;
import org.apache.sshd.server.channel.ChannelDataReceiver;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.*;
import org.apache.sshd.sftp.reply.*;
import org.apache.sshd.sftp.request.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.apache.sshd.sftp.subsystem.SftpConstants.*;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem implements Command, SessionAware, FileSystemAware, SftpSession, ChannelDataReceiver, ChannelSessionAware {

    protected static final Logger LOG = LoggerFactory.getLogger(SftpSubsystem.class);

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

    public static final int LOWER_SFTP_IMPL = 3; // Working implementation from v3
    public static final int HIGHER_SFTP_IMPL = 6; //  .. up to
    public static final String ALL_SFTP_IMPL = "3,4,5,6";
    public static final int  MAX_PACKET_LENGTH = 1024 * 16;

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final String MAX_OPEN_HANDLES_PER_SESSION = "max-open-handles-per-session";


    private ExitCallback callback;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private Environment env;
    private ServerSession session;
    private ChannelSession channel;
    private boolean closed = false;

    private FileSystemView root;

    private int version;
    private Map<String, Handle> handles = new HashMap<String, Handle>();

    private Sftplet sftpLet = new DefaultSftpletContainer();
    private Serializer serializer = new Serializer(this);

    private final ExecutorService executor;

    public SftpSubsystem() {
        executor = ThreadUtils.newSingleThreadExecutor("sftp[" + Integer.toHexString(hashCode()) + "]");
    }

    public void setSftpLet(final Sftplet sftpLet) {
        this.sftpLet = sftpLet;
    }

    public int getVersion() {
        return version;
    }

    public Session getSession() {
        return session;
    }

    public Handle getHandle(String id) {
        return handles.get(id);
    }

    public Handle createFileHandle(SshFile file, int flags) {
        String id = UUID.randomUUID().toString();
        Handle handle = new FileHandle(id,  file, flags);
        handles.put(id, handle);
        return handle;
    }

    public Handle createDirectoryHandle(SshFile file) {
        String id = UUID.randomUUID().toString();
        Handle handle = new DirectoryHandle(id, file);
        handles.put(id, handle);
        return handle;
    }

    public void setChannelSession(ChannelSession channel) {
        this.channel = channel;
        channel.setDataReceiver(this);
    }

    public void setSession(ServerSession session) {
        sftpLet.onConnect(this);
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
    }

    private Buffer buffer = new Buffer();

    public int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException {
        Buffer incoming = new Buffer(buf,  start, len);
        // If we already have partial data, we need to append it to the buffer and use it
        if (buffer.available() > 0) {
            buffer.putBuffer(incoming);
            incoming = buffer;
        }
        // Process commands
        int rpos = incoming.rpos();
        while (receive(incoming));
        int read = incoming.rpos() - rpos;
        // Compact and add remaining data
        buffer.compact();
        if (buffer != incoming && incoming.available() > 0) {
            buffer.putBuffer(incoming);
        }
        return read;
    }

    protected boolean receive(Buffer incoming) throws IOException {
        int rpos = incoming.rpos();
        int wpos = incoming.wpos();
        if (wpos - rpos > 4) {
            int length = incoming.getInt();
            if (length < 5) {
                throw new IOException("Illegal sftp packet length: " + length);
            }
            if (wpos - rpos >= length + 4) {
                incoming.rpos(rpos);
                incoming.wpos(rpos + 4 + length);
                process(incoming);
                incoming.rpos(rpos + 4 + length);
                incoming.wpos(wpos);
                return true;
            }
        }
        incoming.rpos(rpos);
        return false;
    }

    public void close() throws IOException {
        executor.shutdownNow();
        if (handles != null) {
            for (Map.Entry<String, Handle> entry : handles.entrySet()) {
                Handle handle = entry.getValue();
                try {
                    handle.close();
                } catch (IOException ioe) {
                    LOG.error("Could not close open handle: " + entry.getKey(), ioe);
                }
            }
        }
        callback.onExit(0);
        sftpLet.onDisconnect(this);
    }

    public void process(Buffer buffer) throws IOException {
        final Request request = serializer.readRequest(buffer);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received sftp request: " + request);
        }
        executor.execute(new Runnable() {
            public void run() {
                try {
                    Reply reply = sftpLet.beforeCommand(SftpSubsystem.this, request);
                    if (reply == null) {
                        reply = doProcess(request);
                    }
                    reply = sftpLet.afterCommand(SftpSubsystem.this, request, reply);
                    if (reply != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Sending sftp reply: " + reply);
                        }
                        Buffer buffer = serializer.writeReply(reply);
                        send(buffer);
                    }
                } catch (Throwable t) {
                    // TODO do something
                    t.printStackTrace();
                }
            }
        });
    }

    protected Reply doProcess(Request request) throws IOException {
        try {
            if (request instanceof SshFxpInitRequest) {
                return doProcessInit((SshFxpInitRequest) request);
            } else if (request instanceof SshFxpOpenRequest) {
                return doProcessOpen((SshFxpOpenRequest) request);
            } else if (request instanceof SshFxpCloseRequest) {
                return doProcessClose((SshFxpCloseRequest) request);
            } else if (request instanceof SshFxpReadRequest) {
                return doProcessRead((SshFxpReadRequest) request);
            } else if (request instanceof SshFxpWriteRequest) {
                return doProcessWrite((SshFxpWriteRequest) request);
            } else if ((request instanceof SshFxpLstatRequest)
                    || (request instanceof SshFxpStatRequest)) {
                return doProcessStat(request);
            } else if (request instanceof SshFxpFstatRequest) {
                return doProcessFstat((SshFxpFstatRequest) request);
            } else if (request instanceof SshFxpOpendirRequest) {
                return doProcessOpendir((SshFxpOpendirRequest) request);
            } else if (request instanceof SshFxpReaddirRequest) {
                return doProcessReaddir((SshFxpReaddirRequest) request);
            } else if (request instanceof SshFxpRemoveRequest) {
                return doProcessRemove((SshFxpRemoveRequest) request);
            } else if (request instanceof SshFxpMkdirRequest) {
                return doProcessMkdir((SshFxpMkdirRequest) request);
            } else if (request instanceof SshFxpRmdirRequest) {
                return doProcessRmdir((SshFxpRmdirRequest) request);
            } else if (request instanceof SshFxpRealpathRequest) {
                return doProcessRealpath((SshFxpRealpathRequest) request);
            } else if (request instanceof SshFxpRenameRequest) {
                return doProcessRename((SshFxpRenameRequest) request);
            } else if ((request instanceof SshFxpSetstatRequest)
                    || (request instanceof SshFxpFsetstatRequest)) {
                return doProcessSetstat(request);

            } else {
                LOG.error("Received: {}", request);
                int id = request.getId();
                return new SshFxpStatusReply(id, SSH_FX_OP_UNSUPPORTED, "Command " + request + " is unsupported or not implemented");
            }
        } catch (IOException e) {
            int id = request.getId();
            return new SshFxpStatusReply(id, SSH_FX_FAILURE, e.getMessage());
        }
    }

    private Reply doProcessSetstat(Request request) throws IOException {
        // This is required for WinSCP / Cyberduck to upload properly
        // Blindly reply "OK"
        // TODO implement it
        int id = request.getId();
        return new SshFxpStatusReply(id, SSH_FX_OK, "");
    }

    private Reply doProcessRename(SshFxpRenameRequest request) throws IOException {
        int id = request.getId();
        String oldPath = request.getOldPath();
        String newPath = request.getNewPath();
        SshFile o = resolveFile(oldPath);
        SshFile n = resolveFile(newPath);
        if (!o.doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, o.getAbsolutePath());
        } else if (n.doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_FILE_ALREADY_EXISTS, n.getAbsolutePath());
        } else if (!o.move(n)) {
            return new SshFxpStatusReply(id, SSH_FX_FAILURE, "Failed to rename file");
        } else {
            return new SshFxpStatusReply(id, SSH_FX_OK, "");
        }
    }

    private Reply doProcessRealpath(SshFxpRealpathRequest request) throws IOException {
        int id = request.getId();
        String path = request.getPath();
        if (path.trim().length() == 0) {
            path = ".";
        }
        SshFile p = resolveFile(path);
        for (String s : request.getCompose()) {
            p = this.root.getFile(p, s);
        }
        String normalizedPath = SelectorUtils.normalizePath(p.getAbsolutePath(), "/");
        if (normalizedPath.length() == 0) {
            normalizedPath = "/";
        }
        p = resolveFile(normalizedPath);
        if (p.getName().length() == 0) {
            p = resolveFile(".");
        }
        boolean exists = (request.getOptions() != SSH_FXP_REALPATH_NO_CHECK) && p.doesExist();
        if (!exists && request.getOptions() == SSH_FXP_REALPATH_STAT_ALWAYS) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, p.getAbsolutePath());
        } else if (exists && (request.getOptions() == SSH_FXP_REALPATH_STAT_IF || request.getOptions() == SSH_FXP_REALPATH_STAT_ALWAYS)) {
            SshFxpNameReply reply = new SshFxpNameReply(id);
            int flags = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE;
            reply.addFile(p, normalizedPath, getLongName(p), new FileAttributes(p, flags));
            return reply;
        } else {
            SshFxpNameReply reply = new SshFxpNameReply(id);
            reply.addFile(p, normalizedPath, getLongName(p), new FileAttributes());
            return reply;
        }
    }

    private Reply doProcessRmdir(SshFxpRmdirRequest request) throws IOException {
        int id = request.getId();
        String path = request.getPath();
        // attrs
        SshFile p = resolveFile(path);
        if (p.isDirectory()) {
            if (p.doesExist()) {
                if (p.listSshFiles().size() == 0) {
                    if (p.delete()) {
                        return new SshFxpStatusReply(id, SSH_FX_OK, "");
                    } else {
                        return new SshFxpStatusReply(id, SSH_FX_FAILURE, "Unable to delete directory " + path);
                    }
                } else {
                    return new SshFxpStatusReply(id, SSH_FX_DIR_NOT_EMPTY, path);
                }
            } else {
                return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_PATH, path);
            }
        } else {
            return new SshFxpStatusReply(id, SSH_FX_NOT_A_DIRECTORY, p.getAbsolutePath());
        }
    }

    private Reply doProcessMkdir(SshFxpMkdirRequest request) throws IOException {
        int id = request.getId();
        String path = request.getPath();
        // attrs
        SshFile p = resolveFile(path);
        if (p.doesExist()) {
            if (p.isDirectory()) {
                return new SshFxpStatusReply(id, SSH_FX_FILE_ALREADY_EXISTS, p.getAbsolutePath());
            } else {
                return new SshFxpStatusReply(id, SSH_FX_NOT_A_DIRECTORY, p.getAbsolutePath());
            }
        } else if (!p.isWritable()) {
            return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, p.getAbsolutePath());
        } else if (!p.mkdir()) {
            return new SshFxpStatusReply(id, SSH_FX_FAILURE, "Error creating dir " + path);
        } else {
            return new SshFxpStatusReply(id, SSH_FX_OK, "");
        }
    }

    private Reply doProcessRemove(SshFxpRemoveRequest request) throws IOException {
        int id = request.getId();
        String path = request.getPath();
        SshFile p = resolveFile(path);
        if (!p.doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, p.getAbsolutePath());
        } else if (p.isDirectory()) {
            return new SshFxpStatusReply(id, SSH_FX_FILE_IS_A_DIRECTORY, p.getAbsolutePath());
        } else if (!p.delete()) {
            return new SshFxpStatusReply(id, SSH_FX_FAILURE, "Failed to delete file");
        } else {
            return new SshFxpStatusReply(id, SSH_FX_OK, "");
        }
    }

    private Reply doProcessReaddir(SshFxpReaddirRequest request) throws IOException {
        int id = request.getId();
        String handle = request.getHandleId();
        Handle p = getHandle(handle);
        if (!(p instanceof DirectoryHandle)) {
            return new SshFxpStatusReply(id, SSH_FX_INVALID_HANDLE, handle);
        } else if (((DirectoryHandle) p).isDone()) {
            return new SshFxpStatusReply(id, SSH_FX_EOF, "", "");
        } else if (!p.getFile().doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, p.getFile().getAbsolutePath());
        } else if (!p.getFile().isDirectory()) {
            return new SshFxpStatusReply(id, SSH_FX_NOT_A_DIRECTORY, p.getFile().getAbsolutePath());
        } else if (!p.getFile().isReadable()) {
            return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, p.getFile().getAbsolutePath());
        } else {
            DirectoryHandle dh = (DirectoryHandle) p;
            if (dh.hasNext()) {
                // There is at least one file in the directory.
                // Send only a few files at a time to not create packets of a too
                // large size or have a timeout to occur.
                Reply reply = sendName(id, dh);
                if (!dh.hasNext()) {
                    // if no more files to send
                    dh.setDone(true);
                    dh.clearFileList();
                }
                return reply;
            } else {
                // empty directory
                dh.setDone(true);
                dh.clearFileList();
                return new SshFxpStatusReply(id, SSH_FX_EOF, "", "");
            }
        }
    }

    private Reply doProcessOpendir(SshFxpOpendirRequest request) throws IOException {
        int id = request.getId();
        String path = request.getPath();
        SshFile p = resolveFile(path);
        if (!p.doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, path);
        } else if (!p.isDirectory()) {
            return new SshFxpStatusReply(id, SSH_FX_NOT_A_DIRECTORY, path);
        } else if (!p.isReadable()) {
            return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, path);
        } else {
            Handle handle = createDirectoryHandle(p);
            return new SshFxpHandleReply(id, handle);
        }
    }

    private Reply doProcessFstat(SshFxpFstatRequest request) throws IOException {
        int id = request.getId();
        String handle = request.getHandleId();
        Handle p = getHandle(handle);
        if (p == null) {
            return new SshFxpStatusReply(id, SSH_FX_INVALID_HANDLE, handle);
        } else {
            int flags = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE;
            return new SshFxpAttrsReply(id, new FileAttributes(p.getFile(), flags));
        }
    }

    private Reply doProcessStat(Request sftpRequest) throws IOException {
        int id = sftpRequest.getId();
        String path;
        if (sftpRequest instanceof SshFxpLstatRequest) {
            SshFxpLstatRequest sshFxpLstatRequest = (SshFxpLstatRequest) sftpRequest;
            path = sshFxpLstatRequest.getPath();
        } else {
            SshFxpStatRequest sshFxpStatRequest = (SshFxpStatRequest) sftpRequest;
            path = sshFxpStatRequest.getPath();
        }
        SshFile p = resolveFile(path);
        if (!p.doesExist()) {
            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, p.getAbsolutePath());
        }
        int flags = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE;
        return new SshFxpAttrsReply(id, new FileAttributes(p, flags));
    }

    private Reply doProcessWrite(SshFxpWriteRequest request) throws IOException {
        int id = request.getId();
        String handle = request.getHandleId();
        long offset = request.getOffset();
        byte[] data = request.getData();
        Handle p = getHandle(handle);
        if (!(p instanceof FileHandle)) {
            return new SshFxpStatusReply(id, SSH_FX_INVALID_HANDLE, handle);
        } else {
            FileHandle fh = (FileHandle) p;
            fh.write(data, offset);
            SshFile sshFile = fh.getFile();

            sshFile.setLastModified(new Date().getTime());

            return new SshFxpStatusReply(id, SSH_FX_OK, "");
        }
    }

    private Reply doProcessRead(SshFxpReadRequest request) throws IOException {
        int id = request.getId();
        String handle = request.getHandleId();
        long offset = request.getOffset();
        int len = request.getLength();
        Handle p = getHandle(handle);
        if (!(p instanceof FileHandle)) {
            return new SshFxpStatusReply(id, SSH_FX_INVALID_HANDLE, handle);
        } else {
            FileHandle fh = (FileHandle) p;
            byte[] b = new byte[len];
            len = fh.read(b, offset);
            if (len >= 0) {
                return new SshFxpDataReply(id, b, 0, len, len < b.length);
            } else {
                return new SshFxpStatusReply(id, SSH_FX_EOF, "");
            }
        }
    }

    private Reply doProcessClose(SshFxpCloseRequest sftpRequest) throws IOException {
        int id = sftpRequest.getId();
        SshFxpCloseRequest sshFxpCloseRequest = sftpRequest;
        String handle = sshFxpCloseRequest.getHandleId();
        Handle h = getHandle(handle);
        if (h == null) {
            return new SshFxpStatusReply(id, SSH_FX_INVALID_HANDLE, handle, "");
        } else {
            handles.remove(handle);
            h.close();
            return new SshFxpStatusReply(id, SSH_FX_OK, "", "");
        }
    }

    private Reply doProcessOpen(SshFxpOpenRequest request) throws IOException {
        int id = request.getId();
        if (session.getFactoryManager().getProperties() != null) {
            String maxHandlesString = session.getFactoryManager().getProperties().get(MAX_OPEN_HANDLES_PER_SESSION);
            if (maxHandlesString != null) {
                int maxHandleCount = Integer.parseInt(maxHandlesString);
                if (handles.size() > maxHandleCount) {
                    return new SshFxpStatusReply(id, SSH_FX_FAILURE, "Too many open handles");
                }
            }
        }

        int accValue = request.getAcc();
        if (accValue == 0) {
            String path = request.getPath();
            int flags = request.getFlags();
            // attrs
            SshFile file = resolveFile(path);
            if (file.doesExist()) {
                if (((flags & SSH_FXF_CREAT) != 0) && ((flags & SSH_FXF_EXCL) != 0)) {
                    return new SshFxpStatusReply(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                }
            } else {
                if ((flags & SSH_FXF_CREAT) != 0) {
                    if (!file.isWritable()) {
                        return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                    }
                    file.create();
                }
            }
            if ((flags & SSH_FXF_TRUNC) != 0) {
                file.truncate();
            }
            return new SshFxpHandleReply(id, createFileHandle(file, flags));
        } else {
            String path = request.getPath();
            int acc = accValue;
            int flags = request.getFlags();
            // attrs
            SshFile file = resolveFile(path);
            switch (flags & SSH_FXF_ACCESS_DISPOSITION) {
                case SSH_FXF_CREATE_NEW: {
                    if (file.doesExist()) {
                        return new SshFxpStatusReply(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                    } else if (!file.isWritable()) {
                        return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                    }
                    file.create();
                    break;
                }
                case SSH_FXF_CREATE_TRUNCATE: {
                    if (file.doesExist()) {
                        return new SshFxpStatusReply(id, SSH_FX_FILE_ALREADY_EXISTS, path);
                    } else if (!file.isWritable()) {
                        return new SshFxpStatusReply(id, SSH_FX_PERMISSION_DENIED, "Can not create " + path);
                    }
                    file.truncate();
                    break;
                }
                case SSH_FXF_OPEN_EXISTING: {
                    if (!file.doesExist()) {
                        if (!file.getParentFile().doesExist()) {
                            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_PATH, path);
                        } else {
                            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, path);
                        }
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
                            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_PATH, path);
                        } else {
                            return new SshFxpStatusReply(id, SSH_FX_NO_SUCH_FILE, path);
                        }
                    }
                    file.truncate();
                    break;
                }
                default:
                    throw new IllegalArgumentException("Unsupported open mode: " + flags);
            }
            return new SshFxpHandleReply(id, createFileHandle(file, flags));
        }
    }

    private Reply doProcessInit(SshFxpInitRequest request) throws IOException {
        int id = request.getId();
        version = id;
        if (version >= LOWER_SFTP_IMPL) {
            version = Math.min(version, HIGHER_SFTP_IMPL);
            return new SshFxpVersionReply(version);
        } else {
            // We only support version >= 3 (Version 1 and 2 are not common)
            return new SshFxpStatusReply(id, SSH_FX_OP_UNSUPPORTED, "SFTP server only support versions " + ALL_SFTP_IMPL);
        }
    }

    protected SshFxpNameReply sendName(int id, Iterator<SshFile> files) throws IOException {
        SshFxpNameReply reply = new SshFxpNameReply(id);
        int nb = 0;
        while (files.hasNext() && nb < MAX_PACKET_LENGTH / 2) {
            SshFile f = files.next();
            String filename = f.getName();
            if (version <= 3) {
                nb += 55 + filename.length() * 2;
            } else {
                nb += filename.length();
            }
            nb += 10; // Attrs size
            int flags = SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ACCESSTIME;
            reply.addFile(f, filename, getLongName(f), new FileAttributes(f, flags));
        }
        reply.setEol(!files.hasNext());
        return reply;
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

    private final static String[] MONTHS = {"Jan", "Feb", "Mar", "Apr", "May",
            "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

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
