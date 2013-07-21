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

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.sftp.Handle;
import org.apache.sshd.sftp.Reply;
import org.apache.sshd.sftp.Request;
import org.apache.sshd.sftp.SftpSession;
import org.apache.sshd.sftp.reply.*;
import org.apache.sshd.sftp.request.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.apache.sshd.sftp.subsystem.SftpConstants.*;
import static org.apache.sshd.sftp.subsystem.SftpConstants.SSH_FXP_STATUS;

public class Serializer {

    private final SftpSession session;

    public Serializer(SftpSession session) {
        this.session = session;
    }

    protected Request readRequest(final Buffer buffer) {
        Request request;

        int length = buffer.getInt();
        byte type = buffer.getByte();
        int id = buffer.getInt();

        switch (type) {
            case SSH_FXP_INIT: {
                if (length != 5) {
                    throw new IllegalArgumentException();
                }
                request = new SshFxpInitRequest(id);
                break;
            }
            case SSH_FXP_OPEN: {
                String path = buffer.getString();
                int acc = (session.getVersion() > 4) ? buffer.getInt() : 0;
                int flags = buffer.getInt();
                request = new SshFxpOpenRequest(id, path, acc, flags);
                break;
            }
            case SSH_FXP_CLOSE: {
                String handleId = buffer.getString();
                Handle handle = session.getHandle(handleId);
                request = new SshFxpCloseRequest(id, handleId, handle);
                break;
            }
            case SSH_FXP_READ: {
                String handleId = buffer.getString();
                long offset = buffer.getLong();
                int len = buffer.getInt();
                Handle handle = session.getHandle(handleId);
                request = new SshFxpReadRequest(id, handleId, offset, len, handle);
                break;
            }
            case SSH_FXP_WRITE: {
                String handleId = buffer.getString();
                long offset = buffer.getLong();
                byte[] data = buffer.getBytes();
                Handle handle = session.getHandle(handleId);
                request = new SshFxpWriteRequest(id, handleId, offset, data, handle);
                break;
            }
            case SSH_FXP_LSTAT: {
                String path = buffer.getString();
                int flags = 0;
                if (session.getVersion() > 5) {
                    flags = buffer.getInt();
                }
                request = new SshFxpLstatRequest(id, path, flags);
                break;
            }
            case SSH_FXP_FSTAT: {
                String handle = buffer.getString();
                int flags = 0;
                if (session.getVersion() > 5) {
                    flags = buffer.getInt();
                }
                Handle p = session.getHandle(handle);
                request = new SshFxpFstatRequest(id, handle, p);
                break;
            }
            case SSH_FXP_SETSTAT: {
                request = new SshFxpSetstatRequest(id);
                break;
            }
            case SSH_FXP_FSETSTAT: {
                request = new SshFxpFsetstatRequest(id);
                break;
            }
            case SSH_FXP_OPENDIR: {
                String path = buffer.getString();
                request = new SshFxpOpendirRequest(id, path);
                break;
            }
            case SSH_FXP_READDIR: {
                String handle = buffer.getString();
                Handle p = session.getHandle(handle);
                request = new SshFxpReaddirRequest(id, handle, p);
                break;
            }
            case SSH_FXP_REMOVE: {
                String path = buffer.getString();
                request = new SshFxpRemoveRequest(id, path);
                break;
            }
            case SSH_FXP_MKDIR: {
                String path = buffer.getString();
                request = new SshFxpMkdirRequest(id, path);
                break;
            }
            case SSH_FXP_RMDIR: {
                String path = buffer.getString();
                request = new SshFxpRmdirRequest(id, path);
                break;
            }
            case SSH_FXP_REALPATH: {
                String path = buffer.getString();
                byte options = SSH_FXP_REALPATH_NO_CHECK;
                List<String> compose = new ArrayList<String>();
                if (session.getVersion() >= 6 && buffer.available() > 0) {
                    options = buffer.getByte();
                }
                while (session.getVersion() >= 6 && buffer.available() > 0) {
                    compose.add(buffer.getString());
                }
                request = new SshFxpRealpathRequest(id, path, options, compose);
                break;
            }
            case SSH_FXP_STAT: {
                String path = buffer.getString();
                int flags = 0;
                if (session.getVersion() > 5) {
                    flags = buffer.getInt();
                }
                request = new SshFxpStatRequest(id, path, flags);
                break;
            }
            case SSH_FXP_RENAME: {
                final String oldPath = buffer.getString();
                final String newPath = buffer.getString();
                request = new SshFxpRenameRequest(id, oldPath, newPath);
                break;
            }
            case SSH_FXP_READLINK: {
                // TODO: implement
                request = new UnsupportedRequest(id, Type.SSH_FXP_READLINK.toByte());
                break;
            }
            case SSH_FXP_LINK: {
                // TODO: implement
                request = new UnsupportedRequest(id, Type.SSH_FXP_LINK.toByte());
                break;
            }
            case SSH_FXP_BLOCK: {
                // TODO: implement
                request = new UnsupportedRequest(id, Type.SSH_FXP_BLOCK.toByte());
                break;
            }
            case SSH_FXP_UNBLOCK: {
                // TODO: implement
                request = new UnsupportedRequest(id, Type.SSH_FXP_UNBLOCK.toByte());
                break;
            }
            default: {
                request = new UnsupportedRequest(id, type);
                break;
            }
        }
        return request;
    }

    /*
    public Reply readReply(final Buffer buffer) {
        Reply reply;

        int length = buffer.getInt();
        byte type = buffer.getByte();
        int id = buffer.getInt();

        switch (type) {
            //
            // Replies
            //
            case SSH_FXP_VERSION: {
                // TODO
                break;
            }
            case SSH_FXP_STATUS: {
                // TODO
                break;
            }
            case SSH_FXP_HANDLE: {
                // TODO
                break;
            }
            case SSH_FXP_DATA: {
                // TODO
                break;
            }
            case SSH_FXP_NAME: {
                // TODO
                break;
            }
            case SSH_FXP_ATTRS: {
                // TODO
                break;
            }
            default:
                throw new IllegalStateException("Unsupported reply type: " + type);
        }
        return reply;
    }

    public Buffer writeRequest(final Request request) throws IOException {
        if (request == null) {
            throw new IllegalStateException("Can not serialize a null request");
        } else if (request instanceof ...) {
            // TODO
        } else {
            throw new IllegalStateException("Unsupported request: " + request.toString());
        }
    }
    */

    public Buffer writeReply(final Reply reply) throws IOException {
        if (reply == null) {
            throw new IllegalStateException("Can not serialize a null reply");
        } else if (reply instanceof SshFxpAttrsReply) {
            return writeAttrsReply((SshFxpAttrsReply) reply);
        } else if (reply instanceof SshFxpDataReply) {
            return writeDataReply((SshFxpDataReply) reply);
        } else if (reply instanceof SshFxpHandleReply) {
            return writeHandleReply((SshFxpHandleReply) reply);
        } else if (reply instanceof SshFxpNameReply) {
            return writeNameReply((SshFxpNameReply) reply);
        } else if (reply instanceof SshFxpStatusReply) {
            return writeStatus((SshFxpStatusReply) reply);
        } else if (reply instanceof SshFxpVersionReply) {
            return writeVersionReply((SshFxpVersionReply) reply);
        } else {
            throw new IllegalStateException("Unsupported reply: " + reply.toString());
        }
    }

    private Buffer writeAttrsReply(SshFxpAttrsReply reply) throws IOException {
        int id = reply.getId();
        FileAttributes attrs = reply.getAttributes();

        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, attrs);
        return buffer;
    }

    private Buffer writeVersionReply(SshFxpVersionReply reply) {
        int version = reply.getVersion();

        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_VERSION);
        buffer.putInt(version);
        return buffer;
    }

    private Buffer writeNameReply(SshFxpNameReply reply) {
        int id = reply.getId();
        Collection<SshFxpNameReply.ReplyFile> files = reply.getFiles();
        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(files.size());
        for (SshFxpNameReply.ReplyFile f : files) {
            buffer.putString(f.getFileName());
            if (session.getVersion() <= 3) {
                buffer.putString(f.getLongName()); // Format specified in the specs
            }
            writeAttrs(buffer, f.getAttrs());
        }
        if (session.getVersion() >= 6 && reply.isEol()) {
            buffer.putBoolean(true);
        }
        return buffer;
    }

    private Buffer writeHandleReply(SshFxpHandleReply reply) throws IOException {
        int id = reply.getId();
        String handle = reply.getHandle().getId();

        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        return buffer;
    }

    private Buffer writeDataReply(SshFxpDataReply reply) {
        long id = reply.getId();
        byte[] data = reply.getData();
        int offset = reply.getOffset();
        int length = reply.getLength();
        boolean eof = reply.isEof();

        Buffer buffer = new Buffer(length + 5);
        buffer.putByte((byte) SSH_FXP_DATA);
        buffer.putInt(id);
        buffer.putBytes(data, offset, length);
        if (session.getVersion() >= 6 && eof) {
            buffer.putBoolean(eof);
        }
        return buffer;
    }

    private Buffer writeStatus(SshFxpStatusReply reply) throws IOException {
        int id = reply.getId();
        int substatus = reply.getSubstatus();
        String msg = reply.getMsg();
        String lang = reply.getLang();

        Buffer buffer = new Buffer();
        buffer.putByte((byte) SSH_FXP_STATUS);
        buffer.putInt(id);
        buffer.putInt(mapToVersion(substatus));
        buffer.putString(msg);
        buffer.putString(lang);
        return buffer;
    }

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
        return mapToVersion(code, session.getVersion());
    }

    protected void writeAttrs(Buffer buffer, FileAttributes attrs) {
        int version = session.getVersion();
        int flags = attrs.getFlags();
        buffer.putInt(flags);
        if (session.getVersion() >= 4) {
            buffer.putByte(attrs.getType());
        }
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong(attrs.getSize());
        }
        if (version >= 6 && (flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0) {
            buffer.putLong(attrs.getAllocationSize());
        }
        if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            buffer.putString(attrs.getOwner());
            buffer.putString(attrs.getGroup());
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            int perms = attrs.getPermissions();
            if (session.getVersion() < 4) {
                if (attrs.getType() == SSH_FILEXFER_TYPE_REGULAR) {
                    perms |= 0100000;
                } else if (attrs.getType() == SSH_FILEXFER_TYPE_DIRECTORY) {
                    perms |= 0040000;
                }
            }
            buffer.putInt(perms);
        }
        if (version <= 3 && (flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            buffer.putInt(attrs.getAccessTime());
            buffer.putInt(attrs.getAccessTime());
        }
    }

    protected void writeAttrs(Buffer buffer, SshFile file, int flags) {
        if (session.getVersion() >= 4) {
            long size = file.getSize();
            String username = session.getSession().getUsername();
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
                buffer.putInt(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
                buffer.putLong(file.getSize());
                buffer.putInt(p);
                buffer.putInt(file.getLastModified() / 1000);
                buffer.putInt(file.getLastModified() / 1000);
            } else if (file.isDirectory()) {
                buffer.putInt(SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
                buffer.putInt(p);
                buffer.putInt(file.getLastModified() / 1000);
                buffer.putInt(file.getLastModified() / 1000);
            } else {
                buffer.putInt(0);
            }
        }
    }

}
