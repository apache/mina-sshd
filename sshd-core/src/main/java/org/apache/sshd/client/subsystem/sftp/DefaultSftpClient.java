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
package org.apache.sshd.client.subsystem.sftp;

import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_APPEND_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_ATTRIBUTES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_ATTRIBUTES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V3;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V4;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V5;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V6;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ALL;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_CREATETIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_SIZE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_SUBSECOND_TIMES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_UIDGID;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_REGULAR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_SYMLINK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_APPEND;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_CREAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_CREATE_NEW;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_CREATE_TRUNCATE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_EXCL;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_OPEN_EXISTING;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_OPEN_OR_CREATE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_READ;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_TRUNC;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_TRUNCATE_EXISTING;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXF_WRITE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_ATTRS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_BLOCK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_CLOSE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_FSETSTAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_FSTAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_HANDLE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_INIT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_LINK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_LSTAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_MKDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_NAME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_OPEN;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_OPENDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_READ;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_READDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_READLINK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_REALPATH;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_REMOVE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_RENAME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_RENAME_ATOMIC;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_RENAME_OVERWRITE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_RMDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_SETSTAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_STAT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_STATUS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_SYMLINK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_UNBLOCK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_VERSION;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FXP_WRITE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_EOF;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_OK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFLNK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFREG;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.FileTime;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SftpException;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManagerUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.InputStreamWithChannel;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.common.util.io.OutputStreamWithChannel;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSftpClient extends AbstractSftpClient {
    private final ClientSession clientSession;
    private final ChannelSubsystem channel;
    private final Map<Integer, Buffer> messages;
    private final AtomicInteger cmdId = new AtomicInteger(100);
    private final Buffer receiveBuffer = new ByteArrayBuffer();
    private boolean closing;
    private int version;
    private final Map<String,byte[]> extensions = new TreeMap<String,byte[]>(String.CASE_INSENSITIVE_ORDER);
    private final Map<String,byte[]> exposedExtensions = Collections.unmodifiableMap(extensions);

    public DefaultSftpClient(ClientSession clientSession) throws IOException {
        this.clientSession = clientSession;
        this.channel = clientSession.createSubsystemChannel(SftpConstants.SFTP_SUBSYSTEM_NAME);
        this.messages = new HashMap<>();
        this.channel.setOut(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] { (byte) b }, 0, 1);
            }
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                data(b, off, len);
            }
        });
        this.channel.setErr(new ByteArrayOutputStream(Byte.MAX_VALUE));
        this.channel.open().verify(FactoryManagerUtils.getLongProperty(clientSession, SFTP_CHANNEL_OPEN_TIMEOUT, DEFAULT_CHANNEL_OPEN_TIMEOUT));
        this.channel.onClose(new Runnable() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void run() {
                synchronized (messages) {
                    closing = true;
                    messages.notifyAll();
                }
            }
        });
        init();
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public Map<String, byte[]> getServerExtensions() {
        return exposedExtensions;
    }

    @Override
    public boolean isClosing() {
        return closing;
    }

    @Override
    public boolean isOpen() {
        return this.channel.isOpen();
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            this.channel.close(false);
        }
    }

    /**
     * Receive binary data
     */
    protected int data(byte[] buf, int start, int len) throws IOException {
        Buffer incoming = new ByteArrayBuffer(buf,  start, len);
        // If we already have partial data, we need to append it to the buffer and use it
        if (receiveBuffer.available() > 0) {
            receiveBuffer.putBuffer(incoming);
            incoming = receiveBuffer;
        }
        // Process commands
        int rpos = incoming.rpos();
        for (int count=0; receive(incoming); count++) {
            if (log.isTraceEnabled()) {
                log.trace("Processed " + count + " data messages");
            }
        }

        int read = incoming.rpos() - rpos;
        // Compact and add remaining data
        receiveBuffer.compact();
        if (receiveBuffer != incoming && incoming.available() > 0) {
            receiveBuffer.putBuffer(incoming);
        }
        return read;
    }

    /**
     * Read SFTP packets from buffer
     */
    protected boolean receive(Buffer incoming) throws IOException {
        int rpos = incoming.rpos();
        int wpos = incoming.wpos();
        clientSession.resetIdleTimeout();
        if ((wpos - rpos) > 4) {
            int length = incoming.getInt();
            if (length < 5) {
                throw new IOException("Illegal sftp packet length: " + length);
            }
            if ((wpos - rpos) >= (length + 4)) {
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

    /**
     * Process an SFTP packet
     */
    protected void process(Buffer incoming) throws IOException {
        Buffer buffer = new ByteArrayBuffer(incoming.available());
        buffer.putBuffer(incoming);
        buffer.rpos(5);
        int id = buffer.getInt();
        buffer.rpos(0);
        synchronized (messages) {
            messages.put(Integer.valueOf(id), buffer);
            messages.notifyAll();
        }
    }

    protected int send(int cmd, Buffer buffer) throws IOException {
        int id = cmdId.incrementAndGet();
        
        try(DataOutputStream dos = new DataOutputStream(new NoCloseOutputStream(channel.getInvertedIn()))) {
            dos.writeInt(5 + buffer.available());
            dos.writeByte(cmd);
            dos.writeInt(id);
            dos.write(buffer.array(), buffer.rpos(), buffer.available());
            dos.flush();
        }

        return id;
    }

    protected Buffer receive(int id) throws IOException {
        synchronized (messages) {
            while (true) {
                if (closing) {
                    throw new SshException("Channel has been closed");
                }
                Buffer buffer = messages.remove(Integer.valueOf(id));
                if (buffer != null) {
                    return buffer;
                }
                try {
                    messages.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException("Interrupted while waiting for messages").initCause(e);
                }
            }
        }
    }

    protected Buffer read() throws IOException {
        try(DataInputStream dis=new DataInputStream(new NoCloseInputStream(channel.getInvertedOut()))) {
            int length = dis.readInt();
            if (length < 5) {
                throw new IllegalArgumentException("Bad length: " + length);
            }
            Buffer buffer = new ByteArrayBuffer(length + 4);
            buffer.putInt(length);
            int nb = length;
            while (nb > 0) {
                int readLen = dis.read(buffer.array(), buffer.wpos(), nb);
                if (readLen < 0) {
                    throw new IllegalArgumentException("Premature EOF while read " + length + " bytes - remaining=" + nb);
                }
                buffer.wpos(buffer.wpos() + readLen);
                nb -= readLen;
            }

            return buffer;
        }
    }

    protected void init() throws IOException {
        // Init packet
        try(DataOutputStream dos = new DataOutputStream(new NoCloseOutputStream(channel.getInvertedIn()))) {
            dos.writeInt(5);
            dos.writeByte(SSH_FXP_INIT);
            dos.writeInt(SFTP_V6);
            dos.flush();
        }

        Buffer buffer;
        synchronized (messages) {
            while (messages.isEmpty()) {
                try {
                    messages.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException("Interruppted init()").initCause(e);
                }
            }
            buffer = messages.remove(messages.keySet().iterator().next());

        }

        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_VERSION) {
            if (id < SFTP_V3) {
                throw new SshException("Unsupported sftp version " + id);
            }
            version = id;

            while (buffer.available() > 0) {
                String name = buffer.getString();
                byte[] data = buffer.getBytes();
                extensions.put(name, data);
            }
        } else if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("init(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }

            throw new SftpException(substatus, msg);
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected void checkStatus(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkStatus(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }

            if (substatus != SSH_FX_OK) {
                throw new SftpException(substatus, msg);
            }
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected String checkHandle(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkHandle(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_HANDLE) {
            String handle = ValidateUtils.checkNotNullAndNotEmpty(buffer.getString(), "Null/empty handle in buffer", GenericUtils.EMPTY_OBJECT_ARRAY);
            return handle;
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected Attributes checkAttributes(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkAttributes(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_ATTRS) {
            return readAttributes(buffer);
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected String checkOneName(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkOneName(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_NAME) {
            int len = buffer.getInt();
            if (len != 1) {
                throw new SshException("SFTP error: received " + len + " names instead of 1");
            }
            String name = buffer.getString(), longName = null;
            if (version == SFTP_V3) {
                longName = buffer.getString();
            }
            Attributes attrs = readAttributes(buffer);
            if (log.isTraceEnabled()) {
                log.trace("checkOneName(id={}) ({})[{}]: {}", Integer.valueOf(id), name, longName, attrs);
            }
            return name;
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected Attributes readAttributes(Buffer buffer) throws IOException {
        Attributes attrs = new Attributes();
        int flags = buffer.getInt();
        if (version == SFTP_V3) {
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                attrs.flags.add(Attribute.Size);
                attrs.size = buffer.getLong();
            }
            if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
                attrs.flags.add(Attribute.UidGid);
                attrs.uid = buffer.getInt();
                attrs.gid = buffer.getInt();
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                attrs.flags.add(Attribute.Perms);
                attrs.perms = buffer.getInt();
            }
            if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                attrs.flags.add(Attribute.AcModTime);
                attrs.atime = buffer.getInt();
                attrs.mtime = buffer.getInt();
            }
        } else if (version >= SFTP_V4) {
            attrs.type = buffer.getUByte();
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                attrs.flags.add(Attribute.Size);
                attrs.size = buffer.getLong();
            }
            if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                attrs.flags.add(Attribute.OwnerGroup);
                attrs.owner = buffer.getString();
                attrs.group = buffer.getString();
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                attrs.flags.add(Attribute.Perms);
                attrs.perms = buffer.getInt();
            }
            
            // update the permissions according to the type
            switch (attrs.type) {
                case SSH_FILEXFER_TYPE_REGULAR:
                    attrs.perms |= S_IFREG;
                    break;
                case SSH_FILEXFER_TYPE_DIRECTORY:
                    attrs.perms |= S_IFDIR;
                    break;
                case SSH_FILEXFER_TYPE_SYMLINK:
                    attrs.perms |= S_IFLNK;
                    break;
                default:    // do nothing
            }

            if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                attrs.flags.add(Attribute.AccessTime);
                attrs.accessTime = readTime(buffer, flags);
                attrs.atime = (int) attrs.accessTime.to(TimeUnit.SECONDS);
            }
            if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                attrs.flags.add(Attribute.CreateTime);
                attrs.createTime = readTime(buffer, flags);
                attrs.ctime = (int) attrs.createTime.to(TimeUnit.SECONDS);
            }
            if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                attrs.flags.add(Attribute.ModifyTime);
                attrs.modifyTime = readTime(buffer, flags);
                attrs.mtime = (int) attrs.modifyTime.to(TimeUnit.SECONDS);
            }
            // TODO: acl
        } else {
            throw new IllegalStateException("readAttributes - unsupported version: " + version);
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

    protected void writeAttributes(Buffer buffer, Attributes attributes) throws IOException {
        if (version == SFTP_V3) {
            int flags = 0;
            for (Attribute a : attributes.flags) {
                switch (a) {
                    case Size:
                        flags |= SSH_FILEXFER_ATTR_SIZE;
                        break;
                    case UidGid:
                        flags |= SSH_FILEXFER_ATTR_UIDGID;
                        break;
                    case Perms:
                        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
                        break;
                    case AcModTime:
                        flags |= SSH_FILEXFER_ATTR_ACMODTIME;
                        break;
                    default:    // do nothing
                }
            }
            buffer.putInt(flags);
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(attributes.size);
            }
            if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
                buffer.putInt(attributes.uid);
                buffer.putInt(attributes.gid);
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributes.perms);
            }
            if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                buffer.putInt(attributes.atime);
                buffer.putInt(attributes.mtime);
            }
        } else if (version >= SFTP_V4) {
            int flags = 0;
            for (Attribute a : attributes.flags) {
                switch (a) {
                    case Size:
                        flags |= SSH_FILEXFER_ATTR_SIZE;
                        break;
                    case OwnerGroup:
                        flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
                        break;
                    case Perms:
                        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
                        break;
                    case AccessTime:
                        flags |= SSH_FILEXFER_ATTR_ACCESSTIME;
                        break;
                    case ModifyTime:
                        flags |= SSH_FILEXFER_ATTR_MODIFYTIME;
                        break;
                    case CreateTime:
                        flags |= SSH_FILEXFER_ATTR_CREATETIME;
                        break;
                    default:    // do nothing
                }
            }
            buffer.putInt(flags);
            buffer.putByte((byte) attributes.type);
            if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
                buffer.putLong(attributes.size);
            }
            if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                buffer.putString(attributes.owner != null ? attributes.owner : "OWNER@", StandardCharsets.UTF_8);
                buffer.putString(attributes.group != null ? attributes.group : "GROUP@", StandardCharsets.UTF_8);
            }
            if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                buffer.putInt(attributes.perms);
            }
            if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                buffer.putLong(attributes.accessTime.to(TimeUnit.SECONDS));
                if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
                    long nanos = attributes.accessTime.to(TimeUnit.NANOSECONDS);
                    nanos = nanos % TimeUnit.SECONDS.toNanos(1);
                    buffer.putInt((int) nanos);
                }
                buffer.putInt(attributes.atime);
            }
            if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                buffer.putLong(attributes.createTime.to(TimeUnit.SECONDS));
                if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
                    long nanos = attributes.createTime.to(TimeUnit.NANOSECONDS);
                    nanos = nanos % TimeUnit.SECONDS.toNanos(1);
                    buffer.putInt((int) nanos);
                }
                buffer.putInt(attributes.atime);
            }
            if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                buffer.putLong(attributes.modifyTime.to(TimeUnit.SECONDS));
                if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
                    long nanos = attributes.modifyTime.to(TimeUnit.NANOSECONDS);
                    nanos = nanos % TimeUnit.SECONDS.toNanos(1);
                    buffer.putInt((int) nanos);
                }
                buffer.putInt(attributes.atime);
            }
            // TODO: acl
        } else {
            throw new UnsupportedOperationException("writeAttributes(" + attributes + ") unsupported version: " + version);
        }
    }

    @Override
    public CloseableHandle open(String path, Collection<OpenMode> options) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */);
        buffer.putString(path);
        if (version == SFTP_V3) {
            int mode = 0;
            for (OpenMode m : options) {
                switch (m) {
                    case Read:
                        mode |= SSH_FXF_READ;
                        break;
                    case Write:
                        mode |= SSH_FXF_WRITE;
                        break;
                    case Append:
                        mode |= SSH_FXF_APPEND;
                        break;
                    case Create:
                        mode |= SSH_FXF_CREAT;
                        break;
                    case Truncate:
                        mode |= SSH_FXF_TRUNC;
                        break;
                    case Exclusive:
                        mode |= SSH_FXF_EXCL;
                        break;
                    default:    // do nothing
                }
            }
            buffer.putInt(mode);
        } else {
            int mode = 0;
            int access = 0;
            if (options.contains(OpenMode.Read)) {
                access |= ACE4_READ_DATA | ACE4_READ_ATTRIBUTES;
            }
            if (options.contains(OpenMode.Write)) {
                access |= ACE4_WRITE_DATA | ACE4_WRITE_ATTRIBUTES;
            }
            if (options.contains(OpenMode.Append)) {
                access |= ACE4_APPEND_DATA;
            }
            if (options.contains(OpenMode.Create) && options.contains(OpenMode.Exclusive)) {
                mode |= SSH_FXF_CREATE_NEW;
            } else if (options.contains(OpenMode.Create) && options.contains(OpenMode.Truncate)) {
                mode |= SSH_FXF_CREATE_TRUNCATE;
            } else if (options.contains(OpenMode.Create)) {
                mode |= SSH_FXF_OPEN_OR_CREATE;
            } else if (options.contains(OpenMode.Truncate)) {
                mode |= SSH_FXF_TRUNCATE_EXISTING;
            } else {
                mode |= SSH_FXF_OPEN_EXISTING;
            }
            if (version >= SFTP_V5) {
                buffer.putInt(access);
            }
            buffer.putInt(mode);
        }
        writeAttributes(buffer, new Attributes());
        return new DefaultCloseableHandle(this, checkHandle(receive(send(SSH_FXP_OPEN, buffer))));
    }

    @Override
    public void close(Handle handle) throws IOException {
        Buffer buffer = new ByteArrayBuffer(handle.id.length() + Long.SIZE /* some extra fields */);
        buffer.putString(handle.id);
        checkStatus(receive(send(SSH_FXP_CLOSE, buffer)));
    }

    @Override
    public void remove(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */);
        buffer.putString(path);
        checkStatus(receive(send(SSH_FXP_REMOVE, buffer)));
    }

    @Override
    public void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException {
        Buffer buffer = new ByteArrayBuffer(oldPath.length() + newPath.length() + Long.SIZE /* some extra fields */);
        buffer.putString(oldPath);
        buffer.putString(newPath);
        
        int numOptions = GenericUtils.size(options);
        if (version >= SFTP_V5) {
            int opts = 0;
            if (numOptions > 0) {
                for (CopyMode opt : options) {
                    switch (opt) {
                        case Atomic:
                            opts |= SSH_FXP_RENAME_ATOMIC;
                            break;
                        case Overwrite:
                            opts |= SSH_FXP_RENAME_OVERWRITE;
                            break;
                        default:    // do nothing
                    }
                }
            }
            buffer.putInt(opts);
        } else if (numOptions > 0) {
            throw new UnsupportedOperationException("rename(" + oldPath + " => " + newPath + ")"
                                                  + " - copy options can not be used with this SFTP version: " + options);
        }
        checkStatus(receive(send(SSH_FXP_RENAME, buffer)));
    }

    @Override
    public int read(Handle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException {
        Buffer buffer = new ByteArrayBuffer(handle.id.length() + Long.SIZE /* some extra fields */);
        buffer.putString(handle.id);
        buffer.putLong(fileOffset);
        buffer.putInt(len);
        return checkData(receive(send(SSH_FXP_READ, buffer)), dstoff, dst);
    }

    protected int checkData(Buffer buffer, int dstoff, byte[] dst) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkData(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }

            if (substatus == SSH_FX_EOF) {
                return -1;
            }

            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_DATA) {
            int len = buffer.getInt();
            buffer.getRawBytes(dst, dstoff, len);
            return len;
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    @Override
    public void write(Handle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException {
        // do some bounds checking first
        if ((fileOffset < 0) || (srcoff < 0) || (len < 0)) {
            throw new IllegalArgumentException("write(" + handle + ") please ensure all parameters "
                                             + " are non-negative values: file-offset=" + fileOffset
                                             + ", src-offset=" + srcoff + ", len=" + len);
        }
        if ((srcoff + len) > src.length) {
            throw new IllegalArgumentException("write(" + handle + ")"
                                             + " cannot read bytes " + srcoff + " to " + (srcoff + len)
                                             + " when array is only of length " + src.length);
        }

        Buffer buffer = new ByteArrayBuffer(handle.id.length() + len + Long.SIZE /* some extra fields */);
        buffer.putString(handle.id);
        buffer.putLong(fileOffset);
        buffer.putBytes(src, srcoff, len);
        checkStatus(receive(send(SSH_FXP_WRITE, buffer)));
    }

    @Override
    public void mkdir(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() +  Long.SIZE /* some extra fields */);
        buffer.putString(path, StandardCharsets.UTF_8);
        buffer.putInt(0);
        if (version != SFTP_V3) {
            buffer.putByte((byte) 0);
        }
        checkStatus(receive(send(SSH_FXP_MKDIR, buffer)));
    }

    @Override
    public void rmdir(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() +  Long.SIZE /* some extra fields */);
        buffer.putString(path);
        checkStatus(receive(send(SSH_FXP_RMDIR, buffer)));
    }

    @Override
    public CloseableHandle openDir(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */);
        buffer.putString(path);
        return new DefaultCloseableHandle(this, checkHandle(receive(send(SSH_FXP_OPENDIR, buffer))));
    }

    @Override
    public DirEntry[] readDir(Handle handle) throws IOException {
        Buffer buffer = new ByteArrayBuffer(handle.id.length() + Long.SIZE /* some extra fields */);
        buffer.putString(handle.id);
        return checkDir(receive(send(SSH_FXP_READDIR, buffer)));
    }

    protected DirEntry[] checkDir(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isTraceEnabled()) {
                log.trace("checkDir(id={}) - status: {} [{}] {}", Integer.valueOf(id), Integer.valueOf(substatus), lang, msg);
            }
            if (substatus == SSH_FX_EOF) {
                return null;
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_NAME) {
            int len = buffer.getInt();
            DirEntry[] entries = new DirEntry[len];
            for (int i = 0; i < len; i++) {
                String name = buffer.getString();
                String longName = (version == SFTP_V3) ? buffer.getString() : null;
                Attributes attrs = readAttributes(buffer);
                if (log.isTraceEnabled()) {
                    log.trace("checkDir(id={})[{}] ({})[{}]: {}", Integer.valueOf(id), Integer.valueOf(i), name, longName, attrs);
                }

                entries[i] = new DirEntry(name, longName, attrs);
            }
            return entries;
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    @Override
    public String canonicalPath(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(path);
        return checkOneName(receive(send(SSH_FXP_REALPATH, buffer)));
    }

    @Override
    public Attributes stat(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(path);
        if (version >= SFTP_V4) {
            buffer.putInt(SSH_FILEXFER_ATTR_ALL);
        }
        return checkAttributes(receive(send(SSH_FXP_STAT, buffer)));
    }

    @Override
    public Attributes lstat(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(path);
        if (version >= SFTP_V4) {
            buffer.putInt(SSH_FILEXFER_ATTR_ALL);
        }
        return checkAttributes(receive(send(SSH_FXP_LSTAT, buffer)));
    }

    @Override
    public Attributes stat(Handle handle) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(handle.id);
        if (version >= SFTP_V4) {
            buffer.putInt(SSH_FILEXFER_ATTR_ALL);
        }
        return checkAttributes(receive(send(SSH_FXP_FSTAT, buffer)));
    }

    @Override
    public void setStat(String path, Attributes attributes) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(path);
        writeAttributes(buffer, attributes);
        checkStatus(receive(send(SSH_FXP_SETSTAT, buffer)));
    }

    @Override
    public void setStat(Handle handle, Attributes attributes) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(handle.id);
        writeAttributes(buffer, attributes);
        checkStatus(receive(send(SSH_FXP_FSETSTAT, buffer)));
    }

    @Override
    public String readLink(String path) throws IOException {
        Buffer buffer = new ByteArrayBuffer(path.length() + Long.SIZE /* some extra fields */);
        buffer.putString(path);
        return checkOneName(receive(send(SSH_FXP_READLINK, buffer)));
    }

    @Override
    public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
        Buffer buffer = new ByteArrayBuffer(linkPath.length() + targetPath.length() + Long.SIZE /* some extra fields */);
        if (version < SFTP_V6) {
            if (!symbolic) {
                throw new UnsupportedOperationException("Hard links are not supported in sftp v" + version);
            }
            buffer.putString(targetPath);
            buffer.putString(linkPath);
            checkStatus(receive(send(SSH_FXP_SYMLINK, buffer)));
        } else {
            buffer.putString(targetPath);
            buffer.putString(linkPath);
            buffer.putBoolean(symbolic);
            checkStatus(receive(send(SSH_FXP_LINK, buffer)));
        }
    }

    @Override
    public void lock(Handle handle, long offset, long length, int mask) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(handle.id);
        buffer.putLong(offset);
        buffer.putLong(length);
        buffer.putInt(mask);
        checkStatus(receive(send(SSH_FXP_BLOCK, buffer)));
    }

    @Override
    public void unlock(Handle handle, long offset, long length) throws IOException {
        Buffer buffer = new ByteArrayBuffer();
        buffer.putString(handle.id);
        buffer.putLong(offset);
        buffer.putLong(length);
        checkStatus(receive(send(SSH_FXP_UNBLOCK, buffer)));
    }

    @Override
    public Iterable<DirEntry> readDir(final String path) throws IOException {
        return new Iterable<DirEntry>() {
            @Override
            public Iterator<DirEntry> iterator() {
                return new Iterator<DirEntry>() {
                    private CloseableHandle handle;
                    private DirEntry[] entries;
                    private int index;

                    {
                        open();
                        load();
                    }

                    @Override
                    public boolean hasNext() {
                        return (entries != null) && (index < entries.length);
                    }

                    @Override
                    public DirEntry next() {
                        DirEntry entry = entries[index++];
                        if (index >= entries.length) {
                            load();
                        }
                        return entry;
                    }

                    @SuppressWarnings("synthetic-access")
                    private void open() {
                        try {
                            handle = openDir(path);
                            if (log.isDebugEnabled()) {
                                log.debug("readDir(" + path + ") handle=" + handle);
                            }
                        } catch (IOException e) {
                            if (log.isDebugEnabled()) {
                                log.debug("readDir(" + path + ") failed (" + e.getClass().getSimpleName() + ") to open dir: " + e.getMessage());
                            }
                            throw new RuntimeException(e);
                        }
                    }

                    @SuppressWarnings("synthetic-access")
                    private void load() {
                        try {
                            entries = readDir(handle);
                            index = 0;
                            if (entries == null) {
                                handle.close();
                            }
                        } catch (IOException e) {
                            entries = null;
                            try {
                                handle.close();
                            } catch (IOException t) {
                                if (log.isTraceEnabled()) {
                                    log.trace(t.getClass().getSimpleName() + " while close handle=" + handle
                                            + " due to " + e.getClass().getSimpleName() + " [" + e.getMessage() + "]"
                                            + ": " + t.getMessage());
                                }
                            }
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public void remove() {
                        throw new UnsupportedOperationException("readDir(" + path + ") Iterator#remove() N/A");
                    }
                };
            }
        };
    }

    @Override
    public InputStream read(final String path, final int bufferSize, final Collection<OpenMode> mode) throws IOException {
        if (bufferSize < MIN_READ_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient read buffer size: " + bufferSize + ", min.=" + MIN_READ_BUFFER_SIZE);
        }

        return new InputStreamWithChannel() {
            private byte[] bb = new byte[1];
            private byte[] buffer = new byte[bufferSize];
            private int index;
            private int available;
            private CloseableHandle handle = DefaultSftpClient.this.open(path, mode);
            private long offset;

            @Override
            public boolean isOpen() {
                return (handle != null) && handle.isOpen();
            }

            @Override
            public int read() throws IOException {
                int read = read(bb, 0, 1);
                if (read > 0) {
                    return bb[0];
                }

                return read;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (!isOpen()) {
                    throw new IOException("read(" + path + ") stream closed");
                }

                int idx = off;
                while (len > 0) {
                    if (index >= available) {
                        available = DefaultSftpClient.this.read(handle, offset, buffer, 0, buffer.length);
                        if (available < 0) {
                            if (idx == off) {
                                return -1;
                            } else {
                                break;
                            }
                        }
                        offset += available;
                        index = 0;
                    }
                    if (index >= available) {
                        break;
                    }
                    int nb = Math.min(len, available - index);
                    System.arraycopy(buffer, index, b, idx, nb);
                    index += nb;
                    idx += nb;
                    len -= nb;
                }
                return idx - off;
            }

            @Override
            public void close() throws IOException {
                if (isOpen()) {
                    try {
                        handle.close();
                    } finally {
                        handle = null;
                    }
                }
            }
        };
    }

    @Override
    public OutputStream write(final String path, final int bufferSize, final Collection<OpenMode> mode) throws IOException {
        if (bufferSize < MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException("Insufficient write buffer size: " + bufferSize + ", min.=" + MIN_WRITE_BUFFER_SIZE);
        }

        return new OutputStreamWithChannel() {
            private byte[] bb = new byte[1];
            private byte[] buffer = new byte[bufferSize];
            private int index;
            private CloseableHandle handle = DefaultSftpClient.this.open(path, mode);
            private long offset;

            @Override
            public boolean isOpen() {
                return (handle != null) && handle.isOpen();
            }

            @Override
            public void write(int b) throws IOException {
                bb[0] = (byte) b;
                write(bb, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (!isOpen()) {
                    throw new IOException("write(" + path + ")[len=" + len + "] stream is closed");
                }

                do {
                    int nb = Math.min(len, buffer.length - index);
                    System.arraycopy(b, off, buffer, index, nb);
                    index += nb;
                    if (index == buffer.length) {
                        flush();
                    }
                    off += nb;
                    len -= nb;
                } while (len > 0);
            }

            @Override
            public void flush() throws IOException {
                if (!isOpen()) {
                    throw new IOException("flush(" + path + ") stream is closed");
                }

                DefaultSftpClient.this.write(handle, offset, buffer, 0, index);
                offset += index;
                index = 0;
            }

            @Override
            public void close() throws IOException {
                if (isOpen()) {
                    try {
                        try {
                            if (index > 0) {
                                flush();
                            }
                        } finally {
                            handle.close();
                        }
                    } finally {
                        handle = null;
                    }
                }
            }
        };
    }
}
