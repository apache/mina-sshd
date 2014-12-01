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
package org.apache.sshd.client.sftp;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.SftpException;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSftpClient implements SftpClient {

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

    private final ClientSession clientSession;
    private final ChannelSubsystem channel;
    private final Map<Integer, Buffer> messages;
    private final AtomicInteger cmdId = new AtomicInteger(100);
    private final Buffer receiveBuffer = new Buffer();
    private boolean closing;

    public DefaultSftpClient(ClientSession clientSession) throws IOException {
        this.clientSession = clientSession;
        this.channel = clientSession.createSubsystemChannel("sftp");
        this.messages = new HashMap<Integer, Buffer>();
        try {
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
            this.channel.setErr(new ByteArrayOutputStream());
            this.channel.open().await();
        } catch (InterruptedException e) {
            throw (IOException) new InterruptedIOException().initCause(e);
        }
        this.channel.onClose(new Runnable() {
            public void run() {
                synchronized (messages) {
                    closing = true;
                    messages.notifyAll();
                }
            }
        });
        init();
    }

    public void close() throws IOException {
        this.channel.close(false);
    }

    /**
     * Receive binary data
     */
    protected int data(byte[] buf, int start, int len) throws IOException {
        Buffer incoming = new Buffer(buf,  start, len);
        // If we already have partial data, we need to append it to the buffer and use it
        if (receiveBuffer.available() > 0) {
            receiveBuffer.putBuffer(incoming);
            incoming = receiveBuffer;
        }
        // Process commands
        int rpos = incoming.rpos();
        while (receive(incoming));
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

    /**
     * Process an SFTP packet
     */
    protected void process(Buffer incoming) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putBuffer(incoming);
        buffer.rpos(5);
        int id = buffer.getInt();
        buffer.rpos(0);
        synchronized (messages) {
            messages.put(id, buffer);
            messages.notifyAll();
        }
    }


    protected int send(int cmd, Buffer buffer) throws IOException {
        int id = cmdId.incrementAndGet();
        DataOutputStream dos = new DataOutputStream(channel.getInvertedIn());
        dos.writeInt(5 + buffer.available());
        dos.writeByte(cmd);
        dos.writeInt(id);
        dos.write(buffer.array(), buffer.rpos(), buffer.available());
        dos.flush();
        return id;
    }

    protected Buffer receive(int id) throws IOException {
        synchronized (messages) {
            while (true) {
                if (closing) {
                    throw new SshException("Channel has been closed");
                }
                Buffer buffer = messages.remove(id);
                if (buffer != null) {
                    return buffer;
                }
                try {
                    messages.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            }
        }
    }

    protected Buffer read() throws IOException {
        DataInputStream dis = new DataInputStream(channel.getInvertedOut());
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
        return buffer;
    }

    protected void init() throws IOException {
        // Init packet
        DataOutputStream dos = new DataOutputStream(channel.getInvertedIn());
        dos.writeInt(5);
        dos.writeByte(SSH_FXP_INIT);
        dos.writeInt(3);
        dos.flush();
        Buffer buffer = null;
        synchronized (messages) {
            while (messages.isEmpty()) {
                try {
                    messages.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            }
            buffer = messages.remove(messages.keySet().iterator().next());

        }
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_VERSION) {
            if (id != 3) {
                throw new SshException("Unable to use SFTP v3, server replied with version " + id);
            }
        } else if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            throw new SftpException(substatus, msg);
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    protected void checkStatus(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (substatus != SSH_FX_OK) {
                throw new SftpException(substatus, msg);
            }
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    protected Handle checkHandle(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_HANDLE) {
            String handle = buffer.getString();
            return new Handle(handle);
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    protected Attributes checkAttributes(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_ATTRS) {
            return readAttributes(buffer);
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    protected String checkOneName(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_NAME) {
            int len = buffer.getInt();
            if (len != 1) {
                throw new SshException("SFTP error: received " + len + " names instead of 1");
            }
            String name = buffer.getString();
            String longName = buffer.getString();
            Attributes attrs = readAttributes(buffer);
            return name;
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    protected Attributes readAttributes(Buffer buffer) throws IOException {
        Attributes attrs = new Attributes();
        int flags = buffer.getInt();
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
        return attrs;
    }

    protected void writeAttributes(Buffer buffer, Attributes attributes) throws IOException {
        int flags = 0;
        for (Attribute a : attributes.flags) {
            switch (a) {
                case Size:      flags |= SSH_FILEXFER_ATTR_SIZE; break;
                case UidGid:    flags |= SSH_FILEXFER_ATTR_UIDGID; break;
                case Perms:     flags |= SSH_FILEXFER_ATTR_PERMISSIONS; break;
                case AcModTime: flags |= SSH_FILEXFER_ATTR_ACMODTIME; break;
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
    }

    public Handle open(String path, EnumSet<OpenMode> options) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        int mode = 0;
        for (OpenMode m : options) {
            switch (m) {
                case Read:      mode |= SSH_FXF_READ; break;
                case Write:     mode |= SSH_FXF_WRITE; break;
                case Append:    mode |= SSH_FXF_APPEND; break;
                case Create:    mode |= SSH_FXF_CREAT; break;
                case Truncate:  mode |= SSH_FXF_TRUNC; break;
                case Exclusive: mode |= SSH_FXF_EXCL; break;
            }
        }
        buffer.putInt(mode);
        buffer.putInt(0);
        return checkHandle(receive(send(SSH_FXP_OPEN, buffer)));
    }

    public void close(Handle handle) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        checkStatus(receive(send(SSH_FXP_CLOSE, buffer)));
    }

    public void remove(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        checkStatus(receive(send(SSH_FXP_REMOVE, buffer)));
    }

    public void rename(String oldPath, String newPath) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(oldPath);
        buffer.putString(newPath);
        checkStatus(receive(send(SSH_FXP_RENAME, buffer)));
    }

    public int read(Handle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        buffer.putLong(fileOffset);
        buffer.putInt(len);
        return checkData(receive(send(SSH_FXP_READ, buffer)), dstoff, dst);
    }

    protected int checkData(Buffer buffer, int dstoff, byte[] dst) throws IOException {
        int len;
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (substatus == SSH_FX_EOF) {
                return -1;
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_DATA) {
            len = buffer.getInt();
            buffer.getRawBytes(dst, dstoff, len);
            return len;
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    public void write(Handle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException {
        // do some bounds checking first
        if (fileOffset < 0 || srcoff < 0 || len < 0) {
            throw new IllegalArgumentException("please ensure all parameters are non-negative values");
        }
        if (srcoff + len > src.length) {
            throw new IllegalArgumentException("cannot read bytes " + srcoff + " to " + (srcoff + len) + " when array is only of length " + src.length);
        }
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        buffer.putLong(fileOffset);
        buffer.putBytes(src, srcoff, len);
        checkStatus(receive(send(SSH_FXP_WRITE, buffer)));
    }

    public void mkdir(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        buffer.putInt(0);
        checkStatus(receive(send(SSH_FXP_MKDIR, buffer)));
    }

    public void rmdir(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        checkStatus(receive(send(SSH_FXP_RMDIR, buffer)));
    }

    public Handle openDir(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        return checkHandle(receive(send(SSH_FXP_OPENDIR, buffer)));
    }

    public DirEntry[] readDir(Handle handle) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        return checkDir(receive(send(SSH_FXP_READDIR, buffer)));
    }

    protected DirEntry[] checkDir(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getByte();
        int id = buffer.getInt();
        if (type == SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (substatus == SSH_FX_EOF) {
                return null;
            }
            throw new SftpException(substatus, msg);
        } else if (type == SSH_FXP_NAME) {
            int len = buffer.getInt();
            DirEntry[] entries = new DirEntry[len];
            for (int i = 0; i < len; i++) {
                String name = buffer.getString();
                String longName = buffer.getString();
                Attributes attrs = readAttributes(buffer);
                entries[i] = new DirEntry(name, longName, attrs);
            }
            return entries;
        } else {
            throw new SshException("Unexpected SFTP packet received: " + type);
        }
    }

    public String canonicalPath(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        return checkOneName(receive(send(SSH_FXP_REALPATH, buffer)));
    }

    public Attributes stat(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        return checkAttributes(receive(send(SSH_FXP_STAT, buffer)));
    }

    public Attributes lstat(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        return checkAttributes(receive(send(SSH_FXP_LSTAT, buffer)));
    }

    public Attributes stat(Handle handle) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        return checkAttributes(receive(send(SSH_FXP_FSTAT, buffer)));
    }

    public void setStat(String path, Attributes attributes) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        writeAttributes(buffer, attributes);
        checkStatus(receive(send(SSH_FXP_SETSTAT, buffer)));
    }

    public void setStat(Handle handle, Attributes attributes) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(handle.id);
        writeAttributes(buffer, attributes);
        checkStatus(receive(send(SSH_FXP_FSETSTAT, buffer)));
    }

    public String readLink(String path) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(path);
        return checkOneName(receive(send(SSH_FXP_READLINK, buffer)));
    }

    public void symLink(String linkPath, String targetPath) throws IOException {
        Buffer buffer = new Buffer();
        buffer.putString(linkPath);
        buffer.putString(targetPath);
        checkStatus(receive(send(SSH_FXP_SYMLINK, buffer)));
    }

    public Iterable<DirEntry> readDir(final String path) throws IOException {
        return new Iterable<DirEntry>() {
            public Iterator<DirEntry> iterator() {
                return new Iterator<DirEntry>() {
                    Handle handle;
                    DirEntry[] entries;
                    int index;
                    {
                        open();
                        load();
                    }
                    public boolean hasNext() {
                        return entries != null && index < entries.length;
                    }
                    public DirEntry next() {
                        DirEntry entry = entries[index++];
                        if (index >= entries.length) {
                            load();
                        }
                        return entry;
                    }
                    private void open() {
                        try {
                            handle = openDir(path);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    private void load() {
                        try {
                            entries = readDir(handle);
                            index = 0;
                            if (entries == null) {
                                close(handle);
                            }
                        } catch (IOException e) {
                            entries = null;
                            try {
                                close(handle);
                            } catch (IOException t) {
                                // Ignore
                            }
                            throw new RuntimeException(e);
                        }
                    }
                    public void remove() {
                        throw new UnsupportedOperationException();
                    }
                };
            }
        };
    }

    public InputStream read(final String path) throws IOException {
        return read(path, EnumSet.of(OpenMode.Read));
    }

    public InputStream read(final String path, final EnumSet<OpenMode> mode) throws IOException {
        return new InputStream() {
            byte[] buffer = new byte[32 * 1024];
            int index = 0;
            int available = 0;
            Handle handle = DefaultSftpClient.this.open(path, mode);
            long offset;
            @Override
            public int read() throws IOException {
                byte[] buffer = new byte[1];
                int read = read(buffer, 0, 1);
                if (read > 0) {
                    return buffer[0];
                }
                return read;
            }
            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (handle == null) {
                    throw new IOException("Stream closed");
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
                if (handle != null) {
                    DefaultSftpClient.this.close(handle);
                    handle = null;
                }
            }
        };
    }

    public OutputStream write(final String path) throws IOException {
        return write(path, EnumSet.of(OpenMode.Write, OpenMode.Create, OpenMode.Truncate));
    }

    public OutputStream write(final String path, final EnumSet<OpenMode> mode) throws IOException {
        return new OutputStream() {
            byte[] buffer = new byte[32 * 1024];
            int index = 0;
            Handle handle = DefaultSftpClient.this.open(path, mode);
            long offset;
            @Override
            public void write(int b) throws IOException {
                byte[] buffer = new byte[1];
                buffer[0] = (byte) b;
                write(buffer, 0, 1);
            }
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
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
                DefaultSftpClient.this.write(handle, offset, buffer, 0, index);
                offset += index;
                index = 0;
            }
            @Override
            public void close() throws IOException {
                if (index > 0) {
                    flush();
                }
                DefaultSftpClient.this.close(handle);
            }
        };
    }

}
