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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.SftpException;

public class SftpFileChannel extends FileChannel {

    final SftpPath p;
    final EnumSet<SftpClient.OpenMode> modes;
    final SftpClient sftp;
    final SftpClient.Handle handle;
    final Object lock;
    volatile long pos;
    volatile Thread blockingThread;

    public SftpFileChannel(SftpPath p, EnumSet<SftpClient.OpenMode> modes) throws IOException {
        this.p = p;
        this.modes = modes;
        sftp = p.getFileSystem().getClient();
        handle = sftp.open(p.toString(), modes);
        lock = new Object();
        pos = 0;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        return (int) doRead(Collections.singletonList(dst), -1);
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException();
        }
        return (int) doRead(Collections.singletonList(dst), position);
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        List<ByteBuffer> buffers = Arrays.asList(dsts).subList(offset, offset + length);
        return doRead(buffers, -1);
    }

    protected long doRead(List<ByteBuffer> buffers, long position) throws IOException {
        ensureOpen();
        synchronized (lock) {
            boolean completed = false;
            boolean eof = false;
            long curPos = position >= 0 ? position : pos;
            try {
                long totalRead = 0;
                beginBlocking();
                loop:
                for (ByteBuffer buffer : buffers) {
                    while (buffer.remaining() > 0) {
                        ByteBuffer wrap = buffer;
                        if (!buffer.hasArray()) {
                            wrap = ByteBuffer.allocate(Math.min(8192, buffer.remaining()));
                        }
                        int read = sftp.read(handle, curPos, wrap.array(), wrap.arrayOffset() + wrap.position(), wrap.remaining());
                        if (read > 0) {
                            if (wrap == buffer) {
                                wrap.position(wrap.position() + read);
                            } else {
                                buffer.put(wrap.array(), wrap.arrayOffset(), read);
                            }
                            curPos += read;
                            totalRead += read;
                        } else {
                            eof = read == -1;
                            break loop;
                        }
                    }
                }
                completed = true;
                return totalRead > 0 ? totalRead : eof ? -1 : 0;
            } finally {
                if (position < 0) {
                    pos = curPos;
                }
                endBlocking(completed);
            }
        }
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        return (int) doWrite(Collections.singletonList(src), -1);
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException();
        }
        return (int) doWrite(Collections.singletonList(src), position);
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        List<ByteBuffer> buffers = Arrays.asList(srcs).subList(offset, offset + length);
        return doWrite(buffers, -1);
    }

    protected long doWrite(List<ByteBuffer> buffers, long position) throws IOException {
        ensureOpen();
        synchronized (lock) {
            boolean completed = false;
            long curPos = position >= 0 ? position : pos;
            try {
                long totalWritten = 0;
                beginBlocking();
                for (ByteBuffer buffer : buffers) {
                    while (buffer.remaining() > 0) {
                        ByteBuffer wrap = buffer;
                        if (!buffer.hasArray()) {
                            wrap = ByteBuffer.allocate(Math.min(8192, buffer.remaining()));
                            buffer.get(wrap.array(), wrap.arrayOffset(), wrap.remaining());
                        }
                        int written = wrap.remaining();
                        sftp.write(handle, curPos, wrap.array(), wrap.arrayOffset() + wrap.position(), written);
                        if (wrap == buffer) {
                            wrap.position(wrap.position() + written);
                        }
                        curPos += written;
                        totalWritten += written;
                    }
                }
                completed = true;
                return totalWritten;
            } finally {
                if (position < 0) {
                    pos = curPos;
                }
                endBlocking(completed);
            }
        }
    }

    @Override
    public long position() throws IOException {
        ensureOpen();
        return pos;
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        if (newPosition < 0) {
            throw new IllegalArgumentException();
        }
        ensureOpen();
        synchronized (lock) {
            pos = newPosition;
            return this;
        }
    }

    @Override
    public long size() throws IOException {
        return sftp.stat(handle).size;
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        sftp.setStat(handle, new SftpClient.Attributes().size(size));
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        if (position < 0 || count < 0) {
            throw new IllegalArgumentException();
        }
        ensureOpen();
        synchronized (lock) {
            boolean completed = false;
            boolean eof = false;
            long curPos = position;
            try {
                long totalRead = 0;
                beginBlocking();

                byte[] buffer = new byte[32768];
                while (totalRead < count) {
                    int read = sftp.read(handle, curPos, buffer, 0, buffer.length);
                    if (read > 0) {
                        ByteBuffer wrap = ByteBuffer.wrap(buffer);
                        while (wrap.remaining() > 0) {
                            target.write(wrap);
                        }
                        curPos += read;
                        totalRead += read;
                    } else {
                        eof = read == -1;
                    }
                }
                completed = true;
                return totalRead > 0 ? totalRead : eof ? -1 : 0;
            } finally {
                endBlocking(completed);
            }
        }
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        if (position < 0 || count < 0) {
            throw new IllegalArgumentException();
        }
        ensureOpen();
        synchronized (lock) {
            boolean completed = false;
            long curPos = position >= 0 ? position : pos;
            try {
                long totalRead = 0;
                beginBlocking();

                byte[] buffer = new byte[32768];
                while (totalRead < count) {
                    ByteBuffer wrap = ByteBuffer.wrap(buffer, 0, (int) Math.min(buffer.length, count - totalRead));
                    int read = src.read(wrap);
                    if (read > 0) {
                        sftp.write(handle, curPos, buffer, 0, read);
                        curPos += read;
                        totalRead += read;
                    } else {
                        break;
                    }
                }
                completed = true;
                return totalRead;
            } finally {
                endBlocking(completed);
            }
        }
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        return tryLock(position, size, shared);
    }

    @Override
    public FileLock tryLock(final long position, final long size, boolean shared) throws IOException {
        try {
            sftp.lock(handle, position, size, 0);
        } catch (SftpException e) {
            if (e.getStatus() == DefaultSftpClient.SSH_FX_LOCK_CONFLICT) {
                throw new OverlappingFileLockException();
            }
            throw e;
        }
        return new FileLock(this, position, size, shared) {

            private final AtomicBoolean valid = new AtomicBoolean(true);

            @Override
            public boolean isValid() {
                return acquiredBy().isOpen() && valid.get();
            }

            @Override
            public void release() throws IOException {
                if (valid.compareAndSet(true, false)) {
                    sftp.unlock(handle, position, size);
                }
            }
        };
    }

    @Override
    protected void implCloseChannel() throws IOException {
        try {
            final Thread thread = blockingThread;
            if (thread != null) {
                thread.interrupt();
            }
        } finally {
            try {
                sftp.close(handle);
            } finally {
                sftp.close();
            }
        }
    }

    private void beginBlocking() {
        begin();
        blockingThread = Thread.currentThread();
    }

    private void endBlocking(boolean completed) throws AsynchronousCloseException {
        blockingThread = null;
        end(completed);
    }

    private void ensureOpen() throws IOException {
        if (!isOpen()) {
            throw new ClosedChannelException();
        }
    }
}
