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
package org.apache.sshd.client.subsystem.sftp;

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
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

public class SftpFileChannel extends FileChannel {
    public static final String COPY_BUFSIZE_PROP = "sftp-channel-copy-buf-size";
    public static final int DEFAULT_TRANSFER_BUFFER_SIZE = IoUtils.DEFAULT_COPY_SIZE;

    public static final Set<SftpClient.OpenMode> READ_MODES =
            Collections.unmodifiableSet(EnumSet.of(SftpClient.OpenMode.Read));

    public static final Set<SftpClient.OpenMode> WRITE_MODES =
            Collections.unmodifiableSet(
                    EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Append, SftpClient.OpenMode.Create, SftpClient.OpenMode.Truncate));

    private final SftpPath p;
    private final Collection<SftpClient.OpenMode> modes;
    private final SftpClient sftp;
    private final SftpClient.CloseableHandle handle;
    private final Object lock = new Object();
    private final AtomicLong posTracker = new AtomicLong(0L);
    private final AtomicReference<Thread> blockingThreadHolder = new AtomicReference<>(null);

    public SftpFileChannel(SftpPath p, Collection<SftpClient.OpenMode> modes) throws IOException {
        this.p = ValidateUtils.checkNotNull(p, "No target path");
        this.modes = ValidateUtils.checkNotNull(modes, "No channel modes specified");

        SftpFileSystem fs = p.getFileSystem();
        sftp = fs.getClient();
        handle = sftp.open(p.toString(), modes);
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        return (int) doRead(Collections.singletonList(dst), -1);
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("read(" + p + ") illegal position to read from: " + position);
        }
        return (int) doRead(Collections.singletonList(dst), position);
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        List<ByteBuffer> buffers = Arrays.asList(dsts).subList(offset, offset + length);
        return doRead(buffers, -1);
    }

    protected long doRead(List<ByteBuffer> buffers, long position) throws IOException {
        ensureOpen(READ_MODES);
        synchronized (lock) {
            boolean completed = false;
            boolean eof = false;
            long curPos = (position >= 0L) ? position : posTracker.get();
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
                if (totalRead > 0) {
                    return totalRead;
                }

                if (eof) {
                    return -1;
                } else {
                    return 0;
                }
            } finally {
                if (position < 0L) {
                    posTracker.set(curPos);
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
            throw new IllegalArgumentException("write(" + p + ") illegal position to write to: " + position);
        }
        return (int) doWrite(Collections.singletonList(src), position);
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        List<ByteBuffer> buffers = Arrays.asList(srcs).subList(offset, offset + length);
        return doWrite(buffers, -1);
    }

    protected long doWrite(List<ByteBuffer> buffers, long position) throws IOException {
        ensureOpen(WRITE_MODES);
        synchronized (lock) {
            boolean completed = false;
            long curPos = (position >= 0L) ? position : posTracker.get();
            try {
                long totalWritten = 0L;
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
                if (position < 0L) {
                    posTracker.set(curPos);
                }
                endBlocking(completed);
            }
        }
    }

    @Override
    public long position() throws IOException {
        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());
        return posTracker.get();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        if (newPosition < 0L) {
            throw new IllegalArgumentException("position(" + p + ") illegal file channel position: " + newPosition);
        }

        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());
        posTracker.set(newPosition);
        return this;
    }

    @Override
    public long size() throws IOException {
        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());
        return sftp.stat(handle).getSize();
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());
        sftp.setStat(handle, new SftpClient.Attributes().size(size));
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        if ((position < 0) || (count < 0)) {
            throw new IllegalArgumentException("transferTo(" + p + ") illegal position (" + position + ") or count (" + count + ")");
        }
        ensureOpen(READ_MODES);
        synchronized (lock) {
            boolean completed = false;
            boolean eof = false;
            long curPos = position;
            try {
                beginBlocking();

                int bufSize = (int) Math.min(count, 32768);
                byte[] buffer = new byte[bufSize];
                long totalRead = 0L;
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
        if ((position < 0) || (count < 0)) {
            throw new IllegalArgumentException("transferFrom(" + p + ") illegal position (" + position + ") or count (" + count + ")");
        }
        ensureOpen(WRITE_MODES);

        int copySize = PropertyResolverUtils.getIntProperty(sftp.getClientSession(), COPY_BUFSIZE_PROP, DEFAULT_TRANSFER_BUFFER_SIZE);
        boolean completed = false;
        long curPos = (position >= 0L) ? position : posTracker.get();
        long totalRead = 0L;
        byte[] buffer = new byte[(int) Math.min(copySize, count)];

        synchronized (lock) {
            try {
                beginBlocking();

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
        throw new UnsupportedOperationException("map(" + p + ")[" + mode + "," + position + "," + size + "] N/A");
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        return tryLock(position, size, shared);
    }

    @Override
    public FileLock tryLock(final long position, final long size, boolean shared) throws IOException {
        ensureOpen(Collections.<SftpClient.OpenMode>emptySet());

        try {
            sftp.lock(handle, position, size, 0);
        } catch (SftpException e) {
            if (e.getStatus() == SftpConstants.SSH_FX_LOCK_CONFLICT) {
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

            @SuppressWarnings("synthetic-access")
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
            final Thread thread = blockingThreadHolder.get();
            if (thread != null) {
                thread.interrupt();
            }
        } finally {
            try {
                handle.close();
            } finally {
                sftp.close();
            }
        }
    }

    private void beginBlocking() {
        begin();
        blockingThreadHolder.set(Thread.currentThread());
    }

    private void endBlocking(boolean completed) throws AsynchronousCloseException {
        blockingThreadHolder.set(null);
        end(completed);
    }

    /**
     * Checks that the channel is open and that its current mode contains
     * at least one of the required ones
     *
     * @param reqModes The required modes - ignored if {@code null}/empty
     * @throws IOException If channel not open or the required modes are not
     *                     satisfied
     */
    private void ensureOpen(Collection<SftpClient.OpenMode> reqModes) throws IOException {
        if (!isOpen()) {
            throw new ClosedChannelException();
        }

        if (GenericUtils.size(reqModes) > 0) {
            for (SftpClient.OpenMode m : reqModes) {
                if (this.modes.contains(m)) {
                    return;
                }
            }

            throw new IOException("ensureOpen(" + p + ") current channel modes (" + this.modes + ") do contain any of the required: " + reqModes);
        }
    }

    @Override
    public String toString() {
        return Objects.toString(p);
    }
}
