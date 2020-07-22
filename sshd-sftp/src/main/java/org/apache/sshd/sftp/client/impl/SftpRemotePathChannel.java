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

package org.apache.sshd.sftp.client.impl;

import java.io.IOException;
import java.io.StreamCorruptedException;
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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpRemotePathChannel extends FileChannel {

    public static final Set<OpenMode> READ_MODES = Collections.unmodifiableSet(EnumSet.of(OpenMode.Read));

    public static final Set<OpenMode> WRITE_MODES = Collections.unmodifiableSet(
            EnumSet.of(OpenMode.Write, OpenMode.Append, OpenMode.Create, OpenMode.Truncate));

    protected final Logger log;
    protected final Collection<OpenMode> modes;
    protected final boolean closeOnExit;
    protected final SftpClient sftp;
    protected final SftpClient.CloseableHandle handle;
    protected final Object lock = new Object();
    protected final AtomicLong posTracker = new AtomicLong(0L);
    protected final AtomicReference<Thread> blockingThreadHolder = new AtomicReference<>(null);

    private final String path;

    public SftpRemotePathChannel(String path, SftpClient sftp, boolean closeOnExit,
                                 Collection<OpenMode> modes) throws IOException {
        this.log = LoggerFactory.getLogger(getClass());
        this.path = ValidateUtils.checkNotNullAndNotEmpty(path, "No remote file path specified");
        this.modes = Objects.requireNonNull(modes, "No channel modes specified");
        this.sftp = Objects.requireNonNull(sftp, "No SFTP client instance");
        this.closeOnExit = closeOnExit;
        this.handle = sftp.open(path, modes);
    }

    public String getRemotePath() {
        return path;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        long totalRead = doRead(Collections.singletonList(dst), -1L);
        if (totalRead >= Integer.MAX_VALUE) {
            throw new StreamCorruptedException("Total read size exceeds integer: " + totalRead);
        }
        return (int) totalRead;
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        if (position < 0L) {
            throw new IllegalArgumentException(
                    "read(" + getRemotePath() + ")"
                                               + " illegal position to read from: " + position);
        }

        long totalRead = doRead(Collections.singletonList(dst), position);
        if (totalRead >= Integer.MAX_VALUE) {
            throw new StreamCorruptedException("Total read size exceeds integer: " + totalRead);
        }
        return (int) totalRead;
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        Collection<ByteBuffer> buffers = Arrays.asList(dsts)
                .subList(offset, offset + length);
        return doRead(buffers, -1L);
    }

    protected long doRead(Collection<? extends ByteBuffer> buffers, long position) throws IOException {
        ensureOpen(READ_MODES);

        ClientSession clientSession = sftp.getClientSession();
        int copySize = SftpModuleProperties.COPY_BUF_SIZE.getRequired(clientSession);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doRead({})[position={}] fill {} buffers using copySize={}",
                    this, position, buffers.size(), copySize);
        }

        boolean completed = false;
        boolean eof = false;
        long totalRead = 0;
        int numBufsUsed = 0;

        synchronized (lock) {
            long curPos = (position >= 0L) ? position : posTracker.get();
            try {
                beginBlocking("doRead");

                loop: for (ByteBuffer buffer : buffers) {
                    numBufsUsed++;

                    while (buffer.remaining() > 0) {
                        ByteBuffer wrap = buffer;
                        if (!buffer.hasArray()) {
                            wrap = ByteBuffer.allocate(Math.min(copySize, buffer.remaining()));
                        }

                        int read = sftp.read(handle, curPos, wrap.array(),
                                wrap.arrayOffset() + wrap.position(), wrap.remaining());
                        if (read > 0) {
                            // reference equality on purpose
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
            } finally {
                if (position < 0L) {
                    posTracker.set(curPos);
                }
                endBlocking("doRead", completed);
            }
        }

        if (debugEnabled) {
            log.debug("doRead({})[position={}] filled {}/{} with copySize={} - totalRead={}, completed={}, eof={}",
                    this, position, numBufsUsed, buffers.size(), copySize, totalRead, completed, eof);
        }

        if (totalRead > 0L) {
            return totalRead;
        }

        if (eof) {
            return -1L;
        } else {
            return 0L;
        }
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        long totalWritten = doWrite(Collections.singletonList(src), -1L);
        if (totalWritten >= Integer.MAX_VALUE) {
            throw new StreamCorruptedException("Total written size exceeds integer: " + totalWritten);
        }

        return (int) totalWritten;
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        if (position < 0L) {
            throw new IllegalArgumentException(
                    "write(" + getRemotePath() + ")"
                                               + " illegal position to write to: " + position);
        }

        long totalWritten = doWrite(Collections.singletonList(src), position);
        if (totalWritten >= Integer.MAX_VALUE) {
            throw new StreamCorruptedException("Total written size exceeds integer: " + totalWritten);
        }

        return (int) totalWritten;
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        Collection<ByteBuffer> buffers = Arrays.asList(srcs)
                .subList(offset, offset + length);
        return doWrite(buffers, -1L);
    }

    protected long doWrite(Collection<? extends ByteBuffer> buffers, long position) throws IOException {
        ensureOpen(WRITE_MODES);

        ClientSession clientSession = sftp.getClientSession();
        int copySize = SftpModuleProperties.COPY_BUF_SIZE.getRequired(clientSession);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doWrite({})[position={}] write {} buffers using copySize={}",
                    this, position, buffers.size(), copySize);
        }

        boolean completed = false;
        long totalWritten = 0L;
        int numBufsUsed = 0;

        synchronized (lock) {
            long curPos = (position >= 0L) ? position : posTracker.get();
            try {
                beginBlocking("doWrite");

                for (ByteBuffer buffer : buffers) {
                    numBufsUsed++;

                    while (buffer.remaining() > 0) {
                        ByteBuffer wrap = buffer;
                        if (!buffer.hasArray()) {
                            wrap = ByteBuffer.allocate(Math.min(copySize, buffer.remaining()));
                            buffer.get(wrap.array(), wrap.arrayOffset(), wrap.remaining());
                        }

                        int written = wrap.remaining();
                        sftp.write(handle, curPos, wrap.array(),
                                wrap.arrayOffset() + wrap.position(), written);
                        // reference equality on purpose
                        if (wrap == buffer) {
                            wrap.position(wrap.position() + written);
                        }
                        curPos += written;
                        totalWritten += written;
                    }
                }
                completed = true;
            } finally {
                if (position < 0L) {
                    posTracker.set(curPos);
                }
                endBlocking("doWrite", completed);
            }
        }

        if (debugEnabled) {
            log.debug("doWrite({})[position={}] used {}/{} with copySize={} - totalWritten={}, completed={}",
                    this, position, numBufsUsed, buffers.size(), copySize, totalWritten, completed);
        }

        return totalWritten;
    }

    @Override
    public long position() throws IOException {
        ensureOpen(Collections.emptySet());
        return posTracker.get();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        if (newPosition < 0L) {
            throw new IllegalArgumentException(
                    "position(" + getRemotePath() + ")"
                                               + " illegal file channel position: " + newPosition);
        }

        ensureOpen(Collections.emptySet());
        posTracker.set(newPosition);
        return this;
    }

    @Override
    public long size() throws IOException {
        ensureOpen(Collections.emptySet());
        Attributes stat = sftp.stat(handle);
        return stat.getSize();
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen(Collections.emptySet());
        sftp.setStat(handle, new SftpClient.Attributes().size(size));
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        ensureOpen(Collections.emptySet());
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        if ((position < 0L) || (count < 0L)) {
            throw new IllegalArgumentException(
                    "transferTo(" + getRemotePath() + ")"
                                               + " illegal position (" + position + ") or count (" + count + ")");
        }
        ensureOpen(READ_MODES);

        ClientSession clientSession = sftp.getClientSession();
        int copySize = SftpModuleProperties.COPY_BUF_SIZE.getRequired(clientSession);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("transferTo({})[position={}, count={}] use copySize={} for target={}",
                    this, position, count, copySize, target);
        }

        boolean completed = false;
        boolean eof;
        long totalRead;

        synchronized (lock) {
            try {
                beginBlocking("transferTo");

                // DO NOT CLOSE THE STREAM AS IT WOULD CLOSE THE HANDLE
                @SuppressWarnings("resource")
                SftpInputStreamAsync input = new SftpInputStreamAsync(
                        (AbstractSftpClient) sftp,
                        copySize, position, count, getRemotePath(), handle);
                totalRead = input.transferTo(count, target);
                eof = input.isEof();
                completed = true;
            } finally {
                endBlocking("transferTo", completed);
            }
        }

        if (debugEnabled) {
            log.debug("transferTo({})[position={}, count={}] with copySize={} - totalRead={}, eo{} for target={}",
                    this, position, count, copySize, totalRead, eof, target);
        }

        return (totalRead > 0L) ? totalRead : eof ? -1L : 0L;
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        if ((position < 0L) || (count < 0L)) {
            throw new IllegalArgumentException(
                    "transferFrom(" + getRemotePath() + ")"
                                               + " illegal position (" + position + ") or count (" + count + ")");
        }
        ensureOpen(WRITE_MODES);

        ClientSession clientSession = sftp.getClientSession();
        int copySize = SftpModuleProperties.COPY_BUF_SIZE.getRequired(clientSession);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("transferFrom({})[position={}, count={}] use copySize={} for source={}",
                    this, position, count, copySize, src);
        }

        boolean completed = false;
        long totalRead = 0L;
        byte[] buffer = new byte[(int) Math.min(copySize, count)];

        synchronized (lock) {
            try {
                beginBlocking("transferFrom");

                // DO NOT CLOSE THE OUTPUT STREAM AS IT WOULD CLOSE THE HANDLE
                @SuppressWarnings("resource")
                SftpOutputStreamAsync output = new SftpOutputStreamAsync(
                        (AbstractSftpClient) sftp,
                        copySize, getRemotePath(), handle);
                while (totalRead < count) {
                    ByteBuffer wrap = ByteBuffer.wrap(
                            buffer, 0, (int) Math.min(buffer.length, count - totalRead));
                    int read = src.read(wrap);
                    if (read > 0) {
                        output.write(buffer, 0, read);
                        totalRead += read;
                    } else {
                        break;
                    }
                }
                output.flush();
                // DO NOT CLOSE THE OUTPUT STREAM AS IT WOULD CLOSE THE HANDLE
                completed = true;
            } finally {
                endBlocking("transferFrom", completed);
            }
        }

        if (debugEnabled) {
            log.debug("transferFrom({})[position={}, count={}] use copySize={} - totalRead={}, completed={} for source={}",
                    this, position, count, copySize, totalRead, completed, src);
        }
        return totalRead;
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        throw new UnsupportedOperationException(
                "map(" + getRemotePath() + ")[" + mode + "," + position + "," + size + "] N/A");
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        return tryLock(position, size, shared);
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        ensureOpen(Collections.emptySet());

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
        if (log.isDebugEnabled()) {
            log.debug("implCloseChannel({}) closeOnExit={}", this, closeOnExit);
        }

        try {
            Thread thread = blockingThreadHolder.get();
            if (thread != null) {
                thread.interrupt();
            }
        } finally {
            try {
                handle.close();
            } finally {
                if (closeOnExit) {
                    sftp.close();
                }
            }
        }
    }

    protected void beginBlocking(Object actionHint) {
        if (log.isDebugEnabled()) {
            log.debug("beginBlocking({})[{}]", this, actionHint);
        }

        begin();
        blockingThreadHolder.set(Thread.currentThread());
    }

    protected void endBlocking(Object actionHint, boolean completed)
            throws AsynchronousCloseException {
        if (log.isDebugEnabled()) {
            log.debug("endBlocking({})[{}] completed={}", this, actionHint, completed);
        }

        blockingThreadHolder.set(null);
        end(completed);
    }

    /**
     * Checks that the channel is open and that its current mode contains at least one of the required ones
     *
     * @param  reqModes    The required modes - ignored if {@code null}/empty
     * @throws IOException If channel not open or the required modes are not satisfied
     */
    private void ensureOpen(Collection<OpenMode> reqModes) throws IOException {
        if (!isOpen()) {
            throw new ClosedChannelException();
        }

        if (GenericUtils.size(reqModes) > 0) {
            for (OpenMode m : reqModes) {
                if (this.modes.contains(m)) {
                    return;
                }
            }

            throw new IOException(
                    "ensureOpen(" + getRemotePath() + ")"
                                  + " current channel modes (" + this.modes + ")"
                                  + " do contain any of the required ones: " + reqModes);
        }
    }

    @Override
    public String toString() {
        return getRemotePath();
    }
}
