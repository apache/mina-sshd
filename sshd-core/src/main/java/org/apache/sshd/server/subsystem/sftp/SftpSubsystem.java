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
package org.apache.sshd.server.subsystem.sftp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.session.ServerSession;

/**
 * SFTP subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystem extends AbstractSftpSubsystemExecutor implements Command, Runnable {
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected Environment env;
    protected Future<?> pendingFuture;


    /**
     * @param executorService The {@link ExecutorService} to be used by
     *                        the {@link SftpSubsystem} command when starting execution. If
     *                        {@code null} then a single-threaded ad-hoc service is used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when subsystem terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @param policy          The {@link UnsupportedAttributePolicy} to use if failed to access
     *                        some local file attributes
     * @param accessor        The {@link SftpFileSystemAccessor} to use for opening files and directories
     * @param errorStatusDataHandler The (never {@code null}) {@link SftpErrorStatusDataHandler} to
     * use when generating failed commands error messages
     * @see ThreadUtils#newSingleThreadExecutor(String)
     */
    public SftpSubsystem(ExecutorService executorService, boolean shutdownOnExit, UnsupportedAttributePolicy policy,
            SftpFileSystemAccessor accessor, SftpErrorStatusDataHandler errorStatusDataHandler) {
        super(executorService, shutdownOnExit, policy, accessor, errorStatusDataHandler);
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
            ExecutorService executor = getExecutorService();

            if (executor == null) {
                executor = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
                if (log.isDebugEnabled()) {
                    log.debug("start() - created internal single-threaded executor");
                }

                setExecutorService(executor);
                setShutdownOnExit(true);
            }

            pendingFuture = executor.submit(this);
        } catch (RuntimeException e) {    // e.g., RejectedExecutionException
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start command: " + e.toString(), e);
            throw new IOException(e);
        }
    }

    @Override
    public void run() {
        try {
            for (long count = 1L;; count++) {
                Buffer command = readCommand(in, count);
                Buffer reply = process(command);
                if (command != reply) {
                    continue;   // debug breakpoint
                }
            }
        } catch (Throwable t) {
            if ((!closed.get()) && (!(t instanceof EOFException))) { // Ignore
                ServerSession session = getServerSession();
                log.error("run({}) {} caught in SFTP subsystem: {}",
                      session, t.getClass().getSimpleName(), t.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("run(" + session + ") caught exception details", t);
                }
            }
        } finally {
            closeAllHandles();
            onExit(0);
        }
    }

    protected Buffer readCommand(InputStream stream, long cmdIndex) throws IOException {
        byte[] workBuf = getTemporaryWorkBuffer(Integer.BYTES);
        int length = BufferUtils.readInt(stream, workBuf, 0, workBuf.length);
        ValidateUtils.checkTrue(length >= (Integer.BYTES + 1 /* command */), "Bad length to read: %d", length);

        Buffer buffer = new ByteArrayBuffer(length + Integer.BYTES + Long.SIZE /* a bit extra */, false);
        buffer.putInt(length);
        for (int remainLen = length; remainLen > 0;) {
            int l = stream.read(buffer.array(), buffer.wpos(), remainLen);
            if (l < 0) {
                throw new StreamCorruptedException("Premature EOF at buffer #" + cmdIndex + " while read length=" + length + " and remain=" + remainLen);
            }
            buffer.wpos(buffer.wpos() + l);
            remainLen -= l;
        }

        return buffer;
    }

    @Override
    protected <B extends Buffer> B send(B buffer) throws IOException {
        int len = buffer.available();
        byte[] workBuf = getTemporaryWorkBuffer(Integer.BYTES);
        BufferUtils.writeInt(out, len, workBuf, 0, workBuf.length);
        out.write(buffer.array(), buffer.rpos(), len);
        out.flush();
        return buffer;
    }

    @Override
    protected void doDestroy() {
        ServerSession session = getServerSession();
        boolean debugEnabled = log.isDebugEnabled();

        // if thread has not completed, cancel it
        if ((pendingFuture != null) && (!pendingFuture.isDone())) {
            boolean result = pendingFuture.cancel(true);
            // TODO consider waiting some reasonable (?) amount of time for cancellation
            if (debugEnabled) {
                log.debug("destroy(" + session + ") - cancel pending future=" + result);
            }
        }

        pendingFuture = null;

        ExecutorService executors = getExecutorService();
        if ((executors != null) && (!executors.isShutdown()) && isShutdownOnExit()) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (debugEnabled) {
                log.debug("destroy(" + session + ") - shutdown executor service - runners count=" + runners.size());
            }
        }
        setExecutorService(null);
    }
}
