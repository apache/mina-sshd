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
package org.apache.sshd.server.command;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.util.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This commands provide SCP support on both server and client side.
 * Permissions and preservation of access / modification times on files
 * are not supported.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommand implements Command, Runnable, FileSystemAware {

    protected static final Logger log = LoggerFactory.getLogger(ScpCommand.class);

    protected String name;
    protected boolean optR;
    protected boolean optT;
    protected boolean optF;
    protected boolean optD;
    protected boolean optP; // TODO: handle modification times
    protected FileSystemView root;
    protected String path;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected ExitCallback callback;
    protected IOException error;
    protected ExecutorService executors;
    protected boolean shutdownExecutor;
    protected Future<?> pendingFuture;
    protected int sendBufferSize;
    protected int receiveBufferSize;

    /**
     * Simple constructor - uses an ad-hoc {@link ExecutorService} to
     * run the command as well as default send / receive buffer sizes
     *
     * @param command The command to be executed
     * @see #ScpCommand(String, ExecutorService, boolean, int, int)
     * @see ScpHelper#DEFAULT_COPY_BUFFER_SIZE
     */
    public ScpCommand(String command) {
        this(command, ScpHelper.DEFAULT_COPY_BUFFER_SIZE);
    }

    /**
     * Uses an ad-hoc {@link ExecutorService} to run the command
     *
     * @param command    The command to be executed
     * @param bufferSize Size (in bytes) of buffer to be used for <U>both</U>
     *                   sending and receiving files
     * @see #ScpCommand(String, ExecutorService, int)
     */
    public ScpCommand(String command, int bufferSize) {
        this(command, null, bufferSize);
    }

    /**
     * @param command         The command to be executed
     * @param executorService An {@link ExecutorService} to be used when
     *                        {@link #start(Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used. <B>Note:</B> the
     *                        executor service will <U>not</U> be shutdown when command terminates
     *                        unless it is the ad-hoc service
     * @param bufferSize      Size (in bytes) of buffer to be used for <U>both</U>
     *                        sending and receiving files
     * @see #ScpCommand(String, ExecutorService, boolean, int, int)
     */
    public ScpCommand(String command, ExecutorService executorService, int bufferSize) {
        this(command, executorService, false, bufferSize);
    }

    /**
     * @param command         The command to be executed
     * @param executorService An {@link ExecutorService} to be used when
     *                        {@link #start(Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used. <B>Note:</B> the
     *                        executor service will <U>not</U> be shutdown when command terminates
     *                        unless it is the ad-hoc service
     * @see #ScpCommand(String, ExecutorService, boolean, int)
     */
    public ScpCommand(String command, ExecutorService executorService) {
        this(command, executorService, false);
    }

    /**
     * @param command         The command to be executed
     * @param executorService An {@link ExecutorService} to be used when
     *                        {@link #start(Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when command terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @see #ScpCommand(String, ExecutorService, boolean, int)
     * @see ScpHelper#DEFAULT_COPY_BUFFER_SIZE
     */
    public ScpCommand(String command, ExecutorService executorService, boolean shutdownOnExit) {
        this(command, executorService, false, ScpHelper.DEFAULT_COPY_BUFFER_SIZE);
    }

    /**
     * @param command         The command to be executed
     * @param executorService An {@link ExecutorService} to be used when
     *                        {@link #start(Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when command terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @param bufferSize      Size (in bytes) of buffer to be used for <U>both</U>
     *                        sending and receiving files
     * @see #ScpCommand(String, ExecutorService, boolean, int, int)
     */
    public ScpCommand(String command, ExecutorService executorService, boolean shutdownOnExit, int bufferSize) {
        this(command, executorService, shutdownOnExit, bufferSize, bufferSize);
    }

    /**
     * @param command         The command to be executed
     * @param executorService An {@link ExecutorService} to be used when
     *                        {@link #start(Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()}
     *                        will be called when command terminates - unless it is the ad-hoc
     *                        service, which will be shutdown regardless
     * @param sendSize        Size (in bytes) of buffer to use when sending files
     * @param receiveSize     Size (in bytes) of buffer to use when receiving files
     * @see ThreadUtils#newSingleThreadExecutor(String)
     * @see ScpHelper#MIN_SEND_BUFFER_SIZE
     * @see ScpHelper#MIN_RECEIVE_BUFFER_SIZE
     */
    public ScpCommand(String command, ExecutorService executorService, boolean shutdownOnExit, int sendSize, int receiveSize) {
        name = command;

        if ((executors = executorService) == null) {
            String poolName = command.replace(' ', '_').replace('/', ':');
            executors = ThreadUtils.newSingleThreadExecutor(poolName);
            shutdownExecutor = true;    // we always close the ad-hoc executor service
        } else {
            shutdownExecutor = shutdownOnExit;
        }

        if ((sendBufferSize = sendSize) < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommmand>(" + command + ") send buffer size (" + sendSize + ") below minimum required (" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }

        if ((receiveBufferSize = receiveSize) < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommmand>(" + command + ") receive buffer size (" + sendSize + ") below minimum required (" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        log.debug("Executing command {}", command);
        String[] args = command.split(" ");
        for (int i = 1; i < args.length; i++) {
            if (args[i].charAt(0) == '-') {
                for (int j = 1; j < args[i].length(); j++) {
                    switch (args[i].charAt(j)) {
                        case 'f':
                            optF = true;
                            break;
                        case 'p':
                            optP = true;
                            break;
                        case 'r':
                            optR = true;
                            break;
                        case 't':
                            optT = true;
                            break;
                        case 'd':
                            optD = true;
                            break;
//                          default:
//                            error = new IOException("Unsupported option: " + args[i].charAt(j));
//                            return;
                    }
                }
            } else {
                path = command.substring(command.indexOf(args[i - 1]) + args[i - 1].length() + 1);
                if (path.startsWith("\"") && path.endsWith("\"") || path.startsWith("'") && path.endsWith("'")) {
                    path = path.substring(1, path.length() - 1);
                }
                break;
            }
        }
        if (!optF && !optT) {
            error = new IOException("Either -f or -t option should be set for " + command);
        }
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

    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    public void setFileSystemView(FileSystemView view) {
        this.root = view;
    }

    public void start(Environment env) throws IOException {
        if (error != null) {
            throw error;
        }

        try {
            pendingFuture = executors.submit(this);
        } catch (RuntimeException e) {    // e.g., RejectedExecutionException
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start command=" + name + ": " + e.getMessage(), e);
            throw new IOException(e);
        }
    }

    public void destroy() {
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
    }

    public void run() {
        int exitValue = ScpHelper.OK;
        String exitMessage = null;
        ScpHelper helper = new ScpHelper(in, out, root);
        try {
            if (optT) {
                helper.receive(root.getFile(path), optR, optD, optP, receiveBufferSize);
            } else if (optF) {
                helper.send(Collections.singletonList(path), optR, optP, sendBufferSize);
            } else {
                throw new IOException("Unsupported mode");
            }
        } catch (IOException e) {
            try {
                exitValue = ScpHelper.ERROR;
                exitMessage = e.getMessage() == null ? "" : e.getMessage();
                out.write(exitValue);
                out.write(exitMessage.getBytes());
                out.write('\n');
                out.flush();
            } catch (IOException e2) {
                // Ignore
            }
            log.info("Error in scp command=" + name, e);
        } finally {
            if (callback != null) {
                callback.onExit(exitValue, exitMessage);
            }
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
