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
package org.apache.sshd.server.scp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.scp.ScpClient.Option;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpLocation;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;

/**
 * This commands provide SCP support on both server and client side.
 * Permissions and preservation of access / modification times on files
 * are not supported.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommand extends AbstractLoggingBean implements Command, Runnable, FileSystemAware {
    protected String name;
    protected boolean optR;
    protected boolean optT;
    protected boolean optF;
    protected boolean optD;
    protected boolean optP; // TODO: handle modification times
    protected FileSystem fileSystem;
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
    protected ScpTransferEventListener listener;

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
     * @param eventListener   An {@link ScpTransferEventListener} - may be {@code null}
     * @see ThreadUtils#newSingleThreadExecutor(String)
     * @see ScpHelper#MIN_SEND_BUFFER_SIZE
     * @see ScpHelper#MIN_RECEIVE_BUFFER_SIZE
     */
    public ScpCommand(String command, ExecutorService executorService, boolean shutdownOnExit, int sendSize, int receiveSize, ScpTransferEventListener eventListener) {
        name = command;

        if (executorService == null) {
            String poolName = command.replace(' ', '_').replace('/', ':');
            executors = ThreadUtils.newSingleThreadExecutor(poolName);
            shutdownExecutor = true;    // we always close the ad-hoc executor service
        } else {
            executors = executorService;
            shutdownExecutor = shutdownOnExit;
        }

        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommmand>(" + command + ") send buffer size "
                    + "(" + sendSize + ") below minimum required "
                    + "(" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }
        sendBufferSize = sendSize;

        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommmand>(" + command + ") receive buffer size "
                    + "(" + sendSize + ") below minimum required "
                    + "(" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;

        listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;

        if (log.isDebugEnabled()) {
            log.debug("Executing command {}", command);
        }
        String[] args = command.split(" ");
        for (int i = 1; i < args.length; i++) {
            String argVal = args[i];
            if (argVal.charAt(0) == '-') {
                for (int j = 1; j < argVal.length(); j++) {
                    char option = argVal.charAt(j);
                    switch (option) {
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
                        default:  // ignored
//                            error = new IOException("Unsupported option: " + args[i].charAt(j));
//                            return;
                    }
                }
            } else {
                String prevArg = args[i - 1];
                path = command.substring(command.indexOf(prevArg) + prevArg.length() + 1);
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
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void setFileSystem(FileSystem fs) {
        this.fileSystem = fs;
    }

    @Override
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

    @Override
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

        if ((executors != null) && (!executors.isShutdown()) && shutdownExecutor) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("destroy() - shutdown executor service - runners count=" + runners.size());
            }
        }

        executors = null;

        try {
            fileSystem.close();
        } catch (UnsupportedOperationException e) {
            // Ignore
        } catch (IOException e) {
            log.debug("Error closing FileSystem", e);
        }
    }

    @Override
    public void run() {
        int exitValue = ScpHelper.OK;
        String exitMessage = null;
        ScpHelper helper = new ScpHelper(in, out, fileSystem, listener);
        try {
            if (optT) {
                helper.receive(helper.resolveLocalPath(path), optR, optD, optP, receiveBufferSize);
            } else if (optF) {
                helper.send(Collections.singletonList(path), optR, optP, sendBufferSize);
            } else {
                throw new IOException("Unsupported mode");
            }
        } catch (IOException e) {
            try {
                exitValue = ScpHelper.ERROR;
                exitMessage = GenericUtils.trimToEmpty(e.getMessage());
                out.write(exitValue);
                out.write(exitMessage.getBytes(StandardCharsets.UTF_8));
                out.write('\n');
                out.flush();
            } catch (IOException e2) {
                // Ignore
            }

            if (log.isDebugEnabled()) {
                log.debug("Error ({}) in scp command={}: {}", e.getClass().getSimpleName(), name, e.getMessage());
            }
        } finally {
            if (callback != null) {
                callback.onExit(exitValue, GenericUtils.trimToEmpty(exitMessage));
            }
        }
    }

    @Override
    public String toString() {
        return name;
    }

    //////////////////////////////////////////////////////////////////////////

    private static boolean showError(PrintStream stderr, String message) {
        stderr.println(message);
        return true;
    }

    private static String[] normalizeCommandArguments(PrintStream stdout, PrintStream stderr, String ... args) {
        int numArgs = GenericUtils.length(args);
        if (numArgs <= 0) {
            return args;
        }

        List<String> effective = new ArrayList<String>(numArgs);
        boolean error = false;
        for (int index = 0; (index < numArgs) && (!error); index++) {
            String argName = args[index];
            if ("-i".equals(argName) || "-P".equals(argName) || "-o".equals(argName)) {
                if ((index + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                effective.add(argName);
                effective.add(args[++index]);
            } else if ("-r".equals(argName) || "-p".equals(argName) || "-q".equals(argName)) {
                effective.add(argName);
            } else if (argName.charAt(0) == '-') {
                error = showError(stderr, "Unknown option: " + argName);
                break;
            } else {
                if ((index + 1) >= numArgs) {
                    error = showError(stderr, "Not enough arguments");
                    break;
                }

                ScpLocation source = new ScpLocation(argName);
                ScpLocation target = new ScpLocation(args[++index]);
                if (index < (numArgs - 1)) {
                    error = showError(stderr, "Unexpected extra arguments");
                    break;
                }

                if (source.isLocal() == target.isLocal()) {
                    error = showError(stderr, "Both targets are either remote or local");
                    break;
                }

                ScpLocation remote = source.isLocal() ? target : source;
                effective.add(remote.resolveUsername() + "@" + remote.getHost());
                effective.add(source.toString());
                effective.add(target.toString());
                break;
            }
        }

        if (error) {
            return null;
        }

        return effective.toArray(new String[effective.size()]);
    }

    public static void main(String[] args) throws Exception {
        final PrintStream stdout = System.out;
        final PrintStream stderr = System.err;
        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(new NoCloseInputStream(System.in)))) {
            args = normalizeCommandArguments(stdout, stderr, args);

            ClientSession session = GenericUtils.isEmpty(args) ? null : SshClient.setupClientSession("-P", stdin, stdout, stderr, args);
            if (session == null) {
                stderr.println("usage: scp [-P port] [-i identity] [-r] [-p] [-q] [-o option=value] <source> <target>");
                stderr.println();
                stderr.println("Where <source> or <target> are either 'user@host:file' or a local file path");
                stderr.println("NOTE: exactly ONE of the source or target must be remote and the other one local");
                System.exit(-1);
                return; // not that we really need it...
            }

            try {
                // see the way normalizeCommandArguments works...
                int numArgs = GenericUtils.length(args);
                Collection<Option> options = EnumSet.noneOf(Option.class);
                final AtomicBoolean quietHolder = new AtomicBoolean(false);
                for (int index = 0; index < numArgs; index++) {
                    String argName = args[index];
                    if ("-r".equals(argName)) {
                        options.add(Option.Recursive);
                    } else if ("-p".equals(argName)) {
                        options.add(Option.PreserveAttributes);
                    } else if ("-q".equals(argName)) {
                        quietHolder.set(true);
                    }
                }

                ScpLocation source = new ScpLocation(args[numArgs - 2]);
                ScpLocation target = new ScpLocation(args[numArgs - 1]);

                ScpClient client = session.createScpClient(new ScpTransferEventListener() {
                    @Override
                    public void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms) {
                        logEvent("startFolderEvent", op, file, -1L, perms, null);
                    }

                    @Override
                    public void endFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown) {
                        logEvent("endFolderEvent", op, file, -1L, perms, thrown);
                    }

                    @Override
                    public void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
                        logEvent("startFileEvent", op, file, length, perms, null);
                    }

                    @Override
                    public void endFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown) {
                        logEvent("endFileEvent", op, file, length, perms, thrown);
                    }

                    private void logEvent(String name, FileOperation op, Path file, long length, Collection<PosixFilePermission> perms, Throwable thrown) {
                        if (quietHolder.get()) {
                            return;
                        }

                        PrintStream ps = (thrown == null) ? stdout : stderr;
                        ps.append('\t').append(name).append('[').append(op.name()).append(']').append(' ').append(file.toString());
                        if (length > 0L) {
                            ps.append(' ').append("length=").append(Long.toString(length));
                        }
                        ps.append(' ').append(String.valueOf(perms));

                        if (thrown != null) {
                            ps.append(" - ").append(thrown.getClass().getSimpleName()).append(": ").append(thrown.getMessage());
                        }
                        ps.println();
                    }
                });

                if (source.isLocal()) {
                    client.upload(source.getPath(), target.getPath(), options);
                } else {
                    client.download(source.getPath(), target.getPath(), options);
                }
            } finally {
                session.close();
            }
        }
    }
}
