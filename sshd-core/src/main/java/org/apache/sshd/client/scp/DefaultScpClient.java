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
package org.apache.sshd.client.scp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.util.MockFileSystem;
import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpLocation;
import org.apache.sshd.common.scp.ScpTimestamp;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.scp.helpers.DefaultScpFileOpener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpClient extends AbstractScpClient {
    /**
     * Command line option used to indicate a non-default port
     */
    public static final String SCP_PORT_OPTION = "-P";

    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;
    private final ClientSession clientSession;

    public DefaultScpClient(ClientSession clientSession, ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        this.clientSession = ValidateUtils.checkNotNull(clientSession, "No client session");
        this.opener = (fileOpener == null) ? DefaultScpFileOpener.INSTANCE : fileOpener;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public void download(String remote, OutputStream local) throws IOException {
        String cmd = createReceiveCommand(remote, Collections.<Option>emptyList());
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            // NOTE: we use a mock file system since we expect no invocations for it
            ScpHelper helper = new ScpHelper(session, invOut, invIn, new MockFileSystem(remote), opener, listener);
            helper.receiveFileStream(local, ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException {
        String cmd = createReceiveCommand(remote, options);
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            ScpHelper helper = new ScpHelper(session, invOut, invIn, fs, opener, listener);
            helper.receive(local,
                    options.contains(Option.Recursive),
                    options.contains(Option.TargetIsDirectory),
                    options.contains(Option.PreserveAttributes),
                    ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    public void upload(final InputStream local, final String remote, final long size, final Collection<PosixFilePermission> perms, final ScpTimestamp time) throws IOException {
        int namePos = ValidateUtils.checkNotNullAndNotEmpty(remote, "No remote location specified").lastIndexOf('/');
        final String name = (namePos < 0)
                ? remote
                : ValidateUtils.checkNotNullAndNotEmpty(remote.substring(namePos + 1), "No name value in remote=%s", remote);
        final String cmd = createSendCommand(remote, (time != null) ? EnumSet.of(Option.PreserveAttributes) : Collections.<Option>emptySet());
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            // NOTE: we use a mock file system since we expect no invocations for it
            ScpHelper helper = new ScpHelper(session, invOut, invIn, new MockFileSystem(remote), opener, listener);
            final Path mockPath = new MockPath(remote);
            helper.sendStream(new DefaultScpStreamResolver(name, mockPath, perms, time, size, local, cmd),
                              time != null, ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected <T> void runUpload(String remote, Collection<Option> options, Collection<T> local, AbstractScpClient.ScpOperationExecutor<T> executor) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", remote);
        if (local.size() > 1) {
            options = addTargetIsDirectory(options);
        }

        String cmd = createSendCommand(remote, options);
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try {
            FactoryManager manager = session.getFactoryManager();
            FileSystemFactory factory = manager.getFileSystemFactory();
            FileSystem fs = factory.createFileSystem(session);

            try (InputStream invOut = channel.getInvertedOut();
                 OutputStream invIn = channel.getInvertedIn()) {
                ScpHelper helper = new ScpHelper(session, invOut, invIn, fs, opener, listener);
                executor.execute(helper, local, options);
            } finally {
                try {
                    fs.close();
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("runUpload({}) {} => {} - failed ({}) to close file system={}: {}",
                                  session, remote, local, e.getClass().getSimpleName(), fs, e.getMessage());
                    }
                }
            }
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
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
            // handled by 'setupClientSession'
            if (SshClient.isArgumentedOption(SCP_PORT_OPTION, argName)) {
                if ((index + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                effective.add(argName);
                effective.add(args[++index]);
            } else if ("-r".equals(argName) || "-p".equals(argName)
                    || "-q".equals(argName) || "-C".equals(argName)
                    || "-v".equals(argName) || "-vv".equals(argName) || "-vvv".equals(argName)) {
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
        OutputStream logStream = stdout;
        try (BufferedReader stdin = new BufferedReader(new InputStreamReader(new NoCloseInputStream(System.in)))) {
            args = normalizeCommandArguments(stdout, stderr, args);
            int numArgs = GenericUtils.length(args);
            // see the way normalizeCommandArguments works...
            if (numArgs >= 2) {
                Level level = SshClient.resolveLoggingVerbosity(args, numArgs - 2);
                logStream = SshClient.resolveLoggingTargetStream(stdout, stderr, args, numArgs - 2);
                if (logStream != null) {
                    SshClient.setupLogging(level, stdout, stderr, logStream);
                }
            }

            ClientSession session = (logStream == null) || GenericUtils.isEmpty(args)
                    ? null : SshClient.setupClientSession(SCP_PORT_OPTION, stdin, stdout, stderr, args);
            if (session == null) {
                stderr.println("usage: scp [" + SCP_PORT_OPTION + " port] [-i identity]"
                         + " [-v[v][v]] [-E logoutput] [-r] [-p] [-q] [-o option=value]"
                         + " [-c cipherlist] [-m maclist] [-w password] [-C] <source> <target>");
                stderr.println();
                stderr.println("Where <source> or <target> are either 'user@host:file' or a local file path");
                stderr.println("NOTE: exactly ONE of the source or target must be remote and the other one local");
                System.exit(-1);
                return; // not that we really need it...
            }

            try {
                // see the way normalizeCommandArguments works...
                Collection<Option> options = EnumSet.noneOf(Option.class);
                boolean quiet = false;
                for (int index = 0; index < numArgs; index++) {
                    String argName = args[index];
                    if ("-r".equals(argName)) {
                        options.add(Option.Recursive);
                    } else if ("-p".equals(argName)) {
                        options.add(Option.PreserveAttributes);
                    } else if ("-q".equals(argName)) {
                        quiet = true;
                    }
                }

                if (!quiet) {
                    session.setScpTransferEventListener(new ScpTransferEventListener() {
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
                }

                ScpClient client = session.createScpClient();
                ScpLocation source = new ScpLocation(args[numArgs - 2]);
                ScpLocation target = new ScpLocation(args[numArgs - 1]);
                if (source.isLocal()) {
                    client.upload(source.getPath(), target.getPath(), options);
                } else {
                    client.download(source.getPath(), target.getPath(), options);
                }
            } finally {
                session.close();
            }
        } finally {
            if ((logStream != stdout) && (logStream != stderr)) {
                logStream.close();
            }
        }
    }
}

