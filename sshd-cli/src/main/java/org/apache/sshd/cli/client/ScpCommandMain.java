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

package org.apache.sshd.cli.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.apache.sshd.cli.CliLogger;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.scp.client.ScpClient;
import org.apache.sshd.scp.client.ScpClient.Option;
import org.apache.sshd.scp.client.ScpClientCreator;
import org.apache.sshd.scp.client.ScpRemote2RemoteTransferHelper;
import org.apache.sshd.scp.client.ScpRemote2RemoteTransferListener;
import org.apache.sshd.scp.common.ScpLocation;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;
import org.slf4j.Logger;

/**
 * @see    <A HREF="https://man7.org/linux/man-pages/man1/scp.1.html">SCP(1) - manual page</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommandMain extends SshClientCliSupport {
    /**
     * Command line option used to indicate a non-default port
     */
    public static final String SCP_PORT_OPTION = "-P";

    /**
     * Copies between two remote hosts are transferred through the local host
     */
    public static final String SCP_REMOTE_TO_REMOTE_OPTION = "-3";

    public ScpCommandMain() {
        super(); // in case someone wants to extend it
    }

    /* -------------------------------------------------------------------------------- */

    public static String[] normalizeCommandArguments(PrintStream stdout, PrintStream stderr, String... args) {
        int numArgs = GenericUtils.length(args);
        if (numArgs <= 0) {
            return args;
        }

        List<String> effective = new ArrayList<>(numArgs);
        boolean error = false;
        boolean threeWay = false;
        for (int index = 0; (index < numArgs) && (!error); index++) {
            String argName = args[index];
            // handled by 'setupClientSession'
            if (isArgumentedOption(SCP_PORT_OPTION, argName) || "-creator".equals(argName)) {
                index++;
                if (index >= numArgs) {
                    error = CliLogger.showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                effective.add(argName);
                effective.add(args[index]);
            } else if ("-r".equals(argName) || "-p".equals(argName)
                    || "-q".equals(argName) || "-C".equals(argName)
                    || "-v".equals(argName) || "-vv".equals(argName) || "-vvv".equals(argName)) {
                effective.add(argName);
            } else if (SCP_REMOTE_TO_REMOTE_OPTION.equals(argName)) {
                threeWay = true;
                effective.add(argName);
            } else if (argName.charAt(0) == '-') {
                error = CliLogger.showError(stderr, "Unknown option: " + argName);
                break;
            } else {
                index++;
                if (index >= numArgs) {
                    error = CliLogger.showError(stderr, "Not enough arguments");
                    break;
                }

                ScpLocation source = new ScpLocation(argName);
                ScpLocation target = new ScpLocation(args[index]);
                if (index < (numArgs - 1)) {
                    error = CliLogger.showError(stderr, "Unexpected extra arguments");
                    break;
                }

                if (threeWay) {
                    if (source.isLocal() || target.isLocal()) {
                        error = CliLogger.showError(stderr, "Both targets must be remote for the 3-way copy option");
                        break;
                    }

                    adjustRemoteTargetArguments(source, source, target, effective);
                } else {
                    if (source.isLocal() == target.isLocal()) {
                        error = CliLogger.showError(stderr, "Both targets are either remote or local");
                        break;
                    }

                    ScpLocation remote = source.isLocal() ? target : source;
                    adjustRemoteTargetArguments(remote, source, target, effective);
                }
                break;
            }
        }

        if (error) {
            return null;
        }

        return effective.toArray(new String[effective.size()]);
    }

    /* -------------------------------------------------------------------------------- */

    private static void adjustRemoteTargetArguments(
            ScpLocation remote, ScpLocation source, ScpLocation target, Collection<String> effective) {
        int port = remote.resolvePort();
        if (port != SshConstants.DEFAULT_PORT) {
            effective.add(SCP_PORT_OPTION);
            effective.add(Integer.toString(port));
        }

        effective.add(remote.resolveUsername() + "@" + remote.getHost());
        effective.add(source.toString());
        effective.add(target.toString());
    }

    /* -------------------------------------------------------------------------------- */

    public static ScpClientCreator resolveScpClientCreator(PrintStream stderr, String... args) {
        String className = null;
        for (int index = 0, numArgs = GenericUtils.length(args); index < numArgs; index++) {
            String argName = args[index];
            if ("-creator".equals(argName)) {
                index++;
                if (index >= numArgs) {
                    CliLogger.showError(stderr, "option requires an argument: " + argName);
                    return null;
                }

                className = args[index];
            }
        }

        if (GenericUtils.isEmpty(className)) {
            className = System.getProperty(ScpClientCreator.class.getName());
        }

        if (GenericUtils.isEmpty(className)) {
            return ScpClientCreator.instance();
        }

        try {
            ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(ScpClientCreator.class);
            Class<?> clazz = cl.loadClass(className);
            return ReflectionUtils.newInstance(clazz, ScpClientCreator.class);
        } catch (Exception e) {
            stderr.append("WARNING: Failed (").append(e.getClass().getSimpleName()).append(')')
                    .append(" to instantiate ").append(className)
                    .append(": ").println(e.getMessage());
            stderr.flush();
            return null;
        }
    }

    /* -------------------------------------------------------------------------------- */

    public static Set<Option> parseCopyOptions(String[] args) {
        if (GenericUtils.isEmpty(args)) {
            return Collections.emptySet();
        }

        Set<Option> options = EnumSet.noneOf(Option.class);
        for (String argName : args) {
            if ("-r".equals(argName)) {
                options.add(Option.TargetIsDirectory);
                options.add(Option.Recursive);
            } else if ("-p".equals(argName)) {
                options.add(Option.PreserveAttributes);
            }
        }

        return options;
    }

    /* -------------------------------------------------------------------------------- */

    public static void showUsageMessage(PrintStream stderr) {
        stderr.println("usage: scp [" + SCP_PORT_OPTION + " port] [-i identity] [-io nio2|mina|netty]"
                       + " [" + SCP_REMOTE_TO_REMOTE_OPTION + "]"
                       + " [" + Option.Recursive.getOptionValue() + "]"
                       + " [" + Option.PreserveAttributes.getOptionValue() + "]"
                       + " [-v[v][v]] [-E logoutput] [-q] [-o option=value] [-o creator=class name]"
                       + " [-c cipherlist] [-m maclist] [-J proxyJump] [-w password] [-C] <source> <target>");
        stderr.println();
        stderr.println("Where <source> or <target> are either 'user@host:file' or a local file path");
        stderr.println("NOTE: exactly ONE of the source or target must be remote and the other one local");
        stderr.println("    or both remote if " + SCP_REMOTE_TO_REMOTE_OPTION + " specified");
    }

    /* -------------------------------------------------------------------------------- */

    @SuppressWarnings({ "checkstyle:ParameterNumber", "checkstyle:anoninnerlength" })
    public static void xferLocalToRemote(
            BufferedReader stdin, PrintStream stdout, PrintStream stderr, String[] args,
            ScpLocation source, ScpLocation target, Collection<Option> options,
            OutputStream logStream, Level level, boolean quiet)
            throws Exception {
        ScpClientCreator creator = resolveScpClientCreator(stderr, args);
        ClientSession session = ((logStream == null) || (creator == null) || GenericUtils.isEmpty(args))
                ? null : setupClientSession(SCP_PORT_OPTION, stdin, level, stdout, stderr, args);
        if (session == null) {
            showUsageMessage(stderr);
            System.exit(-1);
            return; // not that we really need it...
        }

        try {
            if (!quiet) {
                creator.setScpTransferEventListener(new ScpTransferEventListener() {
                    private final Logger log = CliLogger.resolveLogger(ScpCommandMain.class, level, stdout, stderr);

                    @Override
                    public void startFolderEvent(
                            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms) {
                        logEvent("startFolderEvent", session, op, file, -1L, perms, null);
                    }

                    @Override
                    public void endFolderEvent(
                            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms,
                            Throwable thrown) {
                        logEvent("endFolderEvent", session, op, file, -1L, perms, thrown);
                    }

                    @Override
                    public void startFileEvent(
                            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
                        logEvent("startFileEvent", session, op, file, length, perms, null);
                    }

                    @Override
                    public void endFileEvent(
                            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms,
                            Throwable thrown) {
                        logEvent("endFileEvent", session, op, file, length, perms, thrown);
                    }

                    @Override
                    public void handleFileEventAckInfo(
                            Session session, FileOperation op, Path file, long length,
                            Set<PosixFilePermission> perms, ScpAckInfo ackInfo)
                            throws IOException {
                        logEvent("ackInfo(" + ackInfo + ")", session, op, file, length, perms, null);
                    }

                    private void logEvent(
                            String name, Session session, FileOperation op, Path file, long length,
                            Collection<PosixFilePermission> perms, Throwable thrown) {
                        if (!log.isInfoEnabled()) {
                            return;
                        }

                        log.info("{} - [{}][{}] (length={}) {} {}", name, session, op, file, length, perms);
                        if (thrown != null) {
                            log.error("{} -   {}: {}", name, thrown.getClass().getSimpleName(), thrown.getMessage());
                        }
                    }
                });
            }

            ScpClient client = creator.createScpClient(session);
            if (source.isLocal()) {
                client.upload(source.getPath(), target.getPath(), options);
            } else {
                client.download(source.getPath(), target.getPath(), options);
            }
        } finally {
            session.close();
        }

    }

    /* -------------------------------------------------------------------------------- */

    @SuppressWarnings("checkstyle:ParameterNumber")
    public static void xferRemoteToRemote(
            BufferedReader stdin, PrintStream stdout, PrintStream stderr, String[] args,
            ScpLocation source, ScpLocation target, Collection<Option> options,
            OutputStream logStream, Level level, boolean quiet)
            throws Exception {
        ClientSession srcSession = ((logStream == null) || GenericUtils.isEmpty(args))
                ? null : setupClientSession(SCP_PORT_OPTION, stdin, level, stdout, stderr, args);
        if (srcSession == null) {
            showUsageMessage(stderr);
            System.exit(-1);
            return; // not that we really need it...
        }

        try {
            ClientFactoryManager manager = srcSession.getFactoryManager();
            // TODO see if there is a way to specify a different port or proxy jump for the target
            HostConfigEntry entry = resolveHost(
                    manager, target.resolveUsername(), target.getHost(), target.resolvePort(), null);
            // TODO use a configurable wait time
            ClientSession dstSession = manager.connect(entry, null, null)
                    .verify(CliClientModuleProperties.CONECT_TIMEOUT.getRequired(srcSession))
                    .getSession();
            try {
                // TODO see if there is a way to specify different password/key for target
                // copy non-default identities from source session
                AuthenticationIdentitiesProvider provider = srcSession.getRegisteredIdentities();
                Iterable<?> ids = (provider == null) ? null : provider.loadIdentities();
                Iterator<?> iter = (ids == null) ? null : ids.iterator();
                while ((iter != null) && iter.hasNext()) {
                    Object v = iter.next();
                    if (v instanceof String) {
                        dstSession.addPasswordIdentity((String) v);
                    } else if (v instanceof KeyPair) {
                        dstSession.addPublicKeyIdentity((KeyPair) v);
                    } else {
                        throw new UnsupportedOperationException("Unsupported source identity: " + v);
                    }
                }

                dstSession.auth().verify(CliClientModuleProperties.AUTH_TIMEOUT.getRequired(dstSession));

                ScpRemote2RemoteTransferListener listener = quiet ? null : new ScpRemote2RemoteTransferListener() {
                    @Override
                    public void startDirectFileTransfer(
                            ClientSession srcSession, String source,
                            ClientSession dstSession, String destination,
                            ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details)
                            throws IOException {
                        logEvent("FILE-START: ", source, destination, null);
                    }

                    @Override
                    public void startDirectDirectoryTransfer(
                            ClientSession srcSession, String source,
                            ClientSession dstSession, String destination,
                            ScpTimestampCommandDetails timestamp, ScpReceiveDirCommandDetails details)
                            throws IOException {
                        logEvent("DIR-START: ", source, destination, null);
                    }

                    @Override
                    public void endDirectFileTransfer(
                            ClientSession srcSession, String source,
                            ClientSession dstSession, String destination,
                            ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details,
                            long xferSize, Throwable thrown)
                            throws IOException {
                        logEvent("FILE-END: ", source, destination, thrown);
                    }

                    @Override
                    public void endDirectDirectoryTransfer(
                            ClientSession srcSession, String source,
                            ClientSession dstSession, String destination,
                            ScpTimestampCommandDetails timestamp, ScpReceiveDirCommandDetails details,
                            Throwable thrown)
                            throws IOException {
                        logEvent("DIR-END: ", source, destination, thrown);
                    }

                    private void logEvent(String event, String src, String dst, Throwable thrown) {
                        PrintStream ps = (thrown == null) ? stdout : stderr;
                        ps.append("    ").append(event)
                                .append(' ').append(src).append(" ==> ").append(dst);
                        if (thrown != null) {
                            ps.append(" - ").append(thrown.getClass().getSimpleName()).append(": ")
                                    .append(thrown.getMessage());
                        }
                        ps.println();
                    }
                };
                ScpRemote2RemoteTransferHelper helper = new ScpRemote2RemoteTransferHelper(srcSession, dstSession, listener);
                boolean preserveAttributes = GenericUtils.isNotEmpty(options) && options.contains(Option.PreserveAttributes);
                if (GenericUtils.isNotEmpty(options)
                        && (options.contains(Option.Recursive) || options.contains(Option.TargetIsDirectory))) {
                    helper.transferDirectory(source.getPath(), target.getPath(), preserveAttributes);
                } else {
                    helper.transferFile(source.getPath(), target.getPath(), preserveAttributes);
                }
            } finally {
                dstSession.close();
            }
        } finally {
            srcSession.close();
        }
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        PrintStream stdout = System.out;
        PrintStream stderr = System.err;
        OutputStream logStream = stdout;
        try (BufferedReader stdin = new BufferedReader(
                new InputStreamReader(new NoCloseInputStream(System.in), Charset.defaultCharset()))) {
            args = normalizeCommandArguments(stdout, stderr, args);

            Level level = Level.SEVERE;
            int numArgs = GenericUtils.length(args);
            // see the way normalizeCommandArguments works...
            if (numArgs >= 2) {
                level = CliLogger.resolveLoggingVerbosity(args, numArgs - 2);
                logStream = resolveLoggingTargetStream(stdout, stderr, args, numArgs - 2);
                if (logStream != null) {
                    setupLogging(level, stdout, stderr, logStream);
                }
            }

            // see the way normalizeCommandArguments works...
            ScpLocation source = (numArgs >= 2) ? new ScpLocation(args[numArgs - 2]) : null;
            ScpLocation target = (numArgs >= 2) ? new ScpLocation(args[numArgs - 1]) : null;

            Collection<Option> options = parseCopyOptions(args);
            boolean quiet = false;
            boolean threeWay = false;
            for (int index = 0; index < numArgs; index++) {
                String argName = args[index];
                if ("-q".equals(argName)) {
                    quiet = true;
                } else if (SCP_REMOTE_TO_REMOTE_OPTION.equals(argName)) {
                    threeWay = true;
                }
            }

            if (threeWay) {
                xferRemoteToRemote(stdin, stdout, stderr, args, source, target, options, logStream, level, quiet);
            } else {
                xferLocalToRemote(stdin, stdout, stderr, args, source, target, options, logStream, level, quiet);
            }
        } finally {
            if ((logStream != stdout) && (logStream != stderr)) {
                logStream.close();
            }
        }
    }
}
