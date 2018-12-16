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
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.scp.ScpClient.Option;
import org.apache.sshd.client.scp.ScpClientCreator;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.scp.ScpLocation;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommandMain extends SshClientCliSupport {
    /**
     * Command line option used to indicate a non-default port
     */
    public static final String SCP_PORT_OPTION = "-P";

    public ScpCommandMain() {
        super();    // in case someone wants to extend it
    }

    //////////////////////////////////////////////////////////////////////////

    public static String[] normalizeCommandArguments(PrintStream stdout, PrintStream stderr, String... args) {
        int numArgs = GenericUtils.length(args);
        if (numArgs <= 0) {
            return args;
        }

        List<String> effective = new ArrayList<>(numArgs);
        boolean error = false;
        for (int index = 0; (index < numArgs) && (!error); index++) {
            String argName = args[index];
            // handled by 'setupClientSession'
            if (isArgumentedOption(SCP_PORT_OPTION, argName) || "-creator".equals(argName)) {
                index++;
                if (index >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                effective.add(argName);
                effective.add(args[index]);
            } else if ("-r".equals(argName) || "-p".equals(argName)
                    || "-q".equals(argName) || "-C".equals(argName)
                    || "-v".equals(argName) || "-vv".equals(argName) || "-vvv".equals(argName)) {
                effective.add(argName);
            } else if (argName.charAt(0) == '-') {
                error = showError(stderr, "Unknown option: " + argName);
                break;
            } else {
                index++;
                if (index >= numArgs) {
                    error = showError(stderr, "Not enough arguments");
                    break;
                }

                ScpLocation source = new ScpLocation(argName);
                ScpLocation target = new ScpLocation(args[index]);
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

    public static ScpClientCreator resolveScpClientCreator(PrintStream stderr, String... args) {
        String className = null;
        for (int index = 0, numArgs = GenericUtils.length(args); index < numArgs; index++) {
            String argName = args[index];
            if ("-creator".equals(argName)) {
                index++;
                if (index >= numArgs) {
                    showError(stderr, "option requires an argument: " + argName);
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
            return ScpClientCreator.class.cast(clazz.newInstance());
        } catch (Exception e) {
            stderr.append("WARNING: Failed (").append(e.getClass().getSimpleName()).append(')')
                .append(" to instantiate ").append(className)
                .append(": ").println(e.getMessage());
            stderr.flush();
            return null;
        }
    }

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
                level = CliSupport.resolveLoggingVerbosity(args, numArgs - 2);
                logStream = resolveLoggingTargetStream(stdout, stderr, args, numArgs - 2);
                if (logStream != null) {
                    setupLogging(level, stdout, stderr, logStream);
                }
            }

            ScpClientCreator creator = resolveScpClientCreator(stderr, args);
            ClientSession session = ((logStream == null) || (creator == null) || GenericUtils.isEmpty(args))
                ? null : setupClientSession(SCP_PORT_OPTION, stdin, level, stdout, stderr, args);
            if (session == null) {
                stderr.println("usage: scp [" + SCP_PORT_OPTION + " port] [-i identity] [-io nio2|mina|netty]"
                         + " [-v[v][v]] [-E logoutput] [-r] [-p] [-q] [-o option=value] [-o creator=class name]"
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
                    creator.setScpTransferEventListener(new ScpTransferEventListener() {
                        @Override
                        public void startFolderEvent(
                                Session session, FileOperation op, Path file, Set<PosixFilePermission> perms) {
                            logEvent("startFolderEvent", session, op, file, -1L, perms, null);
                        }

                        @Override
                        public void endFolderEvent(
                                Session session, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown) {
                            logEvent("endFolderEvent", session, op, file, -1L, perms, thrown);
                        }

                        @Override
                        public void startFileEvent(
                                Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
                            logEvent("startFileEvent", session, op, file, length, perms, null);
                        }

                        @Override
                        public void endFileEvent(
                                Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown) {
                            logEvent("endFileEvent", session, op, file, length, perms, thrown);
                        }

                        private void logEvent(
                                String name, Session session, FileOperation op, Path file, long length,
                                Collection<PosixFilePermission> perms, Throwable thrown) {
                            PrintStream ps = (thrown == null) ? stdout : stderr;
                            ps.append("    ").append(name)
                                .append('[').append(session.toString()).append(']')
                                .append('[').append(op.name()).append(']')
                                .append(' ').append(file.toString());
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

                ScpClient client = creator.createScpClient(session);
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
