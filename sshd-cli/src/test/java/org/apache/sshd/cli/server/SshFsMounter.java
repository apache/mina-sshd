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

package org.apache.sshd.cli.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.logging.Level;

import org.apache.sshd.cli.CliLogger;
import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;

/**
 * A basic implementation to allow remote mounting of the local file system via SFTP
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SshFsMounter extends SshServerCliSupport {
    public static class MounterCommand extends AbstractLoggingBean implements Command, SessionAware, Runnable {
        private final String command;
        private final String cmdName;
        private final List<String> args;
        private String username;
        private InputStream stdin;
        private PrintStream stdout;
        private PrintStream stderr;
        private ExitCallback callback;
        private ExecutorService executor;
        private Future<?> future;

        public MounterCommand(String command) {
            this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");

            String[] comps = GenericUtils.split(this.command, ' ');
            int numComps = GenericUtils.length(comps);
            cmdName = GenericUtils.trimToEmpty(ValidateUtils.checkNotNullAndNotEmpty(comps[0], "No command name"));
            if (numComps > 1) {
                args = new ArrayList<>(numComps - 1);
                for (int index = 1; index < numComps; index++) {
                    String c = GenericUtils.trimToEmpty(comps[index]);
                    if (GenericUtils.isEmpty(c)) {
                        continue;
                    }

                    args.add(c);
                }
            } else {
                args = Collections.emptyList();
            }

            log.info("<init>(" + command + ")");
        }

        @Override
        public void run() {
            try {
                log.info("run(" + username + ")[" + command + "] start");
                if ("id".equals(cmdName)) {
                    int numArgs = GenericUtils.size(args);
                    if (numArgs <= 0) {
                        stdout.println("uid=0(root) gid=0(root) groups=0(root)");
                    } else if (numArgs == 1) {
                        String modifier = args.get(0);
                        if ("-u".equals(modifier) || "-G".equals(modifier)) {
                            stdout.println("0");
                        } else {
                            throw new IllegalArgumentException("Unknown modifier: " + modifier);
                        }
                    } else {
                        throw new IllegalArgumentException("Unexpected extra command arguments");
                    }
                } else {
                    throw new UnsupportedOperationException("Unknown command");
                }

                log.info("run(" + username + ")[" + command + "] end");
                callback.onExit(0);
            } catch (Exception e) {
                log.error("run(" + username + ")[" + command + "] " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                stderr.append("ERROR: ").append(e.getClass().getSimpleName()).append(": ").println(e.getMessage());
                callback.onExit(-1, e.toString());
            }
        }

        @Override
        public void setSession(ServerSession session) {
            username = session.getUsername();
        }

        @Override
        public void setInputStream(InputStream in) {
            this.stdin = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.stdout = new PrintStream(out, true);
        }

        @Override
        public void setErrorStream(OutputStream err) {
            this.stderr = new PrintStream(err, true);
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            this.callback = callback;
        }

        @Override
        public void start(ChannelSession channel, Environment env) throws IOException {
            executor = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
            future = executor.submit(this);
        }

        @Override
        public void destroy(ChannelSession channel) {
            stopCommand();

            if (stdout != null) {
                try {
                    log.info("destroy(" + username + ")[" + command + "] close stdout");
                    stdout.close();
                    log.info("destroy(" + username + ")[" + command + "] stdout closed");
                } finally {
                    stdout = null;
                }
            }

            if (stderr != null) {
                try {
                    log.info("destroy(" + username + ")[" + command + "] close stderr");
                    stderr.close();
                    log.info("destroy(" + username + ")[" + command + "] stderr closed");
                } finally {
                    stderr = null;
                }
            }

            if (stdin != null) {
                try {
                    log.info("destroy(" + username + ")[" + command + "] close stdin");
                    stdin.close();
                    log.info("destroy(" + username + ")[" + command + "] stdin closed");
                } catch (IOException e) {
                    warn("destroy({})[{}] failed ({}) to close stdin: {}",
                            username, command, e.getClass().getSimpleName(), e.getMessage(), e);
                } finally {
                    stdin = null;
                }
            }
        }

        private void stopCommand() {
            if ((future != null) && (!future.isDone())) {
                try {
                    log.info("stopCommand(" + username + ")[" + command + "] cancelling");
                    future.cancel(true);
                    log.info("stopCommand(" + username + ")[" + command + "] cancelled");
                } finally {
                    future = null;
                }
            }

            if ((executor != null) && (!executor.isShutdown())) {
                try {
                    log.info("stopCommand(" + username + ")[" + command + "] shutdown executor");
                    executor.shutdownNow();
                    log.info("stopCommand(" + username + ")[" + command + "] executor shut down");
                } finally {
                    executor = null;
                }
            }
        }
    }

    public static class MounterCommandFactory implements CommandFactory {
        public static final MounterCommandFactory INSTANCE = new MounterCommandFactory();

        public MounterCommandFactory() {
            super();
        }

        @Override
        public String toString() {
            return "mounter";
        }

        @Override
        public Command createCommand(ChannelSession channel, String command) {
            return new MounterCommand(command);
        }
    }

    private SshFsMounter() {
        throw new UnsupportedOperationException("No instance");
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        int port = SshConstants.DEFAULT_PORT;
        boolean error = false;
        Map<String, Object> options = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        int numArgs = GenericUtils.length(args);
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            if ("-p".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if ("-io".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    break;
                }

                String provider = args[++i];
                BuiltinIoServiceFactoryFactories factory
                        = CliSupport.resolveBuiltinIoServiceFactory(System.err, argName, provider);
                if (factory != null) {
                    System.setProperty(IoServiceFactory.class.getName(), factory.getFactoryClassName());
                } else {
                    error = true;
                    break;
                }
            } else if ("-o".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    System.err.println("option requires and argument: " + argName);
                    error = true;
                    break;
                }

                String opt = args[++i];
                int idx = opt.indexOf('=');
                if (idx <= 0) {
                    System.err.println("bad syntax for option: " + opt);
                    error = true;
                    break;
                }
                options.put(opt.substring(0, idx), opt.substring(idx + 1));
            }
        }

        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(options);
        Level level = CliLogger.resolveLoggingVerbosity(resolver, args);
        SshServer sshd = error
                ? null : setupIoServiceFactory(
                        CoreTestSupportUtils.setupTestServer(SshFsMounter.class), resolver,
                        level, System.out, System.err, args);
        if (sshd == null) {
            error = true;
        }

        if (error) {
            System.err.println("usage: sshfs [-p port] [-io mina|nio2|netty] [-o option=value]");
            System.exit(-1);
        }

        Map<String, Object> props = sshd.getProperties();
        props.putAll(options);
        Path targetFolder = Objects.requireNonNull(CommonTestSupportUtils.detectTargetFolder(MounterCommandFactory.class),
                "Failed to detect target folder");
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyPairProvider(SecurityUtils.createGeneratorHostKeyProvider(targetFolder.resolve("key.pem")));
        } else {
            sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(targetFolder.resolve("key.ser")));
        }
        // Should come AFTER key pair provider setup so auto-welcome can be generated if needed
        setupServerBanner(sshd, resolver);

        ShellFactory shellFactory = resolveShellFactory(level, System.out, System.err, resolver);
        if (shellFactory != null) {
            System.out.append("Using shell=").println(shellFactory.getClass().getName());
            sshd.setShellFactory(shellFactory);
        }
        sshd.setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);

        ScpCommandFactory scpFactory;
        if (shellFactory instanceof ScpCommandFactory) {
            scpFactory = (ScpCommandFactory) shellFactory;
            scpFactory.setDelegateCommandFactory(MounterCommandFactory.INSTANCE);
        } else {
            scpFactory = new ScpCommandFactory.Builder()
                    .withDelegate(MounterCommandFactory.INSTANCE)
                    .build();
        }

        sshd.setCommandFactory(scpFactory);
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        sshd.setPort(port);

        System.err.println("Starting SSHD on port " + port);
        sshd.start();
        Thread.sleep(Long.MAX_VALUE);
    }
}
