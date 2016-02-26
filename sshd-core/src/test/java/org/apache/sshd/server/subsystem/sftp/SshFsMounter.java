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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.mina.MinaServiceFactory;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.InteractiveProcessShellFactory;
import org.apache.sshd.util.test.Utils;

/**
 * A basic implementation to allow remote mounting of the local file system via SFTP
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SshFsMounter {
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
                args = new ArrayList<String>(numComps - 1);
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
                stderr.append(e.getClass().getSimpleName()).append(": ").println(e.getMessage());
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
        public void start(Environment env) throws IOException {
            executor = ThreadUtils.newSingleThreadExecutor(getClass().getSimpleName());
            future = executor.submit(this);
        }

        @Override
        public void destroy() {
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
                    log.warn("destroy(" + username + ")[" + command + "] failed (" + e.getClass().getSimpleName() + ") to close stdin: " + e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("destroy(" + username + ")[" + command + "] failure details", e);
                    }
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
        public Command createCommand(String command) {
            return new MounterCommand(command);
        }
    }

    private SshFsMounter() {
        throw new UnsupportedOperationException("No instance");
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        int port = SshConfigFileReader.DEFAULT_PORT;
        boolean error = false;
        Map<String, String> options = new LinkedHashMap<String, String>();

        int numArgs = GenericUtils.length(args);
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            if ("-p".equals(argName)) {
                if (i + 1 >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    break;
                }
                port = Integer.parseInt(args[++i]);
            } else if ("-io".equals(argName)) {
                if (i + 1 >= numArgs) {
                    System.err.println("option requires an argument: " + argName);
                    break;
                }

                String provider = args[++i];
                if ("mina".equals(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), MinaServiceFactory.class.getName());
                } else if ("nio2".endsWith(provider)) {
                    System.setProperty(IoServiceFactory.class.getName(), Nio2ServiceFactory.class.getName());
                } else {
                    System.err.println("provider should be mina or nio2: " + argName);
                    error = true;
                    break;
                }
            } else if ("-o".equals(argName)) {
                if (i + 1 >= numArgs) {
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
            } else if (argName.startsWith("-")) {
                System.err.println("illegal option: " + argName);
                error = true;
                break;
            } else {
                System.err.println("extra argument: " + argName);
                error = true;
                break;
            }
        }
        if (error) {
            System.err.println("usage: sshfs [-p port] [-io mina|nio2] [-o option=value]");
            System.exit(-1);
        }

        System.err.println("Starting SSHD on port " + port);

        SshServer sshd = Utils.setupTestServer(SshFsMounter.class);
        Map<String, Object> props = sshd.getProperties();
//        FactoryManagerUtils.updateProperty(props, ServerFactoryManager.WELCOME_BANNER, "Welcome to SSH-FS Mounter\n");
        props.putAll(options);
        sshd.setPort(port);

        File targetFolder = ValidateUtils.checkNotNull(Utils.detectTargetFolder(MounterCommandFactory.class), "Failed to detect target folder");
        if (SecurityUtils.isBouncyCastleRegistered()) {
            sshd.setKeyPairProvider(SecurityUtils.createGeneratorHostKeyProvider(new File(targetFolder, "key.pem").toPath()));
        } else {
            sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(new File(targetFolder, "key.ser")));
        }

        sshd.setShellFactory(InteractiveProcessShellFactory.INSTANCE);
        sshd.setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        sshd.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.setCommandFactory(new ScpCommandFactory.Builder().withDelegate(MounterCommandFactory.INSTANCE).build());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystemFactory()));
        sshd.start();

        Thread.sleep(Long.MAX_VALUE);
    }
}
