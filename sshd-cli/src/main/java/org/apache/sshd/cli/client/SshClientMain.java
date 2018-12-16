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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Level;

import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshClientMain extends SshClientCliSupport {
    protected SshClientMain() {
        super();    // in case someone wants to extend it
    }

    //////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        PrintStream stdout = System.out;
        PrintStream stderr = System.err;
        boolean agentForward = false;
        List<String> command = null;
        int socksPort = -1;
        int numArgs = GenericUtils.length(args);
        boolean error = false;
        String target = null;
        Level level = Level.WARNING;
        OutputStream logStream = stderr;
        for (int i = 0; i < numArgs; i++) {
            String argName = args[i];
            // handled by 'setupClientSession'
            if (GenericUtils.isEmpty(command) && isArgumentedOption("-p", argName)) {
                if ((i + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }

                i++;
                continue;
            }

            // verbosity handled separately
            if (GenericUtils.isEmpty(command) && ("-v".equals(argName) || "-vv".equals(argName) || "-vvv".equals(argName))) {
                continue;
            }

            if (GenericUtils.isEmpty(command) && "-D".equals(argName)) {
                if ((i + 1) >= numArgs) {
                    error = showError(stderr, "option requires an argument: " + argName);
                    break;
                }
                if (socksPort > 0) {
                    error = showError(stderr, argName + " option value re-specified: " + socksPort);
                    break;
                }

                socksPort = Integer.parseInt(args[++i]);
                if (socksPort <= 0) {
                    error = showError(stderr, "Bad option value for " + argName + ": " + socksPort);
                    break;
                }
            } else if (GenericUtils.isEmpty(command) && "-A".equals(argName)) {
                agentForward = true;
            } else if (GenericUtils.isEmpty(command) && "-a".equals(argName)) {
                agentForward = false;
            } else {
                level = CliSupport.resolveLoggingVerbosity(args, i);
                logStream = resolveLoggingTargetStream(stdout, stderr, args, i);
                if (logStream == null) {
                    error = true;
                    break;
                }
                if (GenericUtils.isEmpty(command) && target == null) {
                    target = argName;
                } else {
                    if (command == null) {
                        command = new ArrayList<>();
                    }
                    command.add(argName);
                }
            }
        }

        ClientSession session = null;
        try (BufferedReader stdin = new BufferedReader(
                new InputStreamReader(new NoCloseInputStream(System.in), Charset.defaultCharset()))) {
            if (!error) {
                setupLogging(level, stdout, stderr, logStream);

                session = setupClientSession(SSH_CLIENT_PORT_OPTION, stdin, level, stdout, stderr, args);
                if (session == null) {
                    error = true;
                }
            }

            if (error) {
                System.err.println("usage: ssh [-A|-a] [-v[v][v]] [-E logoutputfile] [-D socksPort]"
                        + " [-l login] [" + SSH_CLIENT_PORT_OPTION + " port] [-o option=value]"
                        + " [-w password] [-c cipherslist] [-m maclist] [-C]"
                        + " hostname/user@host [command]");
                System.exit(-1);
                return;
            }

            try (SshClient client = (SshClient) session.getFactoryManager()) {
                /*
                String authSock = System.getenv(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
                if (authSock == null && provider != null) {
                    Iterable<KeyPair> keys = provider.loadKeys();
                    AgentServer server = new AgentServer();
                    authSock = server.start();
                    SshAgent agent = new AgentClient(authSock);
                    for (KeyPair key : keys) {
                        agent.addIdentity(key, "");
                    }
                    agent.close();
                    props.put(SshAgent.SSH_AUTHSOCKET_ENV_NAME, authSock);
                }
                */

                try {
                    if (socksPort >= 0) {
                        session.startDynamicPortForwarding(new SshdSocketAddress(SshdSocketAddress.LOCALHOST_NAME, socksPort));
                        Thread.sleep(Long.MAX_VALUE);
                    } else {
                        ClientChannel channel;
                        if (GenericUtils.isEmpty(command)) {
                            channel = session.createShellChannel();
                            ((ChannelShell) channel).setAgentForwarding(agentForward);
                            channel.setIn(new NoCloseInputStream(System.in));
                        } else {
                            channel = session.createExecChannel(String.join(" ", command).trim());
                        }

                        try (OutputStream channelOut = new NoCloseOutputStream(System.out);
                             OutputStream channelErr =  new NoCloseOutputStream(System.err)) {
                            channel.setOut(channelOut);
                            channel.setErr(channelErr);
                            channel.open().await(); // TODO use verify and a configurable timeout
                            channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), 0L);
                        } finally {
                            channel.close();
                        }
                        session.close(false);
                    }
                } finally {
                    client.stop();
                }
            } finally {
                session.close();
            }
        } finally {
            if (logStream != null && logStream != stdout && logStream != stderr) {
                logStream.close();
            }
        }
    }
}
