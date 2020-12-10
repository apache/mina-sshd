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
import java.io.PrintStream;
import java.nio.charset.Charset;

import org.apache.sshd.cli.CliLogger;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.util.test.BaseTestSupport;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelExecMain extends BaseTestSupport {
    public ChannelExecMain() {
        super();
    }

    public static void doExecuteCommands(
            BufferedReader stdin, PrintStream stdout, PrintStream stderr, ClientSession session)
            throws Exception {
        while (true) {
            stdout.print("> ");

            String command = stdin.readLine();
            if ("q".equalsIgnoreCase(command) || "quit".equalsIgnoreCase(command)) {
                break;
            }
            if (GenericUtils.isEmpty(command)) {
                continue;
            }

            while (true) {
                try {
                    String response = session.executeRemoteCommand(command);
                    String[] lines = GenericUtils.split(response, '\n');
                    for (String l : lines) {
                        stdout.append('\t').println(l);
                    }
                } catch (Exception e) {
                    stderr.append("WARNING: ").append(e.getClass().getSimpleName()).append(": ").println(e.getMessage());
                }

                stdout.append("Execute ").append(command).print(" again [y]/n ");
                String ans = stdin.readLine();
                if ((GenericUtils.length(ans) > 0) && (Character.toLowerCase(ans.charAt(0)) != 'y')) {
                    break;
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        PrintStream stdout = System.out;
        PrintStream stderr = System.err;
        try (BufferedReader stdin = new BufferedReader(
                new InputStreamReader(new NoCloseInputStream(System.in), Charset.defaultCharset()))) {
            ClientSession session = SshClientCliSupport.setupClientSession("-P", stdin,
                    CliLogger.resolveLoggingVerbosity(args), stdout, stderr, args);
            if (session == null) {
                System.err.println("usage: channelExec [-i identity] [-l login] [-P port] [-o option=value]"
                                   + " [-J proxyJump] [-w password] [-c cipherlist]  [-m maclist] [-C] hostname/user@host");
                System.exit(-1);
                return;
            }

            try (SshClient client = (SshClient) session.getFactoryManager()) {
                try (ClientSession clientSession = session) {
                    doExecuteCommands(stdin, stdout, stderr, session);
                } finally {
                    client.stop();
                }
            }
        }
    }

}
