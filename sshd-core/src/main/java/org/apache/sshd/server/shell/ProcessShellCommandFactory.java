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

package org.apache.sshd.server.shell;

import java.io.IOException;

import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;

/**
 * Executes commands by invoking the underlying shell
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShellCommandFactory implements CommandFactory {
    public static final String FACTORY_NAME = "shell-command";
    public static final ProcessShellCommandFactory INSTANCE = new ProcessShellCommandFactory();

    public ProcessShellCommandFactory() {
        super();
    }

    @Override
    public String toString() {
        return FACTORY_NAME;
    }

    @Override
    public Command createCommand(ChannelSession channel, String command) throws IOException {
        ShellFactory factory = new ProcessShellFactory(command, CommandFactory.split(command));
        return factory.createShell(channel);
    }
}
