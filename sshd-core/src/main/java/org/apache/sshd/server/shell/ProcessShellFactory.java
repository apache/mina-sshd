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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;

/**
 * A {@link Factory} of {@link Command} that will create a new process executing the given command in an OS shell.
 * <p>
 * <b>Caveat:</b> Apache MINA SSHD does <em>not</em> provide privilege separation, and SSH users are by default
 * <em>not</em> tied to OS users. The OS shell will run as the same OS user the process using Apache MINA SSHD runs. The
 * shell will have the same access rights as the Apache MINA SSHD server process itself.
 * </p>
 * <p>
 * It is in general <em>not</em> recommended to use this class as is in a production server.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShellFactory extends AbstractLoggingBean implements ShellFactory {
    private String command;
    private List<String> elements;

    public ProcessShellFactory() {
        command = "";
        elements = Collections.emptyList();
    }

    public ProcessShellFactory(String command, String... elements) {
        this(command, GenericUtils.isEmpty(elements) ? Collections.emptyList() : Arrays.asList(elements));
    }

    public ProcessShellFactory(String command, List<String> elements) {
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");
        this.elements = ValidateUtils.checkNotNullAndNotEmpty(elements, "No parsed elements");
    }

    /**
     * @return The original unparsed raw command
     */
    public String getCommand() {
        return command;
    }

    /**
     * @return The parsed command elements
     */
    public List<String> getElements() {
        return elements;
    }

    public void setCommand(String command, String... elements) {
        setCommand(command, GenericUtils.isEmpty(elements) ? Collections.emptyList() : Arrays.asList(elements));
    }

    public void setCommand(String command, List<String> elements) {
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");
        this.elements = ValidateUtils.checkNotNullAndNotEmpty(elements, "No parsed elements");
    }

    @Override
    public Command createShell(ChannelSession channel) {
        InvertedShell shell = createInvertedShell(channel);
        return new InvertedShellWrapper(shell);
    }

    protected InvertedShell createInvertedShell(ChannelSession channel) {
        return new ProcessShell(resolveEffectiveCommand(channel, getCommand(), getElements()));
    }

    /**
     * Determines the shell command to run. On Windows {@code cmd.exe /C} is used; on other systems {@code /bin/sh -c}.
     *
     * @param  channel        {@link ChannelSession} the shell will be executed in
     * @param  rawCommand     the shell command passed
     * @param  parsedElements legacy; unused
     * @return                a list containing the full command to run to execute the given {@code rawCommand}
     */
    protected List<String> resolveEffectiveCommand(
            ChannelSession channel, String rawCommand, List<String> parsedElements) {
        ValidateUtils.checkNotNullAndNotEmpty(rawCommand, "No command");
        if (OsUtils.isWin32()) {
            return Arrays.asList(OsUtils.WINDOWS_SHELL_COMMAND_NAME, "/C", rawCommand);
        }
        return Arrays.asList(OsUtils.LINUX_SHELL_COMMAND_NAME, "-c", rawCommand);
    }
}
