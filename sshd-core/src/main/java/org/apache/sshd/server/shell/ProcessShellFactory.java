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
 * A {@link Factory} of {@link Command} that will create a new process and bridge the streams.
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

    protected List<String> resolveEffectiveCommand(
            ChannelSession channel, String rawCommand, List<String> parsedElements) {
        if (!OsUtils.isWin32()) {
            return ValidateUtils.checkNotNullAndNotEmpty(parsedElements, "No parsed command elements");
        }

        // Turns out that running a command with no arguments works just fine in Windows
        if (GenericUtils.size(parsedElements) <= 1) {
            return ValidateUtils.checkNotNullAndNotEmpty(parsedElements, "No parsed command elements");
        }

        // For windows create a "cmd.exe /C "..."" string
        String cmdName = parsedElements.get(0);
        // If already using shell prefix then assume callers knows what they're doing
        if (OsUtils.WINDOWS_SHELL_COMMAND_NAME.equalsIgnoreCase(cmdName)) {
            return ValidateUtils.checkNotNullAndNotEmpty(parsedElements, "No parsed command elements");
        }

        return Arrays.asList(OsUtils.WINDOWS_SHELL_COMMAND_NAME, "/C",
                ValidateUtils.checkNotNullAndNotEmpty(rawCommand, "No command"));
    }
}
