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
import org.apache.sshd.server.Command;

/**
 * A {@link Factory} of {@link Command} that will create a new process and bridge
 * the streams.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShellFactory extends AbstractLoggingBean implements Factory<Command> {
    private List<String> command;

    public ProcessShellFactory() {
        this(Collections.<String>emptyList());
    }

    public ProcessShellFactory(String ... command) {
        this(GenericUtils.isEmpty(command) ? Collections.<String>emptyList() : Arrays.asList(command));
    }

    public ProcessShellFactory(List<String> command) {
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");
    }

    public List<String> getCommand() {
        return command;
    }

    public void setCommand(String ... command) {
        setCommand(GenericUtils.isEmpty(command) ? Collections.<String>emptyList() : Arrays.asList(command));
    }

    public void setCommand(List<String> command) {
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "No command");
    }

    @Override
    public Command create() {
        return new InvertedShellWrapper(createInvertedShell());
    }

    protected InvertedShell createInvertedShell() {
        return new ProcessShell(resolveEffectiveCommand(getCommand()));
    }

    protected List<String> resolveEffectiveCommand(List<String> original) {
        if (!OsUtils.isWin32()) {
            return original;
        }

        // Turns out that running a command with no arguments works just fine
        if (GenericUtils.size(original) <= 1) {
            return original;
        }

        // For windows create a "cmd.exe /C "..."" string
        String cmdName = original.get(0);
        if (OsUtils.WINDOWS_SHELL_COMMAND_NAME.equalsIgnoreCase(cmdName)) {
            return original;    // assume callers knows what they're doing
        }

        return Arrays.asList(OsUtils.WINDOWS_SHELL_COMMAND_NAME, "/C", GenericUtils.join(original, ' '));
    }
}
