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

import java.util.Collection;
import java.util.Set;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.Command;

/**
 * A {@link Factory} of {@link Command} that will create a new process and bridge
 * the streams.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShellFactory extends AbstractLoggingBean implements Factory<Command> {
    private String[] command;
    private final Set<TtyOptions> ttyOptions;

    public ProcessShellFactory() {
        this(GenericUtils.EMPTY_STRING_ARRAY);
    }

    public ProcessShellFactory(String[] command) {
        this(command, TtyOptions.resolveDefaultTtyOptions());
    }

    public ProcessShellFactory(String[] command, Collection<TtyOptions> ttyOptions) {
        this.command = command;
        this.ttyOptions = GenericUtils.of(ttyOptions);
    }

    public String[] getCommand() {
        return command;
    }

    public void setCommand(String[] command) {
        this.command = command;
    }

    @Override
    public Command create() {
        return new InvertedShellWrapper(createInvertedShell());
    }

    protected InvertedShell createInvertedShell() {
        return new ProcessShell(ttyOptions, getCommand());
    }
}
