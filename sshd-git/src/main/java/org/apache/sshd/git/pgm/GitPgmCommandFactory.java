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
package org.apache.sshd.git.pgm;

import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.scp.UnknownCommand;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPgmCommandFactory implements CommandFactory {
    public static final String GIT_COMMAND_PREFIX = "git ";

    private final String rootDir;
    private final CommandFactory delegate;

    public GitPgmCommandFactory(String rootDir) {
        this(rootDir,  null);
    }

    public GitPgmCommandFactory(String rootDir, CommandFactory delegate) {
        this.rootDir = rootDir;
        this.delegate = delegate;
    }

    @Override
    public Command createCommand(String command) {
        if (command.startsWith(GIT_COMMAND_PREFIX)) {
            return new GitPgmCommand(rootDir, command.substring(GIT_COMMAND_PREFIX.length()));
        } else if (delegate != null) {
            return delegate.createCommand(command);
        } else {
            return new UnknownCommand(command);
        }
    }
}
