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

import java.util.concurrent.ExecutorService;

import org.apache.sshd.git.AbstractGitCommandFactory;
import org.apache.sshd.server.CommandFactory;

/**
 * Runs a GIT command locally using an embedded executor
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPgmCommandFactory extends AbstractGitCommandFactory {
    public static final String GIT_COMMAND_PREFIX = "git ";

    public GitPgmCommandFactory(String rootDir) {
        this(rootDir,  null);
    }

    public GitPgmCommandFactory(String rootDir, CommandFactory delegate) {
        super(rootDir, delegate, GIT_COMMAND_PREFIX);
    }

    @Override
    public GitPgmCommandFactory withExecutorService(ExecutorService executorService) {
        return (GitPgmCommandFactory) super.withExecutorService(executorService);
    }

    @Override
    public GitPgmCommandFactory withShutdownOnExit(boolean shutdownOnExit) {
        return (GitPgmCommandFactory) super.withShutdownOnExit(shutdownOnExit);
    }

    @Override
    public GitPgmCommand createGitCommand(String command) {
        return new GitPgmCommand(getRootDir(), command.substring(GIT_COMMAND_PREFIX.length()), getExecutorService(), isShutdownOnExit());
    }
}
