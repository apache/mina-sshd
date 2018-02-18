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
package org.apache.sshd.git.pack;

import java.util.concurrent.ExecutorService;

import org.apache.sshd.git.AbstractGitCommandFactory;
import org.apache.sshd.server.CommandFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPackCommandFactory extends AbstractGitCommandFactory {
    public static final String GIT_COMMAND_PREFIX = "git-";

    public GitPackCommandFactory(String rootDir) {
        this(rootDir,  null);
    }

    public GitPackCommandFactory(String rootDir, CommandFactory delegate) {
        super(rootDir, delegate, GIT_COMMAND_PREFIX);
    }

    @Override
    public GitPackCommandFactory withExecutorService(ExecutorService executorService) {
        return (GitPackCommandFactory) super.withExecutorService(executorService);
    }

    @Override
    public GitPackCommandFactory withShutdownOnExit(boolean shutdownOnExit) {
        return (GitPackCommandFactory) super.withShutdownOnExit(shutdownOnExit);
    }

    @Override
    public GitPackCommand createGitCommand(String command) {
        return new GitPackCommand(getRootDir(), command, getExecutorService(), isShutdownOnExit());
    }
}
