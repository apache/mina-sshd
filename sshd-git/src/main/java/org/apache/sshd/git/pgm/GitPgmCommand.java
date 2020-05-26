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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.git.AbstractGitCommand;
import org.apache.sshd.git.GitLocationResolver;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPgmCommand extends AbstractGitCommand {
    /**
     * @param rootDirResolver Resolver for GIT root directory
     * @param command         Command to execute
     * @param executorService An {@link CloseableExecutorService} to be used when
     *                        {@code start(ChannelSession, Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     */
    public GitPgmCommand(
                         GitLocationResolver rootDirResolver, String command, CloseableExecutorService executorService) {
        super(rootDirResolver, command, executorService);
    }

    @Override
    public void run() {
        String command = getCommand();
        OutputStream err = getErrorStream();
        try {
            List<String> strs = parseDelimitedString(command, " ", true);
            String[] args = strs.toArray(new String[strs.size()]);
            for (int i = 0; i < args.length; i++) {
                String argVal = args[i];
                if (argVal.startsWith("'") && argVal.endsWith("'")) {
                    args[i] = argVal.substring(1, argVal.length() - 1);
                    argVal = args[i];
                }

                if (argVal.startsWith("\"") && argVal.endsWith("\"")) {
                    args[i] = argVal.substring(1, argVal.length() - 1);
                    argVal = args[i];
                }
            }

            GitLocationResolver resolver = getGitLocationResolver();
            Path rootDir = resolver.resolveRootDirectory(command, args, getServerSession(), getFileSystem());
            ValidateUtils.checkState(rootDir != null, "No root directory provided for %s command", command);

            new EmbeddedCommandRunner(rootDir).execute(args, getInputStream(), getOutputStream(), err);
            onExit(0);
        } catch (Throwable t) {
            try {
                err.write((t.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                err.flush();
            } catch (IOException e) {
                log.warn("Failed {} to flush command={} failure: {}",
                        e.getClass().getSimpleName(), command, e.getMessage());
            }
            onExit(-1, t.getMessage());
        }
    }
}
