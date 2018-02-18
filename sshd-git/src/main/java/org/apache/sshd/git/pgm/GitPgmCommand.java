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
import java.util.List;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.git.AbstractGitCommand;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPgmCommand extends AbstractGitCommand {
    /**
     * @param rootDir Root directory for the command
     * @param command Command to execute
     * @param executorService An {@link ExecutorService} to be used when {@link #start(Environment)}-ing
     * execution. If {@code null} an ad-hoc single-threaded service is created and used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()} will be called when
     * command terminates - unless it is the ad-hoc service, which will be shutdown regardless
     */
    public GitPgmCommand(String rootDir, String command, ExecutorService executorService, boolean shutdownOnExit) {
        super(rootDir, command, executorService, shutdownOnExit);
    }

    @Override
    public void run() {
        String command = getCommand();
        ExitCallback callback = getExitCallback();
        OutputStream err = getErrorStream();
        try {
            List<String> strs = parseDelimitedString(command, " ", true);
            String[] args = strs.toArray(new String[strs.size()]);
            for (int i = 0; i < args.length; i++) {
                if (args[i].startsWith("'") && args[i].endsWith("'")) {
                    args[i] = args[i].substring(1, args[i].length() - 1);
                }
                if (args[i].startsWith("\"") && args[i].endsWith("\"")) {
                    args[i] = args[i].substring(1, args[i].length() - 1);
                }
            }

            new EmbeddedCommandRunner(getRootDir()).execute(args, getInputStream(), getOutputStream(), err);
            if (callback != null) {
                callback.onExit(0);
            }
        } catch (Throwable t) {
            try {
                err.write((t.getMessage() + "\n").getBytes(StandardCharsets.UTF_8));
                err.flush();
            } catch (IOException e) {
                log.warn("Failed {} to flush command={} failure: {}",
                        e.getClass().getSimpleName(), command, e.getMessage());
            }
            if (callback != null) {
                callback.onExit(-1);
            }
        }
    }
}
