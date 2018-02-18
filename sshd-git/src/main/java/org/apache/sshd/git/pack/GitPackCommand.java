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

import java.io.File;
import java.util.List;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.git.AbstractGitCommand;
import org.apache.sshd.server.Environment;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.lib.RepositoryCache;
import org.eclipse.jgit.transport.ReceivePack;
import org.eclipse.jgit.transport.RemoteConfig;
import org.eclipse.jgit.transport.UploadPack;
import org.eclipse.jgit.util.FS;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GitPackCommand extends AbstractGitCommand {
    /**
     * @param rootDir Root directory for the command
     * @param command Command to execute
     * @param executorService An {@link ExecutorService} to be used when {@link #start(Environment)}-ing
     * execution. If {@code null} an ad-hoc single-threaded service is created and used.
     * @param shutdownOnExit  If {@code true} the {@link ExecutorService#shutdownNow()} will be called when
     * command terminates - unless it is the ad-hoc service, which will be shutdown regardless
     */
    public GitPackCommand(String rootDir, String command, ExecutorService executorService, boolean shutdownOnExit) {
        super(rootDir, command, executorService, shutdownOnExit);
    }

    @Override
    public void run() {
        String command = getCommand();
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

            if (args.length != 2) {
                throw new IllegalArgumentException("Invalid git command line: " + command);
            }

            String rootDir = getRootDir();
            File srcGitdir = new File(rootDir, args[1]);
            RepositoryCache.FileKey key = RepositoryCache.FileKey.lenient(srcGitdir, FS.DETECTED);
            Repository db = key.open(true /* must exist */);
            if (RemoteConfig.DEFAULT_UPLOAD_PACK.equals(args[0])) {
                new UploadPack(db).upload(getInputStream(), getOutputStream(), getErrorStream());
            } else if (RemoteConfig.DEFAULT_RECEIVE_PACK.equals(args[0])) {
                new ReceivePack(db).receive(getInputStream(), getOutputStream(), getErrorStream());
            } else {
                throw new IllegalArgumentException("Unknown git command: " + command);
            }

            onExit(0);
        } catch (Throwable t) {
            onExit(-1, t.getClass().getSimpleName());
        }
    }
}
