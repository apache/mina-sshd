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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.git.AbstractGitCommand;
import org.apache.sshd.git.GitLocationResolver;
import org.apache.sshd.server.Environment;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.lib.RepositoryCache;
import org.eclipse.jgit.transport.GitProtocolConstants;
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

    private GitPackConfiguration packConfiguration = GitPackConfiguration.NOTHING;

    /**
     * @param rootDirResolver Resolver for GIT root directory
     * @param command         Command to execute
     * @param executorService An {@link CloseableExecutorService} to be used when
     *                        {@code start(ChannelSession, Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     */
    public GitPackCommand(GitLocationResolver rootDirResolver, String command, CloseableExecutorService executorService) {
        super(rootDirResolver, command, executorService);
    }

    @Override
    public void run() {
        String command = getCommand();
        try {
            List<String> strs = parseDelimitedString(command, " ", true);
            String[] args = strs.toArray(new String[0]);
            for (int i = 0; i < args.length; i++) {
                String argVal = args[i];
                if (argVal.startsWith("'") && argVal.endsWith("'")) {
                    args[i] = argVal.substring(1, argVal.length() - 1);
                    argVal = args[i];
                }
                if (argVal.startsWith("\"") && argVal.endsWith("\"")) {
                    args[i] = argVal.substring(1, argVal.length() - 1);
                }
            }

            if (args.length != 2) {
                throw new IllegalArgumentException("Invalid git command line (no arguments): " + command);
            }

            Path rootDir = resolveRootDirectory(command, args);
            RepositoryCache.FileKey key = RepositoryCache.FileKey.lenient(rootDir.toFile(), FS.DETECTED);
            try (Repository db = key.open(true /* must exist */)) {
                String subCommand = args[0];
                if (RemoteConfig.DEFAULT_UPLOAD_PACK.equals(subCommand)) {
                    UploadPack uploadPack = new UploadPack(db);
                    packConfiguration.configureUploadPack(getSession(), uploadPack);
                    Environment environment = getEnvironment();
                    Map<String, String> envVars = environment.getEnv();
                    String protocol = MapEntryUtils.isEmpty(envVars)
                            ? null : envVars.get(GitProtocolConstants.PROTOCOL_ENVIRONMENT_VARIABLE);
                    if (GenericUtils.isNotBlank(protocol)) {
                        uploadPack.setExtraParameters(Collections.singleton(protocol));
                    }
                    uploadPack.upload(getInputStream(), getOutputStream(), getErrorStream());
                } else if (RemoteConfig.DEFAULT_RECEIVE_PACK.equals(subCommand)) {
                    ReceivePack receivePack = new ReceivePack(db);
                    packConfiguration.configureReceivePack(getSession(), receivePack);
                    receivePack.receive(getInputStream(), getOutputStream(), getErrorStream());
                } else {
                    throw new IllegalArgumentException("Unknown git command: " + command);
                }
            }
            onExit(0);
        } catch (Throwable t) {
            onExit(-1, t.getClass().getSimpleName());
        }
    }

    protected Path resolveRootDirectory(String command, String[] args) throws IOException {
        GitLocationResolver resolver = getGitLocationResolver();
        Path rootDir = resolver.resolveRootDirectory(command, args, getServerSession(), getFileSystem());
        ValidateUtils.checkState(rootDir != null, "No root directory provided for %s command", command);

        String pathArg = args[1];
        int len = GenericUtils.length(pathArg);
        // Strip any leading path separator since we use relative to root
        if ((len > 0) && (pathArg.charAt(0) == '/')) {
            pathArg = pathArg.substring(1);
        }

        ValidateUtils.hasContent(pathArg, "No %s command sub-path specified", args[0]);
        return rootDir.resolve(pathArg);
    }

    public void setPackConfiguration(GitPackConfiguration packConfiguration) {
        this.packConfiguration = ValidateUtils.checkNotNull(packConfiguration,
                "Pack configuration must not be null");
    }
}
