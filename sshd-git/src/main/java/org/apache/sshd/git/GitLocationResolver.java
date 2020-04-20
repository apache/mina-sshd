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

package org.apache.sshd.git;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.util.Objects;

import org.apache.sshd.server.session.ServerSession;

/**
 * Used by the GIT command(s) to resolve the root directory of the GIT repository
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface GitLocationResolver {
    /**
     * @param  command     The complete received command
     * @param  args        The command split into arguments - {@code args[0]} is the &quot;pure&quot; command itself
     *                     without any other arguments. <B>Note:</B> changing the content of the arguments array may
     *                     affect command execution in undetermined ways, due to invocation code changes without prior
     *                     notice, so <U>highly recommended to avoid it</U>.
     * @param  session     The {@link ServerSession} through which the command was received
     * @param  fs          The {@link FileSystem} associated with the server session
     * @return             The local GIT repository root path
     * @throws IOException If failed to resolve
     */
    Path resolveRootDirectory(String command, String[] args, ServerSession session, FileSystem fs) throws IOException;

    /**
     * Creates a resolver that returns the same root directory for any invocation of
     * {@link #resolveRootDirectory(String, String[], ServerSession, FileSystem) resolveRootDirectory}
     *
     * @param  rootDir The (never {@code null}) root directory to return
     * @return         The wrapper resolver
     */
    static GitLocationResolver constantPath(Path rootDir) {
        Objects.requireNonNull(rootDir, "No root directory provided");
        return (cmd, args, session, fs) -> rootDir;
    }
}
