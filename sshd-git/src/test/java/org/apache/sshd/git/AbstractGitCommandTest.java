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
import java.nio.file.Path;

import org.apache.sshd.common.util.OsUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class AbstractGitCommandTest extends GitTestSupport {

    AbstractGitCommandTest() {
        super();
    }

    @Test
    void windowsRootRelativePathCannotEscapeConfiguredRoot() throws Exception {
        Assumptions.assumeTrue(OsUtils.isWin32(), "Windows root-relative paths are required for this test");
        Path workDir = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName()).toAbsolutePath();
        Path serverRoot = workDir.resolve("server-root");
        Path outsideRepo = workDir.resolve("outside").resolve("repo.git");
        String outside = outsideRepo.toString().replace('\\', '/');
        String driveRelativePayload = "/" + outside.substring(2); // Skip the drive
        try {
            Path resolved = AbstractGitCommand.resolveGitRepo(serverRoot, driveRelativePayload);
            // Case (1) that would be OK: implementation under test strips all leading separators
            assertTrue(resolved.normalize().startsWith(serverRoot.normalize()),
                    "resolved path unexpectedly outside configured root: " + resolved);
        } catch (IOException e) {
            // case (2) that would be OK: implementation under test throws an exception
        }
    }
}
