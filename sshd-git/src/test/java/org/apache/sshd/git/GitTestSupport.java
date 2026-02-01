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

import java.nio.file.Path;

import org.apache.sshd.util.test.BaseTestSupport;
import org.eclipse.jgit.lib.Config;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.storage.file.FileBasedConfig;
import org.eclipse.jgit.util.FS;
import org.eclipse.jgit.util.SystemReader;

public class GitTestSupport extends BaseTestSupport {

    protected GitTestSupport() {
        super();
    }

    protected SystemReader mockGitConfig(Path directory) throws Exception {
        SystemReader defaultSystemReader = SystemReader.getInstance();
        SystemReader.setInstance(new MockSystemReader(defaultSystemReader, directory));
        return defaultSystemReader;
    }

    private static class MockSystemReader extends SystemReader {

        private static final String[] HIDDEN_VARIABLES = { //
                Constants.GIT_DIR_KEY, //
                Constants.GIT_WORK_TREE_KEY, //
                Constants.GIT_OBJECT_DIRECTORY_KEY, //
                Constants.GIT_INDEX_FILE_KEY, //
                Constants.GIT_ALTERNATE_OBJECT_DIRECTORIES_KEY };

        private final SystemReader delegate;
        private final Path tempDir;

        MockSystemReader(SystemReader delegate, Path directory) {
            this.delegate = delegate;
            this.tempDir = directory;
        }

        @Override
        public String getHostname() {
            return "localhost";
        }

        @Override
        public String getenv(String variable) {
            String result = delegate.getenv(variable);
            if (result != null) {
                // Hide some environment variables that if set might confuse JGit.
                boolean isWin = isWindows();
                for (String gitvar : HIDDEN_VARIABLES) {
                    if (isWin && gitvar.equalsIgnoreCase(variable) || !isWin && gitvar.equals(variable)) {
                        return null;
                    }
                }
            }
            return result;
        }

        @Override
        public String getProperty(String key) {
            if (Constants.OS_USER_DIR.equals(key)) {
                // Return a fake "home" directory
                return tempDir.toString();
            }
            return delegate.getProperty(key);
        }

        @Override
        public FileBasedConfig openUserConfig(Config parent, FS fs) {
            return new FileBasedConfig(parent, tempDir.resolve(".userGitConfig").toFile(), fs);
        }

        @Override
        public FileBasedConfig openSystemConfig(Config parent, FS fs) {
            return new FileBasedConfig(parent, tempDir.resolve(".systemGitConfig").toFile(), fs);
        }

        @Override
        public FileBasedConfig openJGitConfig(Config parent, FS fs) {
            return new FileBasedConfig(parent, tempDir.resolve(".jGitConfig").toFile(), fs);
        }

        @Override
        public long getCurrentTime() {
            return delegate.getCurrentTime();
        }

        @Override
        public int getTimezone(long when) {
            return delegate.getTimezone(when);
        }
    }
}
