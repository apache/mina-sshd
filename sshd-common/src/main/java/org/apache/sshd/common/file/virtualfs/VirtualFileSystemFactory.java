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
package org.apache.sshd.common.file.virtualfs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * SSHd file system factory to reduce the visibility to a physical folder.
 */
public class VirtualFileSystemFactory implements FileSystemFactory {

    private Path defaultHomeDir;
    private final Map<String, Path> homeDirs = new ConcurrentHashMap<>();

    public VirtualFileSystemFactory() {
        super();
    }

    public VirtualFileSystemFactory(Path defaultHomeDir) {
        this.defaultHomeDir = defaultHomeDir;
    }

    public void setDefaultHomeDir(Path defaultHomeDir) {
        this.defaultHomeDir = defaultHomeDir;
    }

    public Path getDefaultHomeDir() {
        return defaultHomeDir;
    }

    public void setUserHomeDir(String userName, Path userHomeDir) {
        homeDirs.put(ValidateUtils.checkNotNullAndNotEmpty(userName, "No username"),
                Objects.requireNonNull(userHomeDir, "No home dir"));
    }

    public Path getUserHomeDir(String userName) {
        return homeDirs.get(ValidateUtils.checkNotNullAndNotEmpty(userName, "No username"));
    }

    @Override
    public Path getUserHomeDir(SessionContext session) throws IOException {
        String username = session.getUsername();
        Path homeDir = getUserHomeDir(username);
        if (homeDir == null) {
            homeDir = getDefaultHomeDir();
        }

        return homeDir;
    }

    @Override
    public FileSystem createFileSystem(SessionContext session) throws IOException {
        Path dir = getUserHomeDir(session);
        if (dir == null) {
            throw new InvalidPathException(session.getUsername(), "Cannot resolve home directory");
        }

        return new RootedFileSystemProvider().newFileSystem(dir, Collections.emptyMap());
    }
}
