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
package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.file.util.BaseFileSystem;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedFileSystem extends BaseFileSystem<RootedPath> {

    private final Path rootPath;
    private final FileSystem rootFs;

    public RootedFileSystem(RootedFileSystemProvider fileSystemProvider, Path root, Map<String, ?> env) {
        super(fileSystemProvider);
        this.rootPath = Objects.requireNonNull(root, "No root path");
        this.rootFs = root.getFileSystem();
    }

    public FileSystem getRootFileSystem() {
        return rootFs;
    }

    public Path getRoot() {
        return rootPath;
    }

    @Override
    public RootedFileSystemProvider provider() {
        return (RootedFileSystemProvider) super.provider();
    }

    @Override
    public void close() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("close({})", this);
        }
    }

    @Override
    public boolean isOpen() {
        return rootFs.isOpen();
    }

    @Override
    public boolean isReadOnly() {
        return rootFs.isReadOnly();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return rootFs.supportedFileAttributeViews();
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return rootFs.getUserPrincipalLookupService();
    }

    @Override
    protected RootedPath create(String root, List<String> names) {
        return new RootedPath(this, root, names);
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        return rootFs.getFileStores();
    }

    @Override
    public String toString() {
        return rootPath.toString();
    }
}
