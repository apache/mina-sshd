/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.file.util.BaseFileSystem;
import org.apache.sshd.common.file.util.ImmutableList;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedFileSystem extends BaseFileSystem<RootedPath> {

    private Path rootPath;

    public RootedFileSystem(RootedFileSystemProvider fileSystemProvider, Path root, Map<String, ?> env) {
        super(fileSystemProvider);
        this.rootPath = root;
    }

    public Path getRoot() {
        return rootPath;
    }

    @Override
    public void close() throws IOException {
        // ignored
    }

    @Override
    public boolean isOpen() {
        return getRoot().getFileSystem().isOpen();
    }

    @Override
    public boolean isReadOnly() {
        return getRoot().getFileSystem().isReadOnly();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return rootPath.getFileSystem().supportedFileAttributeViews();
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return getRoot().getFileSystem().getUserPrincipalLookupService();
    }

    @Override
    protected RootedPath create(String root, ImmutableList<String> names) {
        return new RootedPath(this, root, names);
    }
}
