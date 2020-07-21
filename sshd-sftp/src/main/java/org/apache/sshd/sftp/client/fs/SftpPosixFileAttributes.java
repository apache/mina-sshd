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
package org.apache.sshd.sftp.client.fs;

import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.sftp.client.SftpClient.Attributes;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPosixFileAttributes implements PosixFileAttributes {
    private final Path path;
    private final Attributes attributes;

    public SftpPosixFileAttributes(Path path, Attributes attributes) {
        this.path = path;
        this.attributes = attributes;
    }

    /**
     * @return The referenced attributes file {@link Path}
     */
    public final Path getPath() {
        return path;
    }

    @Override
    public UserPrincipal owner() {
        String owner = attributes.getOwner();
        return GenericUtils.isEmpty(owner) ? null : new SftpFileSystem.DefaultUserPrincipal(owner);
    }

    @Override
    public GroupPrincipal group() {
        String group = attributes.getGroup();
        return GenericUtils.isEmpty(group) ? null : new SftpFileSystem.DefaultGroupPrincipal(group);
    }

    @Override
    public Set<PosixFilePermission> permissions() {
        return SftpFileSystemProvider.permissionsToAttributes(attributes.getPermissions());
    }

    @Override
    public FileTime lastModifiedTime() {
        return attributes.getModifyTime();
    }

    @Override
    public FileTime lastAccessTime() {
        return attributes.getAccessTime();
    }

    @Override
    public FileTime creationTime() {
        return attributes.getCreateTime();
    }

    @Override
    public boolean isRegularFile() {
        return attributes.isRegularFile();
    }

    @Override
    public boolean isDirectory() {
        return attributes.isDirectory();
    }

    @Override
    public boolean isSymbolicLink() {
        return attributes.isSymbolicLink();
    }

    @Override
    public boolean isOther() {
        return attributes.isOther();
    }

    @Override
    public long size() {
        return attributes.getSize();
    }

    @Override
    public Object fileKey() {
        // TODO consider implementing this
        return null;
    }
}
