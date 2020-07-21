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

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.impl.AbstractSftpFileAttributeView;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPosixFileAttributeView extends AbstractSftpFileAttributeView implements PosixFileAttributeView {
    public SftpPosixFileAttributeView(SftpFileSystemProvider provider, Path path, LinkOption... options) {
        super(provider, path, options);
    }

    @Override
    public String name() {
        return "posix";
    }

    @Override
    public PosixFileAttributes readAttributes() throws IOException {
        return new SftpPosixFileAttributes(path, readRemoteAttributes());
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
        SftpClient.Attributes attrs = new SftpClient.Attributes();
        if (lastModifiedTime != null) {
            attrs.modifyTime(lastModifiedTime);
        }
        if (lastAccessTime != null) {
            attrs.accessTime(lastAccessTime);
        }
        if (createTime != null) {
            attrs.createTime(createTime);
        }

        if (GenericUtils.isEmpty(attrs.getFlags())) {
            if (log.isDebugEnabled()) {
                log.debug("setTimes({}) no changes", path);
            }
        } else {
            writeRemoteAttributes(attrs);
        }
    }

    @Override
    public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
        provider.setAttribute(path, "permissions", perms, options);
    }

    @Override
    public void setGroup(GroupPrincipal group) throws IOException {
        provider.setAttribute(path, "group", group, options);
    }

    @Override
    public UserPrincipal getOwner() throws IOException {
        return readAttributes().owner();
    }

    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        provider.setAttribute(path, "owner", owner, options);
    }
}
