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
package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Set;

import org.apache.sshd.client.subsystem.sftp.SftpClient.Attributes;
import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPosixFileAttributeView implements PosixFileAttributeView {
    private final SftpFileSystemProvider provider;
    private final Path path;
    private final LinkOption[] options;

    public SftpPosixFileAttributeView(SftpFileSystemProvider provider, Path path, LinkOption... options) {
        this.provider = ValidateUtils.checkNotNull(provider, "No file system provider instance");
        this.path = path;
        this.options = options;
    }

    @Override
    public String name() {
        return "view";
    }

    /**
     * @return The underlying {@link SftpFileSystemProvider} used to
     * provide the view functionality
     */
    public final SftpFileSystemProvider provider() {
        return provider;
    }

    /**
     * @return The referenced view {@link Path}
     */
    public final Path getPath() {
        return path;
    }

    @Override
    public PosixFileAttributes readAttributes() throws IOException {
        SftpPath p = provider.toSftpPath(path);
        SftpFileSystem fs = p.getFileSystem();
        final Attributes attributes;
        try (SftpClient client = fs.getClient()) {
            try {
                if (IoUtils.followLinks(options)) {
                    attributes = client.stat(p.toString());
                } else {
                    attributes = client.lstat(p.toString());
                }
            } catch (SftpException e) {
                if (e.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                    throw new NoSuchFileException(p.toString());
                }
                throw e;
            }
        }
        return new SftpPosixFileAttributes(path, attributes);
    }

    @Override
    public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) throws IOException {
        if (lastModifiedTime != null) {
            provider.setAttribute(path, "lastModifiedTime", lastModifiedTime, options);
        }
        if (lastAccessTime != null) {
            provider.setAttribute(path, "lastAccessTime", lastAccessTime, options);
        }
        if (createTime != null) {
            provider.setAttribute(path, "createTime", createTime, options);
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