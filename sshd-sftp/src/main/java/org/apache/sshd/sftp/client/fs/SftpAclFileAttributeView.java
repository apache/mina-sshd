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
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;

import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.impl.AbstractSftpFileAttributeView;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpAclFileAttributeView extends AbstractSftpFileAttributeView implements AclFileAttributeView {
    public SftpAclFileAttributeView(SftpFileSystemProvider provider, Path path, LinkOption... options) {
        super(provider, path, options);
    }

    @Override
    public UserPrincipal getOwner() throws IOException {
        PosixFileAttributes v = provider.readAttributes(path, PosixFileAttributes.class, options);
        return v.owner();
    }

    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        provider.setAttribute(path, "posix", "owner", owner, options);
    }

    @Override
    public String name() {
        return "acl";
    }

    @Override
    public List<AclEntry> getAcl() throws IOException {
        return readRemoteAttributes().getAcl();
    }

    @Override
    public void setAcl(List<AclEntry> acl) throws IOException {
        writeRemoteAttributes(new SftpClient.Attributes().acl(acl));
    }

}
