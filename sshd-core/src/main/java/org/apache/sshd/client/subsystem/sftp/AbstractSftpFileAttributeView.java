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

package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttributeView;

import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.subsystem.sftp.SftpException;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpFileAttributeView extends AbstractLoggingBean implements FileAttributeView {
    protected final SftpFileSystemProvider provider;
    protected final Path path;
    protected final LinkOption[] options;

    protected AbstractSftpFileAttributeView(SftpFileSystemProvider provider, Path path, LinkOption... options) {
        this.provider = ValidateUtils.checkNotNull(provider, "No file system provider instance");
        this.path = ValidateUtils.checkNotNull(path, "No path");
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

    protected SftpClient.Attributes readRemoteAttributes() throws IOException {
        return provider.readRemoteAttributes(provider.toSftpPath(path), options);
    }

    protected void writeRemoteAttributes(SftpClient.Attributes attrs) throws IOException {
        SftpPath p = provider.toSftpPath(path);
        SftpFileSystem fs = p.getFileSystem();
        try (SftpClient client = fs.getClient()) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("writeRemotAttributes({})[{}]: {}", fs, p, attrs);
                }
                client.setStat(p.toString(), attrs);
            } catch (SftpException e) {
                if (e.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                    throw new NoSuchFileException(p.toString());
                }
                throw e;
            }
        }
    }
}
