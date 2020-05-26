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

package org.apache.sshd.server.command;

import java.io.IOException;
import java.nio.file.FileSystem;

import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.server.channel.ChannelSession;

/**
 * Provides a basic useful skeleton for {@link Command} executions that require file system access
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFileSystemCommand extends AbstractCommandSupport implements FileSystemAware {

    protected FileSystem fileSystem;

    public AbstractFileSystemCommand(
                                     String command, CloseableExecutorService executorService) {
        super(command, executorService);
    }

    public FileSystem getFileSystem() {
        return fileSystem;
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        this.fileSystem = fileSystem;
    }

    @Override
    public void destroy(ChannelSession channel) throws Exception {
        try {
            super.destroy(channel);
        } finally {
            if (fileSystem != null) {
                try {
                    fileSystem.close();
                } catch (UnsupportedOperationException | IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("destroy({}) - failed ({}) to close file system={}: {}",
                                this, e.getClass().getSimpleName(), fileSystem, e.getMessage());
                    }
                } finally {
                    fileSystem = null;
                }
            }
        }
    }
}
