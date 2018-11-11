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
package org.apache.sshd.client.subsystem.sftp.impl;

import java.io.IOException;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClientFactory;
import org.apache.sshd.client.subsystem.sftp.SftpVersionSelector;
import org.apache.sshd.client.subsystem.sftp.fs.SftpFileSystem;
import org.apache.sshd.client.subsystem.sftp.fs.SftpFileSystemProvider;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultSftpClientFactory extends AbstractLoggingBean implements SftpClientFactory {
    public static final DefaultSftpClientFactory INSTANCE = new DefaultSftpClientFactory();

    public DefaultSftpClientFactory() {
        super();
    }

    @Override
    public SftpClient createSftpClient(ClientSession session, SftpVersionSelector selector) throws IOException {
        DefaultSftpClient client = createDefaultSftpClient(session, selector);
        try {
            client.negotiateVersion(selector);
        } catch (IOException | RuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("createSftpClient({}) failed ({}) to negotiate version: {}",
                          session, e.getClass().getSimpleName(), e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("createSftpClient(" + session + ") version negotiation failure details", e);
            }

            client.close();
            throw e;
        }

        return client;
    }

    protected DefaultSftpClient createDefaultSftpClient(ClientSession session, SftpVersionSelector selector) throws IOException {
        return new DefaultSftpClient(session);
    }

    @Override
    public SftpFileSystem createSftpFileSystem(
            ClientSession session, SftpVersionSelector selector, int readBufferSize, int writeBufferSize)
                throws IOException {
        ClientFactoryManager manager = session.getFactoryManager();
        SftpFileSystemProvider provider = new SftpFileSystemProvider((SshClient) manager, selector);
        SftpFileSystem fs = provider.newFileSystem(session);
        fs.setReadBufferSize(readBufferSize);
        fs.setWriteBufferSize(writeBufferSize);
        return fs;
    }
}
