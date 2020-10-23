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
package org.apache.sshd.sftp.client.impl;

import java.io.IOException;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;

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
        } catch (IOException | RuntimeException | Error e) {
            debug("createSftpClient({}) failed ({}) to negotiate version: {}",
                    session, e.getClass().getSimpleName(), e.getMessage(), e);
            client.close();
            throw e;
        }

        return client;
    }

    protected DefaultSftpClient createDefaultSftpClient(ClientSession session, SftpVersionSelector selector)
            throws IOException {
        return new DefaultSftpClient(session, selector);
    }

    @Override
    public SftpFileSystem createSftpFileSystem(
            ClientSession session, SftpVersionSelector selector, int readBufferSize, int writeBufferSize)
            throws IOException {
        ClientFactoryManager manager = session.getFactoryManager();
        SftpFileSystemProvider provider = new SftpFileSystemProvider((SshClient) manager, selector);
        SftpFileSystem fs = provider.newFileSystem(session);
        if (readBufferSize > 0) {
            fs.setReadBufferSize(readBufferSize);
        }
        if (writeBufferSize > 0) {
            fs.setWriteBufferSize(writeBufferSize);
        }
        return fs;
    }
}
