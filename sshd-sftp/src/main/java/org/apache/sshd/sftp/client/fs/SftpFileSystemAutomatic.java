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

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpErrorDataHandler;
import org.apache.sshd.sftp.client.SftpVersionSelector;

/**
 * An {@link SftpFileSystem} that uses a provider function for its {@link ClientSession} so that it can continue to
 * function even if a session was closed. The provider is supposed to create a new session if the current one is not
 * open.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpFileSystemAutomatic extends SftpFileSystem {

    private final IOFunction<Boolean, ClientSession> sessionProvider;

    public SftpFileSystemAutomatic(SftpFileSystemProvider provider, String id,
                                   IOFunction<Boolean, ClientSession> sessionProvider, SftpClientFactory factory,
                                   SftpVersionSelector selector, SftpErrorDataHandler errorDataHandler)
            throws IOException {
        super(provider, id, factory, selector, errorDataHandler);
        this.sessionProvider = sessionProvider;
        init();
    }

    @Override
    public ClientSession getClientSession() {
        try {
            return sessionProvider.apply(Boolean.FALSE);
        } catch (IOException e) {
            // Cannot occur
            return null;
        }
    }

    @Override
    protected ClientSession sessionForSftpClient() throws IOException {
        if (!isOpen()) {
            throw new IOException("SftpFileSystem is closed" + this);
        }
        ClientSession result = sessionProvider.apply(Boolean.TRUE);
        setClientSession(result);
        return result;
    }

}
