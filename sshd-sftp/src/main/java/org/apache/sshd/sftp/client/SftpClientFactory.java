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
package org.apache.sshd.sftp.client;

import java.io.IOException;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.apache.sshd.sftp.client.impl.DefaultSftpClientFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpClientFactory {

    static SftpClientFactory instance() {
        return DefaultSftpClientFactory.INSTANCE;
    }

    /**
     * Create an SFTP client from this session.
     *
     * @param  session     The {@link ClientSession} to be used for creating the SFTP client
     * @return             The created {@link SftpClient}
     * @throws IOException if failed to create the client
     */
    default SftpClient createSftpClient(ClientSession session) throws IOException {
        return createSftpClient(session, SftpVersionSelector.CURRENT);
    }

    /**
     * Creates an SFTP client using the specified version
     *
     * @param  session     The {@link ClientSession} to be used for creating the SFTP client
     * @param  version     The version to use - <B>Note:</B> if the specified version is not supported by the server
     *                     then an exception will occur
     * @return             The created {@link SftpClient}
     * @throws IOException If failed to create the client or use the specified version
     */
    default SftpClient createSftpClient(ClientSession session, int version) throws IOException {
        return createSftpClient(session, SftpVersionSelector.fixedVersionSelector(version));
    }

    /**
     * @param  session     The {@link ClientSession} to which the SFTP client should be attached
     * @param  selector    The {@link SftpVersionSelector} to use in order to negotiate the SFTP version
     * @return             The created {@link SftpClient} instance
     * @throws IOException If failed to create the client
     */
    SftpClient createSftpClient(ClientSession session, SftpVersionSelector selector) throws IOException;

    default SftpFileSystem createSftpFileSystem(ClientSession session) throws IOException {
        return createSftpFileSystem(session, SftpVersionSelector.CURRENT);
    }

    default SftpFileSystem createSftpFileSystem(ClientSession session, int version) throws IOException {
        return createSftpFileSystem(session, SftpVersionSelector.fixedVersionSelector(version));
    }

    default SftpFileSystem createSftpFileSystem(ClientSession session, SftpVersionSelector selector) throws IOException {
        return createSftpFileSystem(session, selector, 0, 0);
    }

    default SftpFileSystem createSftpFileSystem(ClientSession session, int version, int readBufferSize, int writeBufferSize)
            throws IOException {
        return createSftpFileSystem(session, SftpVersionSelector.fixedVersionSelector(version), readBufferSize,
                writeBufferSize);
    }

    default SftpFileSystem createSftpFileSystem(ClientSession session, int readBufferSize, int writeBufferSize)
            throws IOException {
        return createSftpFileSystem(session, SftpVersionSelector.CURRENT, readBufferSize, writeBufferSize);
    }

    /**
     * @param  session         The {@link ClientSession} to which the SFTP client backing the file system should be
     *                         attached
     * @param  selector        The {@link SftpVersionSelector} to use in order to negotiate the SFTP version
     * @param  readBufferSize  Default I/O read buffer size
     * @param  writeBufferSize Default I/O write buffer size
     * @return                 The created {@link SftpFileSystem} instance
     * @throws IOException     If failed to create the instance
     */
    SftpFileSystem createSftpFileSystem(
            ClientSession session, SftpVersionSelector selector, int readBufferSize, int writeBufferSize)
            throws IOException;
}
