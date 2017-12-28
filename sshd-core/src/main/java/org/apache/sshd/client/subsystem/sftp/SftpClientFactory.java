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
import java.nio.file.FileSystem;

import org.apache.sshd.client.session.ClientSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpClientFactory {
    /**
     * @param session The {@link ClientSession} to which the SFTP client should be attached
     * @param selector The {@link SftpVersionSelector} to use in order to negotiate the SFTP version
     * @return The created {@link SftpClient} instance
     * @throws IOException If failed to create the client
     */
    SftpClient createSftpClient(ClientSession session, SftpVersionSelector selector) throws IOException;

    /**
     * @param session The {@link ClientSession} to which the SFTP client backing the file system should be attached
     * @param selector The {@link SftpVersionSelector} to use in order to negotiate the SFTP version
     * @param readBufferSize Default I/O read buffer size
     * @param writeBufferSize Default I/O write buffer size
     * @return The created {@link FileSystem} instance
     * @throws IOException If failed to create the instance
     */
    FileSystem createSftpFileSystem(
        ClientSession session, SftpVersionSelector selector, int readBufferSize, int writeBufferSize)
            throws IOException;
}
