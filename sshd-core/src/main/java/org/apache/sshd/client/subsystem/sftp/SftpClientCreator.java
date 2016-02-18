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

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpClientCreator {
    /**
     * Create an SFTP client from this session.
     *
     * @return The created {@link SftpClient}
     * @throws IOException if failed to create the client
     */
    SftpClient createSftpClient() throws IOException;

    /**
     * Creates an SFTP client using the specified version
     *
     * @param version The version to use - <B>Note:</B> if the specified
     *                version is not supported by the server then an exception
     *                will occur
     * @return The created {@link SftpClient}
     * @throws IOException If failed to create the client or use the specified version
     */
    SftpClient createSftpClient(int version) throws IOException;

    /**
     * Creates an SFTP client while allowing the selection of a specific version
     *
     * @param selector The {@link SftpVersionSelector} to use - <B>Note:</B>
     *                 if the server does not support versions re-negotiation then the
     *                 selector will be presented with only one &quot;choice&quot; - the
     *                 current version
     * @return The created {@link SftpClient}
     * @throws IOException If failed to create the client or re-negotiate
     */
    SftpClient createSftpClient(SftpVersionSelector selector) throws IOException;

    FileSystem createSftpFileSystem() throws IOException;

    FileSystem createSftpFileSystem(int version) throws IOException;

    FileSystem createSftpFileSystem(SftpVersionSelector selector) throws IOException;

    FileSystem createSftpFileSystem(int readBufferSize, int writeBufferSize) throws IOException;

    FileSystem createSftpFileSystem(int version, int readBufferSize, int writeBufferSize) throws IOException;

    FileSystem createSftpFileSystem(SftpVersionSelector selector, int readBufferSize, int writeBufferSize) throws IOException;
}
