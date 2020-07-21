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
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;

/**
 * Provides an {@link Iterable} implementation of the {@link DirEntry}-ies for a remote directory
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpIterableDirEntry implements Iterable<DirEntry> {
    private final SftpClient client;
    private final String path;

    /**
     * @param client The {@link SftpClient} instance to use for the iteration
     * @param path   The remote directory path
     */
    public SftpIterableDirEntry(SftpClient client, String path) {
        this.client = Objects.requireNonNull(client, "No client instance");
        this.path = ValidateUtils.checkNotNullAndNotEmpty(path, "No remote path");
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote file
     */
    public final SftpClient getClient() {
        return client;
    }

    /**
     * The remotely accessed directory path
     *
     * @return Remote directory path
     */
    public final String getPath() {
        return path;
    }

    @Override
    public SftpDirEntryIterator iterator() {
        try {
            return new SftpDirEntryIterator(getClient(), getPath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
