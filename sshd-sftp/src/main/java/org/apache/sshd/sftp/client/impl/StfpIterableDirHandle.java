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

import java.util.Objects;

import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClient.Handle;

public class StfpIterableDirHandle implements Iterable<DirEntry> {
    private final SftpClient client;
    private final Handle handle;

    /**
     * @param client The {@link SftpClient} to use for iteration
     * @param handle The remote directory {@link Handle}
     */
    public StfpIterableDirHandle(SftpClient client, Handle handle) {
        this.client = Objects.requireNonNull(client, "No client instance");
        this.handle = handle;
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
     * @return The remote directory {@link Handle}
     */
    public final Handle getHandle() {
        return handle;
    }

    @Override
    public SftpDirEntryIterator iterator() {
        return new SftpDirEntryIterator(getClient(), getHandle());
    }
}
