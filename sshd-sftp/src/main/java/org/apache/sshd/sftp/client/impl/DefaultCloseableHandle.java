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
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.CloseableHandle;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultCloseableHandle extends CloseableHandle {
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final SftpClient client;

    public DefaultCloseableHandle(SftpClient client, String path, byte[] id) {
        super(path, id);
        this.client = ValidateUtils.checkNotNull(client, "No client for path=%s", path);
    }

    public final SftpClient getSftpClient() {
        return client;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            client.close(this);
        }
    }

    @Override // to avoid Findbugs[EQ_DOESNT_OVERRIDE_EQUALS]
    public int hashCode() {
        return super.hashCode();
    }

    @Override // to avoid Findbugs[EQ_DOESNT_OVERRIDE_EQUALS]
    public boolean equals(Object obj) {
        return super.equals(obj);
    }
}
