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

package org.apache.sshd.client.subsystem.sftp.extensions.openssh.helpers;

import java.io.IOException;
import java.util.Map;

import org.apache.sshd.client.subsystem.sftp.RawSftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient;
import org.apache.sshd.client.subsystem.sftp.SftpClient.Handle;
import org.apache.sshd.client.subsystem.sftp.extensions.openssh.OpenSSHStatExtensionInfo;
import org.apache.sshd.client.subsystem.sftp.extensions.openssh.OpenSSHStatHandleExtension;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.FstatVfsExtensionParser;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHStatHandleExtensionImpl extends AbstractOpenSSHStatCommandExtension implements OpenSSHStatHandleExtension {
    public OpenSSHStatHandleExtensionImpl(SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions) {
        super(FstatVfsExtensionParser.NAME, client, raw, extensions);
    }

    @Override
    public OpenSSHStatExtensionInfo stat(Handle handle) throws IOException {
        return doGetStat(handle.getIdentifier());
    }
}
