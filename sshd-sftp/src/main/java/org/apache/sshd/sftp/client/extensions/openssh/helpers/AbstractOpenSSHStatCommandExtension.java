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

package org.apache.sshd.sftp.client.extensions.openssh.helpers;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.util.Map;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.helpers.AbstractSftpClientExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatExtensionInfo;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractOpenSSHStatCommandExtension extends AbstractSftpClientExtension {
    protected AbstractOpenSSHStatCommandExtension(String name, SftpClient client, RawSftpClient raw,
                                                  Map<String, byte[]> extensions) {
        super(name, client, raw, extensions);
    }

    protected OpenSSHStatExtensionInfo doGetStat(Object target) throws IOException {
        Buffer buffer = getCommandBuffer(target);
        putTarget(buffer, target);

        if (log.isDebugEnabled()) {
            log.debug("doGetStat({})[{}]", getName(),
                    (target instanceof CharSequence)
                            ? target : BufferUtils.toHex(BufferUtils.EMPTY_HEX_SEPARATOR, (byte[]) target));
        }

        buffer = checkExtendedReplyBuffer(receive(sendExtendedCommand(buffer)));
        if (buffer == null) {
            throw new StreamCorruptedException("Missing extended reply data");
        }

        return new OpenSSHStatExtensionInfo(buffer);
    }
}
