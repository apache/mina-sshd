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

package org.apache.sshd.sftp.client.extensions.helpers;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.util.Collection;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.SpaceAvailableExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.SpaceAvailableExtensionInfo;

/**
 * Implements &quot;space-available&quot; extension
 *
 * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
 *         - section 9.3</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SpaceAvailableExtensionImpl extends AbstractSftpClientExtension implements SpaceAvailableExtension {
    public SpaceAvailableExtensionImpl(SftpClient client, RawSftpClient raw, Collection<String> extra) {
        super(SftpConstants.EXT_SPACE_AVAILABLE, client, raw, extra);
    }

    @Override
    public SpaceAvailableExtensionInfo available(String path) throws IOException {
        Buffer buffer = getCommandBuffer(path);
        buffer.putString(path);
        buffer = checkExtendedReplyBuffer(receive(sendExtendedCommand(buffer)));

        if (buffer == null) {
            throw new StreamCorruptedException("Missing extended reply data");
        }

        return new SpaceAvailableExtensionInfo(buffer);
    }
}
