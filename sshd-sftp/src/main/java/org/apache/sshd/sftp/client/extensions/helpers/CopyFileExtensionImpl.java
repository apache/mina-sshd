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
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.CopyFileExtension;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * Implements the &quot;copy-file&quot; extension
 *
 * @see    <A HREF="http://tools.ietf.org/id/draft-ietf-secsh-filexfer-extensions-00.txt">DRFAT 00 - section 6</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CopyFileExtensionImpl extends AbstractSftpClientExtension implements CopyFileExtension {
    public CopyFileExtensionImpl(SftpClient client, RawSftpClient raw, Collection<String> extra) {
        super(SftpConstants.EXT_COPY_FILE, client, raw, extra);
    }

    @Override
    public void copyFile(String src, String dst, boolean overwriteDestination) throws IOException {
        Buffer buffer = getCommandBuffer(Integer.BYTES + GenericUtils.length(src)
                                         + Integer.BYTES + GenericUtils.length(dst)
                                         + 1 /* override destination */);
        buffer.putString(src);
        buffer.putString(dst);
        buffer.putBoolean(overwriteDestination);
        sendAndCheckExtendedCommandStatus(buffer);
    }
}
