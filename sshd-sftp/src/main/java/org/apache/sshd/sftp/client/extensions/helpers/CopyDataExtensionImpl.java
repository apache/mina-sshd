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

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Handle;
import org.apache.sshd.sftp.client.extensions.CopyDataExtension;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * Implements the &quot;copy-data&quot; extension
 *
 * @see    <A HREF="http://tools.ietf.org/id/draft-ietf-secsh-filexfer-extensions-00.txt">DRFAT 00 - section 7</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CopyDataExtensionImpl extends AbstractSftpClientExtension implements CopyDataExtension {
    public CopyDataExtensionImpl(SftpClient client, RawSftpClient raw, Collection<String> extra) {
        super(SftpConstants.EXT_COPY_DATA, client, raw, extra);
    }

    @Override
    public void copyData(Handle readHandle, long readOffset, long readLength, Handle writeHandle, long writeOffset)
            throws IOException {
        byte[] srcId = readHandle.getIdentifier();
        byte[] dstId = writeHandle.getIdentifier();
        Buffer buffer = getCommandBuffer(Integer.BYTES + NumberUtils.length(srcId)
                                         + Integer.BYTES + NumberUtils.length(dstId)
                                         + (3 * (Long.SIZE + Integer.BYTES)));
        buffer.putBytes(srcId);
        buffer.putLong(readOffset);
        buffer.putLong(readLength);
        buffer.putBytes(dstId);
        buffer.putLong(writeOffset);
        sendAndCheckExtendedCommandStatus(buffer);
    }
}
