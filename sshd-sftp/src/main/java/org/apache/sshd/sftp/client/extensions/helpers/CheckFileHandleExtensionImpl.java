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
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;

import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Handle;
import org.apache.sshd.sftp.client.extensions.CheckFileHandleExtension;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * Implements &quot;check-file-handle&quot; extension
 *
 * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
 *         - section 9.1.2</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CheckFileHandleExtensionImpl extends AbstractCheckFileExtension implements CheckFileHandleExtension {
    public CheckFileHandleExtensionImpl(SftpClient client, RawSftpClient raw, Collection<String> extras) {
        super(SftpConstants.EXT_CHECK_FILE_HANDLE, client, raw, extras);
    }

    @Override
    public SimpleImmutableEntry<String, Collection<byte[]>> checkFileHandle(
            Handle handle, Collection<String> algorithms, long startOffset, long length, int blockSize)
            throws IOException {
        return doGetHash(handle.getIdentifier(), algorithms, startOffset, length, blockSize);
    }
}
