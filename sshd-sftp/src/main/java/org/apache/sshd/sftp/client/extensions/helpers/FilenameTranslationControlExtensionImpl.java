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
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.FilenameTranslationControlExtension;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * Implements &quot;filename-translation-control&quot; extension command
 *
 * @see    <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-16">DRAFT 13 - page 16</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FilenameTranslationControlExtensionImpl
        extends AbstractSftpClientExtension
        implements FilenameTranslationControlExtension {
    public FilenameTranslationControlExtensionImpl(SftpClient client, RawSftpClient raw, Collection<String> extras) {
        super(SftpConstants.EXT_FILENAME_XLATE_CONTROL, client, raw,
              GenericUtils.isNotEmpty(extras) && extras.contains(SftpConstants.EXT_FILENAME_CHARSET));
    }

    public FilenameTranslationControlExtensionImpl(SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions) {
        super(SftpConstants.EXT_FILENAME_XLATE_CONTROL, client, raw,
              MapEntryUtils.isNotEmpty(extensions) && extensions.containsKey(SftpConstants.EXT_FILENAME_CHARSET));
    }

    @Override
    public void setFilenameTranslationControl(boolean doTranslate) throws IOException {
        Buffer request = getCommandBuffer(Byte.SIZE);
        request.putBoolean(doTranslate);
        if (log.isDebugEnabled()) {
            log.debug("setFilenameTranslationControl({}) doTranslate={}", getName(), doTranslate);
        }

        int id = sendExtendedCommand(request);
        Buffer response = receive(id);
        response = checkExtendedReplyBuffer(response);
        if (response != null) {
            throw new StreamCorruptedException("Unexpected extended reply data");
        }
    }
}
