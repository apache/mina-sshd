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

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractMD5HashExtension extends AbstractSftpClientExtension {
    protected AbstractMD5HashExtension(String name, SftpClient client, RawSftpClient raw, Collection<String> extras) {
        super(name, client, raw, extras);
    }

    protected byte[] doGetHash(Object target, long offset, long length, byte[] quickHash) throws IOException {
        Buffer buffer = getCommandBuffer(target, Long.SIZE + 2 * Long.BYTES + Integer.BYTES + NumberUtils.length(quickHash));
        String opcode = getName();
        putTarget(buffer, target);
        buffer.putLong(offset);
        buffer.putLong(length);
        buffer.putBytes((quickHash == null) ? GenericUtils.EMPTY_BYTE_ARRAY : quickHash);

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doGetHash({})[{}] - offset={}, length={}, quick-hash={}",
                    opcode,
                    (target instanceof CharSequence)
                            ? target : BufferUtils.toHex(BufferUtils.EMPTY_HEX_SEPARATOR, (byte[]) target),
                    offset, length, BufferUtils.toHex(':', quickHash));
        }

        buffer = checkExtendedReplyBuffer(receive(sendExtendedCommand(buffer)));
        if (buffer == null) {
            throw new StreamCorruptedException("Missing extended reply data");
        }

        String targetType = buffer.getString();
        if (String.CASE_INSENSITIVE_ORDER.compare(targetType, opcode) != 0) {
            throw new StreamCorruptedException("Mismatched reply target type: expected=" + opcode + ", actual=" + targetType);
        }

        byte[] hashValue = buffer.getBytes();
        if (debugEnabled) {
            log.debug("doGetHash({})[{}] - offset={}, length={}, quick-hash={} - result={}",
                    opcode, target, offset, length,
                    BufferUtils.toHex(':', quickHash), BufferUtils.toHex(':', hashValue));
        }

        return hashValue;
    }
}
