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
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Collection;
import java.util.LinkedList;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractCheckFileExtension extends AbstractSftpClientExtension {
    protected AbstractCheckFileExtension(String name, SftpClient client, RawSftpClient raw, Collection<String> extras) {
        super(name, client, raw, extras);
    }

    protected SimpleImmutableEntry<String, Collection<byte[]>> doGetHash(
            Object target, Collection<String> algorithms, long offset, long length, int blockSize)
            throws IOException {
        Buffer buffer = getCommandBuffer(target, Byte.MAX_VALUE);
        putTarget(buffer, target);
        buffer.putString(GenericUtils.join(algorithms, ','));
        buffer.putLong(offset);
        buffer.putLong(length);
        buffer.putInt(blockSize);

        if (log.isDebugEnabled()) {
            log.debug("doGetHash({})[{}] - offset={}, length={}, block-size={}",
                    getName(),
                    (target instanceof CharSequence)
                            ? target : BufferUtils.toHex(BufferUtils.EMPTY_HEX_SEPARATOR, (byte[]) target),
                    offset, length, blockSize);
        }

        buffer = checkExtendedReplyBuffer(receive(sendExtendedCommand(buffer)));
        if (buffer == null) {
            throw new StreamCorruptedException("Missing extended reply data");
        }

        String targetType = buffer.getString();
        if (String.CASE_INSENSITIVE_ORDER.compare(targetType, SftpConstants.EXT_CHECK_FILE) != 0) {
            throw new StreamCorruptedException(
                    "Mismatched reply type: expected=" + SftpConstants.EXT_CHECK_FILE + ", actual=" + targetType);
        }

        String algo = buffer.getString();
        Collection<byte[]> hashes = new LinkedList<>();
        while (buffer.available() > 0) {
            byte[] hashValue = buffer.getBytes();
            hashes.add(hashValue);
        }

        return new SimpleImmutableEntry<>(algo, hashes);
    }
}
