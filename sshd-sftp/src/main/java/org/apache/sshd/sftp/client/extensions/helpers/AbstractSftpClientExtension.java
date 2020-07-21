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
import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Handle;
import org.apache.sshd.sftp.client.extensions.SftpClientExtension;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpClientExtension extends AbstractLoggingBean implements SftpClientExtension, RawSftpClient {
    private final String name;
    private final SftpClient client;
    private final RawSftpClient raw;
    private final boolean supported;

    protected AbstractSftpClientExtension(String name, SftpClient client, RawSftpClient raw, Collection<String> extras) {
        this(name, client, raw, GenericUtils.isNotEmpty(extras) && extras.contains(name));
    }

    protected AbstractSftpClientExtension(String name, SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions) {
        this(name, client, raw, GenericUtils.isNotEmpty(extensions) && extensions.containsKey(name));
    }

    protected AbstractSftpClientExtension(String name, SftpClient client, RawSftpClient raw, boolean supported) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No extension name");
        this.client = Objects.requireNonNull(client, "No client instance");
        this.raw = Objects.requireNonNull(raw, "No raw access");
        this.supported = supported;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final SftpClient getClient() {
        return client;
    }

    protected void sendAndCheckExtendedCommandStatus(Buffer buffer) throws IOException {
        int reqId = sendExtendedCommand(buffer);
        if (log.isDebugEnabled()) {
            log.debug("sendAndCheckExtendedCommandStatus(" + getName() + ") id=" + reqId);
        }
        checkStatus(receive(reqId));
    }

    protected int sendExtendedCommand(Buffer buffer) throws IOException {
        return send(SftpConstants.SSH_FXP_EXTENDED, buffer);
    }

    @Override
    public int send(int cmd, Buffer buffer) throws IOException {
        return raw.send(cmd, buffer);
    }

    @Override
    public Buffer receive(int id) throws IOException {
        return raw.receive(id);
    }

    @Override
    public Buffer receive(int id, long timeout) throws IOException {
        return raw.receive(id, timeout);
    }

    @Override
    public Buffer receive(int id, Duration timeout) throws IOException {
        return raw.receive(id, timeout);
    }

    @Override
    public final boolean isSupported() {
        return supported;
    }

    protected void checkStatus(Buffer buffer) throws IOException {
        if (checkExtendedReplyBuffer(buffer) != null) {
            throw new StreamCorruptedException("Unexpected extended reply received");
        }
    }

    /**
     * @param  buffer                        The {@link Buffer}
     * @param  target                        A target path {@link String} or {@link Handle} or {@code byte[]} to be
     *                                       encoded in the buffer
     * @return                               The updated buffer
     * @throws UnsupportedOperationException If target is not one of the above supported types
     */
    public Buffer putTarget(Buffer buffer, Object target) {
        if (target instanceof CharSequence) {
            buffer.putString(target.toString());
        } else if (target instanceof byte[]) {
            buffer.putBytes((byte[]) target);
        } else if (target instanceof Handle) {
            buffer.putBytes(((Handle) target).getIdentifier());
        } else {
            throw new UnsupportedOperationException("Unknown target type: " + target);
        }

        return buffer;
    }

    /**
     * @param  target A target path {@link String} or {@link Handle} or {@code byte[]} to be encoded in the buffer
     * @return        A {@link Buffer} with the extension name set
     * @see           #getCommandBuffer(Object, int)
     */
    protected Buffer getCommandBuffer(Object target) {
        return getCommandBuffer(target, 0);
    }

    /**
     * @param  target    A target path {@link String} or {@link Handle} or {@code byte[]} to be encoded in the buffer
     * @param  extraSize Extra size - beyond the path/handle to be allocated
     * @return           A {@link Buffer} with the extension name set
     * @see              #getCommandBuffer(int)
     */
    protected Buffer getCommandBuffer(Object target, int extraSize) {
        if (target instanceof CharSequence) {
            return getCommandBuffer(Integer.BYTES + ((CharSequence) target).length() + extraSize);
        } else if (target instanceof byte[]) {
            return getCommandBuffer(Integer.BYTES + ((byte[]) target).length + extraSize);
        } else if (target instanceof Handle) {
            return getCommandBuffer(Integer.BYTES + ((Handle) target).length() + extraSize);
        } else {
            return getCommandBuffer(extraSize);
        }
    }

    /**
     * @param  extraSize Extra size - besides the extension name
     * @return           A {@link Buffer} with the extension name set
     */
    protected Buffer getCommandBuffer(int extraSize) {
        String opcode = getName();
        Buffer buffer = new ByteArrayBuffer(Integer.BYTES + GenericUtils.length(opcode) + extraSize + Byte.SIZE, false);
        buffer.putString(opcode);
        return buffer;
    }

    /**
     * @param  buffer      The {@link Buffer} to check
     * @return             The {@link Buffer} if this is an {@link SftpConstants#SSH_FXP_EXTENDED_REPLY}, or
     *                     {@code null} if this is a {@link SftpConstants#SSH_FXP_STATUS} carrying an
     *                     {@link SftpConstants#SSH_FX_OK} result
     * @throws IOException If a non-{@link SftpConstants#SSH_FX_OK} result or not a
     *                     {@link SftpConstants#SSH_FXP_EXTENDED_REPLY} buffer
     */
    protected Buffer checkExtendedReplyBuffer(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        validateIncomingResponse(SftpConstants.SSH_FXP_EXTENDED, id, type, length, buffer);

        if (type == SftpConstants.SSH_FXP_STATUS) {
            int substatus = buffer.getInt();
            String msg = buffer.getString();
            String lang = buffer.getString();
            if (log.isDebugEnabled()) {
                log.debug("checkExtendedReplyBuffer({})[id={}] - status: {} [{}] {}",
                        getName(), id, substatus, lang, msg);
            }

            if (substatus != SftpConstants.SSH_FX_OK) {
                throwStatusException(id, substatus, msg, lang);
            }

            return null;
        } else if (type == SftpConstants.SSH_FXP_EXTENDED_REPLY) {
            return buffer;
        } else {
            throw new SshException("Unexpected SFTP packet received: type=" + type + ", id=" + id + ", length=" + length);
        }
    }

    protected void validateIncomingResponse(
            int cmd, int id, int type, int length, Buffer buffer)
            throws IOException {
        int remaining = buffer.available();
        if ((length < 0) || (length > (remaining + 5 /* type + id */))) {
            throw new SshException(
                    "Bad length (" + length + ") for remaining data (" + remaining + ")"
                                   + " in response to " + SftpConstants.getCommandMessageName(cmd)
                                   + ": type=" + SftpConstants.getCommandMessageName(type) + ", id=" + id);
        }
    }

    protected void throwStatusException(int id, int substatus, String msg, String lang) throws IOException {
        throw new SftpException(substatus, msg);
    }
}
