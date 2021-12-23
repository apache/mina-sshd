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

package org.apache.sshd.sftp.client.extensions.openssh;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.SftpModuleProperties;

/**
 * Response for the &quot;limits@openssh.com&quot; request
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH - section 4.8</A>
 */
public class OpenSSHLimitsExtensionInfo implements Cloneable {
    // CHECKSTYLE:OFF
    /** The total number of bytes in a single SFTP packet. */
    public long maxPacketLength;

    /**
     * The largest length in a SSH_FXP_READ packet. Even if the client requests a larger size,\
     * servers will usually respond with a shorter SSH_FXP_DATA packet
     */
    public long maxReadLength;

    /** The largest length in a SSH_FXP_WRITE packet the server will accept */
    public long maxWriteLength;

    /**
     * The maximum number of active handles that the server allows (e.g. handles created
     * by SSH_FXP_OPEN and SSH_FXP_OPENDIR packets). If the server doesn't enforce a
     * specific limit, then the field may be set to 0. This implies the server relies on
     * the OS to enforce limits (e.g. available memory or file handles), and such limits
     * might be dynamic. The client SHOULD take care to not try to exceed reasonable limits.
     */
    public long maxOpenHandles;
    // CHECKSTYLE:ON

    public OpenSSHLimitsExtensionInfo() {
        super();
    }

    public OpenSSHLimitsExtensionInfo(Buffer buffer) {
        decode(buffer, this);
    }

    public OpenSSHLimitsExtensionInfo(PropertyResolver resolver) {
        fill(resolver, this);
    }

    public <B extends Buffer> B encode(B buffer) {
        return encode(buffer, this);
    }

    @Override
    public int hashCode() {
        return NumberUtils.hashCode(maxPacketLength, maxReadLength, maxWriteLength, maxOpenHandles);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        OpenSSHLimitsExtensionInfo other = (OpenSSHLimitsExtensionInfo) obj;
        return (this.maxPacketLength == other.maxPacketLength)
                && (this.maxReadLength == other.maxReadLength)
                && (this.maxWriteLength == other.maxWriteLength)
                && (this.maxOpenHandles == other.maxOpenHandles);
    }

    @Override
    public OpenSSHLimitsExtensionInfo clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Failed to close " + toString() + ": " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "maxPacketLength=" + maxPacketLength
               + ", maxReadLength=" + maxReadLength
               + ", maxWriteLength=" + maxWriteLength
               + ", maxOpenHandles=" + maxOpenHandles;
    }

    public static <B extends Buffer> B encode(B buffer, OpenSSHLimitsExtensionInfo info) {
        buffer.putLong(info.maxPacketLength);
        buffer.putLong(info.maxReadLength);
        buffer.putLong(info.maxWriteLength);
        buffer.putLong(info.maxOpenHandles);
        return buffer;
    }

    public static <I extends OpenSSHLimitsExtensionInfo> I decode(Buffer buffer, I info) {
        info.maxPacketLength = buffer.getLong();
        info.maxReadLength = buffer.getLong();
        info.maxWriteLength = buffer.getLong();
        info.maxOpenHandles = buffer.getLong();
        return info;
    }

    public static <I extends OpenSSHLimitsExtensionInfo> I fill(PropertyResolver resolver, I info) {
        info.maxReadLength = SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.getRequired(resolver);
        info.maxWriteLength = SftpModuleProperties.MAX_WRITEDATA_PACKET_LENGTH.getRequired(resolver);
        info.maxPacketLength = Math.max(info.maxReadLength, info.maxWriteLength)
                               + SshConstants.SSH_PACKET_HEADER_LEN
                               + (3 * Integer.BYTES)   // id, type, len
        ;
        info.maxOpenHandles = SftpModuleProperties.MAX_OPEN_HANDLES_PER_SESSION.getRequired(resolver);
        /*
         * Quote:
         *
         *      If the server doesn't enforce a specific limit, then the field may be set to 0.
         *      This implies the server relies on the OS to enforce limits.
         */
        if (info.maxOpenHandles >= (Integer.MAX_VALUE - 1)) {
            info.maxOpenHandles = 0;
        }
        return info;
    }
}
