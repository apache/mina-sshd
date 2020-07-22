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

package org.apache.sshd.sftp.common.extensions;

import java.io.IOException;
import java.nio.file.FileStore;

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT 09
 *         section 9.2</A>
 */
public class SpaceAvailableExtensionInfo implements Cloneable {
    // CHECKSTYLE:OFF
    public long bytesOnDevice;
    public long unusedBytesOnDevice;
    public long bytesAvailableToUser;
    public long unusedBytesAvailableToUser;
    public int bytesPerAllocationUnit;
    // CHECKSTYLE:ON

    public SpaceAvailableExtensionInfo() {
        super();
    }

    public SpaceAvailableExtensionInfo(Buffer buffer) {
        decode(buffer, this);
    }

    public SpaceAvailableExtensionInfo(FileStore store) throws IOException {
        bytesOnDevice = store.getTotalSpace();

        long unallocated = store.getUnallocatedSpace();
        long usable = store.getUsableSpace();
        unusedBytesOnDevice = Math.max(unallocated, usable);

        // the rest are intentionally left zero indicating "UNKNOWN"
    }

    @Override
    public int hashCode() {
        return NumberUtils.hashCode(bytesOnDevice, unusedBytesOnDevice,
                bytesAvailableToUser, unusedBytesAvailableToUser,
                bytesPerAllocationUnit);
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

        SpaceAvailableExtensionInfo other = (SpaceAvailableExtensionInfo) obj;
        return this.bytesOnDevice == other.bytesOnDevice
                && this.unusedBytesOnDevice == other.unusedBytesOnDevice
                && this.bytesAvailableToUser == other.bytesAvailableToUser
                && this.unusedBytesAvailableToUser == other.unusedBytesAvailableToUser
                && this.bytesPerAllocationUnit == other.bytesPerAllocationUnit;
    }

    @Override
    public SpaceAvailableExtensionInfo clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Failed to close " + toString() + ": " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "bytesOnDevice=" + bytesOnDevice
               + ",unusedBytesOnDevice=" + unusedBytesOnDevice
               + ",bytesAvailableToUser=" + bytesAvailableToUser
               + ",unusedBytesAvailableToUser=" + unusedBytesAvailableToUser
               + ",bytesPerAllocationUnit=" + bytesPerAllocationUnit;
    }

    public static SpaceAvailableExtensionInfo decode(Buffer buffer) {
        SpaceAvailableExtensionInfo info = new SpaceAvailableExtensionInfo();
        decode(buffer, info);
        return info;
    }

    public static void decode(Buffer buffer, SpaceAvailableExtensionInfo info) {
        info.bytesOnDevice = buffer.getLong();
        info.unusedBytesOnDevice = buffer.getLong();
        info.bytesAvailableToUser = buffer.getLong();
        info.unusedBytesAvailableToUser = buffer.getLong();
        info.bytesPerAllocationUnit = buffer.getInt();
    }

    public static void encode(Buffer buffer, SpaceAvailableExtensionInfo info) {
        buffer.putLong(info.bytesOnDevice);
        buffer.putLong(info.unusedBytesOnDevice);
        buffer.putLong(info.bytesAvailableToUser);
        buffer.putLong(info.unusedBytesAvailableToUser);
        buffer.putInt(info.bytesPerAllocationUnit & 0xFFFFFFFFL);
    }
}
