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

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Response for the &quot;statvfs@openssh.com&quot; and &quot;fstatvfs@openssh.com&quot; extension commands.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF=
 *         "http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL?rev=1.28&content-type=text/plain">OpenSSH
 *         section 3.4</A>
 */
public class OpenSSHStatExtensionInfo implements Cloneable {
    // The values of the f_flag bitmask
    public static final long SSH_FXE_STATVFS_ST_RDONLY = 0x1; /* read-only */
    public static final long SSH_FXE_STATVFS_ST_NOSUID = 0x2; /* no setuid */

    // CHECKSTYLE:OFF
    public long f_bsize;     /* file system block size */
    public long f_frsize;    /* fundamental fs block size */
    public long f_blocks;    /* number of blocks (unit f_frsize) */
    public long f_bfree;     /* free blocks in file system */
    public long f_bavail;    /* free blocks for non-root */
    public long f_files;     /* total file inodes */
    public long f_ffree;     /* free file inodes */
    public long f_favail;    /* free file inodes for to non-root */
    public long f_fsid;      /* file system id */
    public long f_flag;      /* bit mask of f_flag values */
    public long f_namemax;   /* maximum filename length */
    // CHECKSTYLE:ON

    public OpenSSHStatExtensionInfo() {
        super();
    }

    public OpenSSHStatExtensionInfo(Buffer buffer) {
        decode(buffer, this);
    }

    @Override
    public int hashCode() {
        return NumberUtils.hashCode(this.f_bsize, this.f_frsize, this.f_blocks,
                this.f_bfree, this.f_bavail, this.f_files, this.f_ffree,
                this.f_favail, this.f_fsid, this.f_flag, this.f_namemax);
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

        OpenSSHStatExtensionInfo other = (OpenSSHStatExtensionInfo) obj;
        // debug breakpoint
        return this.f_bsize == other.f_bsize
                && this.f_frsize == other.f_frsize
                && this.f_blocks == other.f_blocks
                && this.f_bfree == other.f_bfree
                && this.f_bavail == other.f_bavail
                && this.f_files == other.f_files
                && this.f_ffree == other.f_ffree
                && this.f_favail == other.f_favail
                && this.f_fsid == other.f_fsid
                && this.f_flag == other.f_flag
                && this.f_namemax == other.f_namemax;
    }

    @Override
    public OpenSSHStatExtensionInfo clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Failed to close " + toString() + ": " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "f_bsize=" + f_bsize
               + ",f_frsize=" + f_frsize
               + ",f_blocks=" + f_blocks
               + ",f_bfree=" + f_bfree
               + ",f_bavail=" + f_bavail
               + ",f_files=" + f_files
               + ",f_ffree=" + f_ffree
               + ",f_favail=" + f_favail
               + ",f_fsid=" + f_fsid
               + ",f_flag=0x" + Long.toHexString(f_flag)
               + ",f_namemax=" + f_namemax;
    }

    public static void encode(Buffer buffer, OpenSSHStatExtensionInfo info) {
        buffer.putLong(info.f_bsize);
        buffer.putLong(info.f_frsize);
        buffer.putLong(info.f_blocks);
        buffer.putLong(info.f_bfree);
        buffer.putLong(info.f_bavail);
        buffer.putLong(info.f_files);
        buffer.putLong(info.f_ffree);
        buffer.putLong(info.f_favail);
        buffer.putLong(info.f_fsid);
        buffer.putLong(info.f_flag);
        buffer.putLong(info.f_namemax);
    }

    public static OpenSSHStatExtensionInfo decode(Buffer buffer) {
        OpenSSHStatExtensionInfo info = new OpenSSHStatExtensionInfo();
        decode(buffer, info);
        return info;
    }

    public static void decode(Buffer buffer, OpenSSHStatExtensionInfo info) {
        info.f_bsize = buffer.getLong();
        info.f_frsize = buffer.getLong();
        info.f_blocks = buffer.getLong();
        info.f_bfree = buffer.getLong();
        info.f_bavail = buffer.getLong();
        info.f_files = buffer.getLong();
        info.f_ffree = buffer.getLong();
        info.f_favail = buffer.getLong();
        info.f_fsid = buffer.getLong();
        info.f_flag = buffer.getLong();
        info.f_namemax = buffer.getLong();
    }
}
