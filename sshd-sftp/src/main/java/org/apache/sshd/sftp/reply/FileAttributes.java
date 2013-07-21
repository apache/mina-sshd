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
package org.apache.sshd.sftp.reply;

import org.apache.sshd.common.file.SshFile;

import static org.apache.sshd.sftp.subsystem.SftpConstants.*;

/**
 * Data container for file attributes in relies.
 * TODO: implement
 * 
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class FileAttributes {

    int flags = 0;
    byte type;
    long size;
    long allocationSize;
    String owner;
    String group;
    int permissions;
    long accessTime;
    int accessTimeNanos;
    long modifyTime;
    int modifyTimeNanos;
    long createTime;
    int createTimeNanos;
    String acl;
    int attribBits;
    int attribBitsValid;
    byte textHint;
    String mimeType;
    int linkCount;
    String untranslatedName;
    int extended;

    public FileAttributes() {
    }

    public FileAttributes(SshFile file, int flags) {
        // Type
        if (file.isFile()) {
            setType((byte) SSH_FILEXFER_TYPE_REGULAR);
        } else if (file.isDirectory()) {
            setType((byte) SSH_FILEXFER_TYPE_DIRECTORY);
        } else {
            setType((byte) SSH_FILEXFER_TYPE_UNKNOWN);
        }
        // Size
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            setSize(file.getSize());
        }
        // Permissions
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            setPermissions((file.isReadable() ? S_IRUSR : 0) | (file.isWritable() ? S_IWUSR : 0) | (file.isExecutable() ? S_IXUSR : 0));
        }
        // Times
        if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
            setAccessTime(file.getLastModified() / 1000);
        }
        if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
            setCreateTime(file.getLastModified() / 1000);
        }
        if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
            setModifyTime(file.getLastModified() / 1000);
        }
    }

    public int getFlags() {
        return flags;
    }

    public byte getType() {
        return type;
    }

    public void setType(byte type) {
        this.type = type;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.flags |= SSH_FILEXFER_ATTR_SIZE;
        this.size = size;
    }

    public long getAllocationSize() {
        return allocationSize;
    }

    public void setAllocationSize(long allocationSize) {
        this.flags |= SSH_FILEXFER_ATTR_ALLOCATION_SIZE;
        this.allocationSize = allocationSize;
    }

    public String getOwner() {
        return owner;
    }

    public String getGroup() {
        return group;
    }

    public void setOwnerGroup(String owner, String group) {
        this.flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
        this.owner = owner;
        this.group = group;
    }

    public int getPermissions() {
        return permissions;
    }

    public void setPermissions(int permissions) {
        this.flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        this.permissions = permissions;
    }

    public long getAccessTime() {
        return accessTime;
    }

    public void setAccessTime(long accessTime) {
        this.flags |= SSH_FILEXFER_ATTR_ACCESSTIME;
        this.accessTime = accessTime;
    }

    public long getModifyTime() {
        return modifyTime;
    }

    public void setModifyTime(long modifyTime) {
        this.flags |= SSH_FILEXFER_ATTR_MODIFYTIME;
        this.modifyTime = modifyTime;
    }

    public long getCreateTime() {
        return createTime;
    }

    public void setCreateTime(long createTime) {
        this.flags |= SSH_FILEXFER_ATTR_CREATETIME;
        this.createTime = createTime;
    }
}
