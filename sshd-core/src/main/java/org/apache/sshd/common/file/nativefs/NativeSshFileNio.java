/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.file.nativefs;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * <strong>Internal class, do not use directly.</strong>
 * 
 * This class wraps native file object.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeSshFileNio extends NativeSshFile {

    /**
     * Constructor, internal do not use directly.
     * @param nativeFileSystemView
     */
    public NativeSshFileNio(NativeFileSystemView nativeFileSystemView, String fileName, File file, String userName) {
        super(nativeFileSystemView, fileName, file, userName);
    }

    public Map<Attribute, Object> getAttributes(boolean followLinks) throws IOException {
        Map<String, Object> a = Files.readAttributes(
                file.toPath(),
                "unix:size,uid,owner,gid,group,isDirectory,isRegularFile,isSymbolicLink,permissions,creationTime,lastModifiedTime,lastAccessTime",
                followLinks ? new LinkOption[0] : new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
        Map<Attribute, Object> map = new HashMap<Attribute, Object>();
        map.put(Attribute.Size, a.get("size"));
        map.put(Attribute.Uid, a.get("uid"));
        map.put(Attribute.Owner, ((UserPrincipal) a.get("owner")).getName());
        map.put(Attribute.Gid, a.get("gid"));
        map.put(Attribute.Group, ((GroupPrincipal) a.get("group")).getName());
        map.put(Attribute.IsDirectory, a.get("isDirectory"));
        map.put(Attribute.IsRegularFile, a.get("isRegularFile"));
        map.put(Attribute.IsSymbolicLink, a.get("isSymbolicLink"));
        map.put(Attribute.CreationTime, ((FileTime) a.get("creationTime")).toMillis());
        map.put(Attribute.LastModifiedTime, ((FileTime) a.get("lastModifiedTime")).toMillis());
        map.put(Attribute.LastAccessTime, ((FileTime) a.get("lastAccessTime")).toMillis());
        map.put(Attribute.Permissions, fromPerms((Set<PosixFilePermission>) a.get("permissions")));
        return map;
    }

    public void setAttributes(Map<Attribute, Object> attributes) throws IOException {
        for (Attribute attribute : attributes.keySet()) {
            String name = null;
            Object value = attributes.get(attribute);
            switch (attribute) {
                case Size:             {
                    long newSize = (Long) value;
                    FileChannel outChan = new FileOutputStream(file, true).getChannel();
                    outChan.truncate(newSize);
                    outChan.close();
                    continue;
                }
                case Uid:              name = "unix:uid"; break;
                case Owner:            name = "unix:owner"; value = toUser((String) value); break;
                case Gid:              name = "unix:gid"; break;
                case Group:            name = "unix:group"; value = toGroup((String) value); break;
                case Permissions:      name = "unix:permissions"; value = toPerms((EnumSet<Permission>) value); break;
                case CreationTime:     name = "unix:creationTime"; value = FileTime.fromMillis((Long) value); break;
                case LastModifiedTime: name = "unix:lastModifiedTime"; value = FileTime.fromMillis((Long) value); break;
                case LastAccessTime:   name = "unix:lastAccessTime"; value = FileTime.fromMillis((Long) value); break;
            }
            if (name != null && value != null) {
                Files.setAttribute(file.toPath(), name, value, LinkOption.NOFOLLOW_LINKS);
            }
        }
    }

    public String readSymbolicLink() throws IOException {
        Path path = file.toPath();
        Path link = Files.readSymbolicLink(path);
        return link.toString();
    }

    private EnumSet<Permission> fromPerms(Set<PosixFilePermission> perms) {
        EnumSet<Permission> p = EnumSet.noneOf(Permission.class);
        for (PosixFilePermission perm : perms) {
            switch (perm) {
                case OWNER_READ:     p.add(Permission.UserRead); break;
                case OWNER_WRITE:    p.add(Permission.UserWrite); break;
                case OWNER_EXECUTE:  p.add(Permission.UserExecute); break;
                case GROUP_READ:     p.add(Permission.GroupRead); break;
                case GROUP_WRITE:    p.add(Permission.GroupWrite); break;
                case GROUP_EXECUTE:  p.add(Permission.GroupExecute); break;
                case OTHERS_READ:    p.add(Permission.OthersRead); break;
                case OTHERS_WRITE:   p.add(Permission.OthersWrite); break;
                case OTHERS_EXECUTE: p.add(Permission.OthersExecute); break;
            }
        }
        return p;
    }

    private GroupPrincipal toGroup(String name) throws IOException {
        UserPrincipalLookupService lookupService = file.toPath().getFileSystem().getUserPrincipalLookupService();
        return lookupService.lookupPrincipalByGroupName(name);
    }

    private UserPrincipal toUser(String name) throws IOException {
        UserPrincipalLookupService lookupService = file.toPath().getFileSystem().getUserPrincipalLookupService();
        return lookupService.lookupPrincipalByName(name);
    }

    private Set<PosixFilePermission> toPerms(EnumSet<Permission> perms) {
        Set<PosixFilePermission> set = new HashSet<PosixFilePermission>();
        for (Permission p : perms) {
            switch (p) {
                case UserRead:      set.add(PosixFilePermission.OWNER_READ); break;
                case UserWrite:     set.add(PosixFilePermission.OWNER_WRITE); break;
                case UserExecute:   set.add(PosixFilePermission.OWNER_EXECUTE); break;
                case GroupRead:     set.add(PosixFilePermission.GROUP_READ); break;
                case GroupWrite:    set.add(PosixFilePermission.GROUP_WRITE); break;
                case GroupExecute:  set.add(PosixFilePermission.GROUP_EXECUTE); break;
                case OthersRead:    set.add(PosixFilePermission.OTHERS_READ); break;
                case OthersWrite:   set.add(PosixFilePermission.OTHERS_WRITE); break;
                case OthersExecute: set.add(PosixFilePermission.OTHERS_EXECUTE); break;
            }
        }
        return set;
    }

}
