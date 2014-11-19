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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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

import org.apache.sshd.common.file.SshFile;

/**
 * <strong>Internal class, do not use directly.</strong>
 * 
 * This class wraps native file object.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeSshFileNio extends NativeSshFile {

    @Override
    public boolean doesExist() {
        return Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS);
    }

    /**
     * Constructor, internal do not use directly.
     * @param nativeFileSystemView
     */
    public NativeSshFileNio(NativeFileSystemView nativeFileSystemView, String fileName, File file, String userName) {
        super(nativeFileSystemView, fileName, file, userName);
    }

    public Map<Attribute, Object> getAttributes(boolean followLinks) throws IOException {
        String[] attrs = new String[] { "unix:*", "posix:*", "*" };
        Map<String, Object> a = null;
        for (String attr : attrs) {
            try {
                a = Files.readAttributes(
                        file.toPath(), attr,
                        followLinks ? new LinkOption[0] : new LinkOption[]{LinkOption.NOFOLLOW_LINKS});
                break;
            } catch (UnsupportedOperationException e) {
                // Ignore
            }
        }
        if (a == null) {
            throw new IllegalStateException();
        }
        Map<Attribute, Object> map = new HashMap<Attribute, Object>();
        map.put(Attribute.Size, a.get("size"));
        if (a.containsKey("uid")) {
            map.put(Attribute.Uid, a.get("uid"));
        }
        if (a.containsKey("owner")) {
            map.put(Attribute.Owner, ((UserPrincipal) a.get("owner")).getName());
        } else {
            map.put(Attribute.Owner, userName);
        }
        if (a.containsKey("gid")) {
            map.put(Attribute.Gid, a.get("gid"));
        }
        if (a.containsKey("group")) {
            map.put(Attribute.Group, ((GroupPrincipal) a.get("group")).getName());
        } else {
            map.put(Attribute.Group, userName);
        }
        if (a.containsKey("nlink")) {
            map.put(Attribute.NLink, a.get("nlink"));
        }
        map.put(Attribute.IsDirectory, a.get("isDirectory"));
        map.put(Attribute.IsRegularFile, a.get("isRegularFile"));
        map.put(Attribute.IsSymbolicLink, a.get("isSymbolicLink"));
        map.put(Attribute.CreationTime, ((FileTime) a.get("creationTime")).toMillis());
        map.put(Attribute.LastModifiedTime, ((FileTime) a.get("lastModifiedTime")).toMillis());
        map.put(Attribute.LastAccessTime, ((FileTime) a.get("lastAccessTime")).toMillis());
        if (a.containsKey("permissions")) {
            map.put(Attribute.Permissions, fromPerms((Set<PosixFilePermission>) a.get("permissions")));
        } else {
            EnumSet<Permission> p = EnumSet.noneOf(Permission.class);
            if (isReadable()) {
                p.add(Permission.UserRead);
                p.add(Permission.GroupRead);
                p.add(Permission.OthersRead);
            }
            if (isWritable()) {
                p.add(Permission.UserWrite);
                p.add(Permission.GroupWrite);
                p.add(Permission.OthersWrite);
            }
            if (isExecutable()) {
                p.add(Permission.UserExecute);
                p.add(Permission.GroupExecute);
                p.add(Permission.OthersExecute);
            }
            map.put(Attribute.Permissions, p);
        }
        return map;
    }

    public void setAttributes(Map<Attribute, Object> attributes) throws IOException {
        Set<Attribute> unsupported = new HashSet<Attribute>();
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
                case Gid:              name = "unix:gid"; break;
                case Owner:            name = "posix:owner"; value = toUser((String) value); break;
                case Group:            name = "posix:group"; value = toGroup((String) value); break;
                case Permissions:      name = "posix:permissions"; value = toPerms((EnumSet<Permission>) value); break;
                case CreationTime:     name = "basic:creationTime"; value = FileTime.fromMillis((Long) value); break;
                case LastModifiedTime: name = "basic:lastModifiedTime"; value = FileTime.fromMillis((Long) value); break;
                case LastAccessTime:   name = "basic:lastAccessTime"; value = FileTime.fromMillis((Long) value); break;
            }
            if (name != null && value != null) {
                try {
                    Files.setAttribute(file.toPath(), name, value, LinkOption.NOFOLLOW_LINKS);
                } catch (UnsupportedOperationException e) {
                    unsupported.add(attribute);
                }
            }
        }
        handleUnsupportedAttributes(unsupported);
    }

    public String readSymbolicLink() throws IOException {
        Path path = file.toPath();
        Path link = Files.readSymbolicLink(path);
        return link.toString();
    }

    public void createSymbolicLink(SshFile destination) throws IOException {
        Path link = file.toPath();
        Path target = Paths.get(destination.getAbsolutePath());
        Files.createSymbolicLink(target, link);
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

    @Override
    public OutputStream createOutputStream(long offset) throws IOException {
        Path path = file.toPath();
        final SeekableByteChannel sbc = Files.newByteChannel(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
        if (offset > 0) {
            sbc.position(offset);
        }
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] { (byte) b }, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (b == null) {
                    throw new NullPointerException();
                } else if ((off < 0) || (off > b.length) || (len < 0) ||
                        ((off + len) > b.length) || ((off + len) < 0)) {
                    throw new IndexOutOfBoundsException();
                } else if (len == 0) {
                    return;
                }
                sbc.write(ByteBuffer.wrap(b, off, len));
            }

            @Override
            public void close() throws IOException {
                sbc.close();
            }
        };
    }

}
