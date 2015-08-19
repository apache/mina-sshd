/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.subsystem.sftp;

import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.buffer.Buffer;

import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_ACCESS_ALLOWED_ACE_TYPE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_ACCESS_DENIED_ACE_TYPE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_ADD_FILE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_ADD_SUBDIRECTORY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_APPEND_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_DELETE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_DELETE_CHILD;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_DIRECTORY_INHERIT_ACE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_EXECUTE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_FILE_INHERIT_ACE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_INHERIT_ONLY_ACE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_LIST_DIRECTORY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_NO_PROPAGATE_INHERIT_ACE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_ACL;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_ATTRIBUTES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_READ_NAMED_ATTRS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_SYNCHRONIZE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_SYSTEM_ALARM_ACE_TYPE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_SYSTEM_AUDIT_ACE_TYPE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_ACL;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_ATTRIBUTES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_DATA;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_NAMED_ATTRS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.ACE4_WRITE_OWNER;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V3;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V4;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SFTP_V6;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ACL;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_ALLOCATION_SIZE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_BITS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_CREATETIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_CTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_EXTENDED;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_LINK_COUNT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_MIME_TYPE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_SIZE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_SUBSECOND_TIMES;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_TEXT_HINT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_UIDGID;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_ATTR_UNTRANSLATED_NAME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_REGULAR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_SYMLINK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_DIR_NOT_EMPTY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_EOF;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_FAILURE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_FILE_ALREADY_EXISTS;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_INVALID_FILENAME;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_INVALID_HANDLE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_INVALID_PARAMETER;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_LOCK_CONFLICT;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_NOT_A_DIRECTORY;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_NO_SUCH_FILE;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_OP_UNSUPPORTED;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.SSH_FX_PERMISSION_DENIED;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFDIR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFLNK;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IFREG;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IRGRP;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IROTH;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IRUSR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IWGRP;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IWOTH;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IWUSR;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IXGRP;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IXOTH;
import static org.apache.sshd.common.subsystem.sftp.SftpConstants.S_IXUSR;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SftpHelper {

    private SftpHelper() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static void writeAttrs(int version, Buffer buffer, Map<String, ?> attributes) throws IOException {
        if (version == SFTP_V3) {
            writeAttrsV3(buffer, attributes);
        } else if (version >= SFTP_V4) {
            writeAttrsV4(buffer, attributes);
        } else {
            throw new IllegalStateException("Unsupported SFTP version: " + version);
        }
    }

    public static void writeAttrsV3(Buffer buffer, Map<String, ?> attributes) throws IOException {
        boolean isReg = getBool((Boolean) attributes.get("isRegularFile"));
        boolean isDir = getBool((Boolean) attributes.get("isDirectory"));
        boolean isLnk = getBool((Boolean) attributes.get("isSymbolicLink"));
        @SuppressWarnings("unchecked")
        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) attributes.get("permissions");
        Number size = (Number) attributes.get("size");
        FileTime lastModifiedTime = (FileTime) attributes.get("lastModifiedTime");
        FileTime lastAccessTime = (FileTime) attributes.get("lastAccessTime");

        int flags =
                ((isReg || isLnk) && (size != null) ? SSH_FILEXFER_ATTR_SIZE : 0)
                        | (attributes.containsKey("uid") && attributes.containsKey("gid") ? SSH_FILEXFER_ATTR_UIDGID : 0)
                        | ((perms != null) ? SSH_FILEXFER_ATTR_PERMISSIONS : 0)
                        | (((lastModifiedTime != null) && (lastAccessTime != null)) ? SSH_FILEXFER_ATTR_ACMODTIME : 0);
        buffer.putInt(flags);
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong(size.longValue());
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            buffer.putInt(((Number) attributes.get("uid")).intValue());
            buffer.putInt(((Number) attributes.get("gid")).intValue());
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
        }
        if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            buffer.putInt(lastAccessTime.to(TimeUnit.SECONDS));
            buffer.putInt(lastModifiedTime.to(TimeUnit.SECONDS));
        }
    }

    public static void writeAttrsV4(Buffer buffer, Map<String, ?> attributes) throws IOException {
        boolean isReg = getBool((Boolean) attributes.get("isRegularFile"));
        boolean isDir = getBool((Boolean) attributes.get("isDirectory"));
        boolean isLnk = getBool((Boolean) attributes.get("isSymbolicLink"));
        @SuppressWarnings("unchecked")
        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) attributes.get("permissions");
        Number size = (Number) attributes.get("size");
        FileTime lastModifiedTime = (FileTime) attributes.get("lastModifiedTime");
        FileTime lastAccessTime = (FileTime) attributes.get("lastAccessTime");

        FileTime creationTime = (FileTime) attributes.get("creationTime");
        int flags = (((isReg || isLnk) && (size != null)) ? SSH_FILEXFER_ATTR_SIZE : 0)
                | ((attributes.containsKey("owner") && attributes.containsKey("group")) ? SSH_FILEXFER_ATTR_OWNERGROUP : 0)
                | ((perms != null) ? SSH_FILEXFER_ATTR_PERMISSIONS : 0)
                | ((lastModifiedTime != null) ? SSH_FILEXFER_ATTR_MODIFYTIME : 0)
                | ((creationTime != null) ? SSH_FILEXFER_ATTR_CREATETIME : 0)
                | ((lastAccessTime != null) ? SSH_FILEXFER_ATTR_ACCESSTIME : 0);
        buffer.putInt(flags);
        buffer.putByte((byte) (isReg ? SSH_FILEXFER_TYPE_REGULAR
                : isDir ? SSH_FILEXFER_TYPE_DIRECTORY
                : isLnk ? SSH_FILEXFER_TYPE_SYMLINK
                : SSH_FILEXFER_TYPE_UNKNOWN));
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong(size.longValue());
        }
        if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            buffer.putString(Objects.toString(attributes.get("owner"), null));
            buffer.putString(Objects.toString(attributes.get("group"), null));
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
        }

        if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
            putFileTime(buffer, flags, lastAccessTime);
        }

        if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
            putFileTime(buffer, flags, lastAccessTime);
        }
        if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
            putFileTime(buffer, flags, lastModifiedTime);
        }
        // TODO: acls
        // TODO: bits
        // TODO: extended
    }

    public static void putFileTime(Buffer buffer, int flags, FileTime time) {
        buffer.putLong(time.to(TimeUnit.SECONDS));
        if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            long nanos = time.to(TimeUnit.NANOSECONDS);
            nanos = nanos % TimeUnit.SECONDS.toNanos(1);
            buffer.putInt((int) nanos);
        }
    }

    protected static boolean getBool(Boolean bool) {
        return bool != null && bool;
    }

    public static int attributesToPermissions(boolean isReg, boolean isDir, boolean isLnk, Collection<PosixFilePermission> perms) {
        int pf = 0;
        if (perms != null) {
            for (PosixFilePermission p : perms) {
                switch (p) {
                    case OWNER_READ:
                        pf |= S_IRUSR;
                        break;
                    case OWNER_WRITE:
                        pf |= S_IWUSR;
                        break;
                    case OWNER_EXECUTE:
                        pf |= S_IXUSR;
                        break;
                    case GROUP_READ:
                        pf |= S_IRGRP;
                        break;
                    case GROUP_WRITE:
                        pf |= S_IWGRP;
                        break;
                    case GROUP_EXECUTE:
                        pf |= S_IXGRP;
                        break;
                    case OTHERS_READ:
                        pf |= S_IROTH;
                        break;
                    case OTHERS_WRITE:
                        pf |= S_IWOTH;
                        break;
                    case OTHERS_EXECUTE:
                        pf |= S_IXOTH;
                        break;
                    default: // ignored
                }
            }
        }
        pf |= isReg ? S_IFREG : 0;
        pf |= isDir ? S_IFDIR : 0;
        pf |= isLnk ? S_IFLNK : 0;
        return pf;
    }

    public static Set<PosixFilePermission> permissionsToAttributes(int perms) {
        Set<PosixFilePermission> p = new HashSet<>();
        if ((perms & S_IRUSR) != 0) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }
        return p;
    }

    public static int resolveSubstatus(Exception e) {
        if ((e instanceof NoSuchFileException) || (e instanceof FileNotFoundException)) {
            return SSH_FX_NO_SUCH_FILE;
        } else if (e instanceof InvalidHandleException) {
            return SSH_FX_INVALID_HANDLE;
        } else if (e instanceof FileAlreadyExistsException) {
            return SSH_FX_FILE_ALREADY_EXISTS;
        } else if (e instanceof DirectoryNotEmptyException) {
            return SSH_FX_DIR_NOT_EMPTY;
        } else if (e instanceof NotDirectoryException) {
            return SSH_FX_NOT_A_DIRECTORY;
        } else if (e instanceof AccessDeniedException) {
            return SSH_FX_PERMISSION_DENIED;
        } else if (e instanceof EOFException) {
            return SSH_FX_EOF;
        } else if (e instanceof OverlappingFileLockException) {
            return SSH_FX_LOCK_CONFLICT;
        } else if (e instanceof UnsupportedOperationException) {
            return SSH_FX_OP_UNSUPPORTED;
        } else if (e instanceof InvalidPathException) {
            return SSH_FX_INVALID_FILENAME;
        } else if (e instanceof IllegalArgumentException) {
            return SSH_FX_INVALID_PARAMETER;
        } else {
            return SSH_FX_FAILURE;
        }
    }

    public static AclEntry buildAclEntry(int aclType, int aclFlag, int aclMask, final String aclWho) {
        AclEntryType type;
        switch (aclType) {
            case ACE4_ACCESS_ALLOWED_ACE_TYPE:
                type = AclEntryType.ALLOW;
                break;
            case ACE4_ACCESS_DENIED_ACE_TYPE:
                type = AclEntryType.DENY;
                break;
            case ACE4_SYSTEM_AUDIT_ACE_TYPE:
                type = AclEntryType.AUDIT;
                break;
            case ACE4_SYSTEM_ALARM_ACE_TYPE:
                type = AclEntryType.AUDIT;
                break;
            default:
                throw new IllegalStateException("Unknown acl type: " + aclType);
        }
        Set<AclEntryFlag> flags = new HashSet<>();
        if ((aclFlag & ACE4_FILE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.FILE_INHERIT);
        }
        if ((aclFlag & ACE4_DIRECTORY_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.DIRECTORY_INHERIT);
        }
        if ((aclFlag & ACE4_NO_PROPAGATE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.NO_PROPAGATE_INHERIT);
        }
        if ((aclFlag & ACE4_INHERIT_ONLY_ACE) != 0) {
            flags.add(AclEntryFlag.INHERIT_ONLY);
        }
        Set<AclEntryPermission> mask = new HashSet<>();
        if ((aclMask & ACE4_READ_DATA) != 0) {
            mask.add(AclEntryPermission.READ_DATA);
        }
        if ((aclMask & ACE4_LIST_DIRECTORY) != 0) {
            mask.add(AclEntryPermission.LIST_DIRECTORY);
        }
        if ((aclMask & ACE4_WRITE_DATA) != 0) {
            mask.add(AclEntryPermission.WRITE_DATA);
        }
        if ((aclMask & ACE4_ADD_FILE) != 0) {
            mask.add(AclEntryPermission.ADD_FILE);
        }
        if ((aclMask & ACE4_APPEND_DATA) != 0) {
            mask.add(AclEntryPermission.APPEND_DATA);
        }
        if ((aclMask & ACE4_ADD_SUBDIRECTORY) != 0) {
            mask.add(AclEntryPermission.ADD_SUBDIRECTORY);
        }
        if ((aclMask & ACE4_READ_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.READ_NAMED_ATTRS);
        }
        if ((aclMask & ACE4_WRITE_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.WRITE_NAMED_ATTRS);
        }
        if ((aclMask & ACE4_EXECUTE) != 0) {
            mask.add(AclEntryPermission.EXECUTE);
        }
        if ((aclMask & ACE4_DELETE_CHILD) != 0) {
            mask.add(AclEntryPermission.DELETE_CHILD);
        }
        if ((aclMask & ACE4_READ_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.READ_ATTRIBUTES);
        }
        if ((aclMask & ACE4_WRITE_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.WRITE_ATTRIBUTES);
        }
        if ((aclMask & ACE4_DELETE) != 0) {
            mask.add(AclEntryPermission.DELETE);
        }
        if ((aclMask & ACE4_READ_ACL) != 0) {
            mask.add(AclEntryPermission.READ_ACL);
        }
        if ((aclMask & ACE4_WRITE_ACL) != 0) {
            mask.add(AclEntryPermission.WRITE_ACL);
        }
        if ((aclMask & ACE4_WRITE_OWNER) != 0) {
            mask.add(AclEntryPermission.WRITE_OWNER);
        }
        if ((aclMask & ACE4_SYNCHRONIZE) != 0) {
            mask.add(AclEntryPermission.SYNCHRONIZE);
        }
        UserPrincipal who = new DefaultGroupPrincipal(aclWho);
        return AclEntry.newBuilder()
                .setType(type)
                .setFlags(flags)
                .setPermissions(mask)
                .setPrincipal(who)
                .build();
    }

    protected static Map<String, Object> readAttrs(int version, Buffer buffer) throws IOException {
        Map<String, Object> attrs = new HashMap<>();
        int flags = buffer.getInt();
        if (version >= SFTP_V4) {
            int type = buffer.getUByte();
            switch (type) {
                case SSH_FILEXFER_TYPE_REGULAR:
                    attrs.put("isRegular", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_DIRECTORY:
                    attrs.put("isDirectory", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_SYMLINK:
                    attrs.put("isSymbolicLink", Boolean.TRUE);
                    break;
                case SSH_FILEXFER_TYPE_UNKNOWN:
                    attrs.put("isOther", Boolean.TRUE);
                    break;
                default:    // ignored
            }
        }
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            attrs.put("size", buffer.getLong());
        }
        if ((flags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0) {
            attrs.put("allocationSize", buffer.getLong());
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            attrs.put("uid", buffer.getInt());
            attrs.put("gid", buffer.getInt());
        }
        if ((flags & SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            attrs.put("owner", new DefaultGroupPrincipal(buffer.getString()));
            attrs.put("group", new DefaultGroupPrincipal(buffer.getString()));
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            attrs.put("permissions", permissionsToAttributes(buffer.getInt()));
        }
        if (version == SFTP_V3) {
            if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, flags));
                attrs.put("lastModifiedTime", readTime(buffer, flags));
            }
        } else if (version >= SFTP_V4) {
            if ((flags & SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                attrs.put("creationTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                attrs.put("lastModifiedTime", readTime(buffer, flags));
            }
            if ((flags & SSH_FILEXFER_ATTR_CTIME) != 0) {
                attrs.put("ctime", readTime(buffer, flags));
            }
        }
        if ((flags & SSH_FILEXFER_ATTR_ACL) != 0) {
            int count = buffer.getInt();
            List<AclEntry> acls = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                int aclType = buffer.getInt();
                int aclFlag = buffer.getInt();
                int aclMask = buffer.getInt();
                String aclWho = buffer.getString();
                acls.add(buildAclEntry(aclType, aclFlag, aclMask, aclWho));
            }
            attrs.put("acl", acls);
        }
        if ((flags & SSH_FILEXFER_ATTR_BITS) != 0) {
            int bits = buffer.getInt();
            int valid = 0xffffffff;
            if (version >= SFTP_V6) {
                valid = buffer.getInt();
            }
            // TODO: handle attrib bits
        }
        if ((flags & SSH_FILEXFER_ATTR_TEXT_HINT) != 0) {
            boolean text = buffer.getBoolean();
            // TODO: handle text
        }
        if ((flags & SSH_FILEXFER_ATTR_MIME_TYPE) != 0) {
            String mimeType = buffer.getString();
            // TODO: handle mime-type
        }
        if ((flags & SSH_FILEXFER_ATTR_LINK_COUNT) != 0) {
            int nlink = buffer.getInt();
            // TODO: handle link-count
        }
        if ((flags & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) != 0) {
            String untranslated = buffer.getString();
            // TODO: handle untranslated-name
        }
        if ((flags & SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            int count = buffer.getInt();
            Map<String, String> extended = new HashMap<>();
            for (int i = 0; i < count; i++) {
                String key = buffer.getString();
                String val = buffer.getString();
                extended.put(key, val);
            }
            attrs.put("extended", extended);
        }

        return attrs;
    }

    private static FileTime readTime(Buffer buffer, int flags) {
        long secs = buffer.getLong();
        long millis = secs * 1000;
        if ((flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
            millis += buffer.getInt() / 1000000L;
        }
        return FileTime.from(millis, TimeUnit.MILLISECONDS);
    }
}
