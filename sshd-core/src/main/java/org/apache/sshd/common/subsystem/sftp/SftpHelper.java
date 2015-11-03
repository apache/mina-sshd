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
package org.apache.sshd.common.subsystem.sftp;

import java.io.EOFException;
import java.io.FileNotFoundException;
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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.subsystem.sftp.DefaultGroupPrincipal;
import org.apache.sshd.server.subsystem.sftp.InvalidHandleException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SftpHelper {

    private SftpHelper() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * Writes a file / folder's attributes to a buffer
     *
     * @param buffer The target {@link Buffer}
     * @param version The output encoding version
     * @param attributes The {@link Map} of attributes
     * @see #writeAttrsV3(Buffer, int, Map)
     * @see #writeAttrsV4(Buffer, int, Map)
     */
    public static void writeAttrs(Buffer buffer, int version, Map<String, ?> attributes) {
        if (version == SftpConstants.SFTP_V3) {
            writeAttrsV3(buffer, version, attributes);
        } else if (version >= SftpConstants.SFTP_V4) {
            writeAttrsV4(buffer, version, attributes);
        } else {
            throw new IllegalStateException("Unsupported SFTP version: " + version);
        }
    }

    /**
     * Writes the retrieved file / directory attributes in V3 format
     *
     * @param buffer The target {@link Buffer}
     * @param version The actual version - must be {@link SftpConstants#SFTP_V3}
     * @param attributes The {@link Map} of attributes
     */
    public static void writeAttrsV3(Buffer buffer, int version, Map<String, ?> attributes) {
        ValidateUtils.checkTrue(version == SftpConstants.SFTP_V3, "Illegal version: %d", version);

        boolean isReg = getBool((Boolean) attributes.get("isRegularFile"));
        boolean isDir = getBool((Boolean) attributes.get("isDirectory"));
        boolean isLnk = getBool((Boolean) attributes.get("isSymbolicLink"));
        @SuppressWarnings("unchecked")
        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) attributes.get("permissions");
        Number size = (Number) attributes.get("size");
        FileTime lastModifiedTime = (FileTime) attributes.get("lastModifiedTime");
        FileTime lastAccessTime = (FileTime) attributes.get("lastAccessTime");
        int flags = ((isReg || isLnk) && (size != null) ? SftpConstants.SSH_FILEXFER_ATTR_SIZE : 0)
                  | (attributes.containsKey("uid") && attributes.containsKey("gid") ? SftpConstants.SSH_FILEXFER_ATTR_UIDGID : 0)
                  | ((perms != null) ? SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS : 0)
                  | (((lastModifiedTime != null) && (lastAccessTime != null)) ? SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME : 0);
        buffer.putInt(flags);
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong(size.longValue());
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0) {
            buffer.putInt(((Number) attributes.get("uid")).intValue());
            buffer.putInt(((Number) attributes.get("gid")).intValue());
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            writeTime(buffer, version, flags, lastAccessTime);
            writeTime(buffer, version, flags, lastModifiedTime);
        }
    }

    /**
     * Writes the retrieved file / directory attributes in V4+ format
     *
     * @param buffer The target {@link Buffer}
     * @param version The actual version - must be at least {@link SftpConstants#SFTP_V4}
     * @param attributes The {@link Map} of attributes
     */
    public static void writeAttrsV4(Buffer buffer, int version, Map<String, ?> attributes) {
        ValidateUtils.checkTrue(version >= SftpConstants.SFTP_V4, "Illegal version: %d", version);

        boolean isReg = getBool((Boolean) attributes.get("isRegularFile"));
        boolean isDir = getBool((Boolean) attributes.get("isDirectory"));
        boolean isLnk = getBool((Boolean) attributes.get("isSymbolicLink"));
        @SuppressWarnings("unchecked")
        Collection<PosixFilePermission> perms = (Collection<PosixFilePermission>) attributes.get("permissions");
        Number size = (Number) attributes.get("size");
        FileTime lastModifiedTime = (FileTime) attributes.get("lastModifiedTime");
        FileTime lastAccessTime = (FileTime) attributes.get("lastAccessTime");
        FileTime creationTime = (FileTime) attributes.get("creationTime");
        @SuppressWarnings("unchecked")
        Collection<AclEntry> acl = (Collection<AclEntry>) attributes.get("acl");
        int flags = (((isReg || isLnk) && (size != null)) ? SftpConstants.SSH_FILEXFER_ATTR_SIZE : 0)
                  | ((attributes.containsKey("owner") && attributes.containsKey("group")) ? SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP : 0)
                  | ((perms != null) ? SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS : 0)
                  | ((lastModifiedTime != null) ? SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME : 0)
                  | ((creationTime != null) ? SftpConstants.SSH_FILEXFER_ATTR_CREATETIME : 0)
                  | ((lastAccessTime != null) ? SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME : 0)
                  | ((acl != null) ? SftpConstants.SSH_FILEXFER_ATTR_ACL : 0);
        buffer.putInt(flags);
        buffer.putByte((byte) (isReg ? SftpConstants.SSH_FILEXFER_TYPE_REGULAR
                : isDir ? SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY
                : isLnk ? SftpConstants.SSH_FILEXFER_TYPE_SYMLINK
                : SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN));
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
            buffer.putLong(size.longValue());
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
            buffer.putString(Objects.toString(attributes.get("owner"), SftpUniversalOwnerAndGroup.Owner.getName()));
            buffer.putString(Objects.toString(attributes.get("group"), SftpUniversalOwnerAndGroup.Group.getName()));
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            buffer.putInt(attributesToPermissions(isReg, isDir, isLnk, perms));
        }

        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
            writeTime(buffer, version, flags, lastAccessTime);
        }

        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
            writeTime(buffer, version, flags, lastAccessTime);
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
            writeTime(buffer, version, flags, lastModifiedTime);
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACL) != 0) {
            writeACLs(buffer, version, acl);
        }
        // TODO: ctime
        // TODO: bits
        // TODO: extensions
    }

    /**
     * @param bool The {@link Boolean} value
     * @return {@code true} it the argument is non-{@code null} and
     * its {@link Boolean#booleanValue()} is {@code true}
     */
    public static boolean getBool(Boolean bool) {
        return bool != null && bool;
    }

    /**
     * Converts a file / folder's attributes into a mask
     *
     * @param isReg {@code true} if this is a normal file
     * @param isDir {@code true} if this is a directory
     * @param isLnk {@code true} if this is a symbolic link
     * @param perms The file / folder's access {@link PosixFilePermission}s
     * @return A mask encoding the file / folder's attributes
     */
    public static int attributesToPermissions(boolean isReg, boolean isDir, boolean isLnk, Collection<PosixFilePermission> perms) {
        int pf = 0;
        if (perms != null) {
            for (PosixFilePermission p : perms) {
                switch (p) {
                    case OWNER_READ:
                        pf |= SftpConstants.S_IRUSR;
                        break;
                    case OWNER_WRITE:
                        pf |= SftpConstants.S_IWUSR;
                        break;
                    case OWNER_EXECUTE:
                        pf |= SftpConstants.S_IXUSR;
                        break;
                    case GROUP_READ:
                        pf |= SftpConstants.S_IRGRP;
                        break;
                    case GROUP_WRITE:
                        pf |= SftpConstants.S_IWGRP;
                        break;
                    case GROUP_EXECUTE:
                        pf |= SftpConstants.S_IXGRP;
                        break;
                    case OTHERS_READ:
                        pf |= SftpConstants.S_IROTH;
                        break;
                    case OTHERS_WRITE:
                        pf |= SftpConstants.S_IWOTH;
                        break;
                    case OTHERS_EXECUTE:
                        pf |= SftpConstants.S_IXOTH;
                        break;
                    default: // ignored
                }
            }
        }
        pf |= isReg ? SftpConstants.S_IFREG : 0;
        pf |= isDir ? SftpConstants.S_IFDIR : 0;
        pf |= isLnk ? SftpConstants.S_IFLNK : 0;
        return pf;
    }

    /**
     * Converts a POSIX permissions mask to a file type value
     *
     * @param perms The POSIX permissions mask
     * @return The file type - see {@code SSH_FILEXFER_TYPE_xxx} values
     */
    public static int permissionsToFileType(int perms) {
        if ((SftpConstants.S_IFLNK & perms) == SftpConstants.S_IFLNK) {
            return SftpConstants.SSH_FILEXFER_TYPE_SYMLINK;
        } else if ((SftpConstants.S_IFREG & perms) == SftpConstants.S_IFREG) {
            return SftpConstants.SSH_FILEXFER_TYPE_REGULAR;
        } else if ((SftpConstants.S_IFDIR & perms) == SftpConstants.S_IFDIR) {
            return SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY;
        } else if ((SftpConstants.S_IFSOCK & perms) == SftpConstants.S_IFSOCK) {
            return SftpConstants.SSH_FILEXFER_TYPE_SOCKET;
        } else if ((SftpConstants.S_IFBLK & perms) == SftpConstants.S_IFBLK) {
            return SftpConstants.SSH_FILEXFER_TYPE_BLOCK_DEVICE;
        } else if ((SftpConstants.S_IFCHR & perms) == SftpConstants.S_IFCHR) {
            return SftpConstants.SSH_FILEXFER_TYPE_CHAR_DEVICE;
        } else if ((SftpConstants.S_IFIFO & perms) == SftpConstants.S_IFIFO) {
            return SftpConstants.SSH_FILEXFER_TYPE_FIFO;
        } else {
            return SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN;
        }
    }

    /**
     * Converts a file type into a POSIX permission mask value

     * @param type File type - see {@code SSH_FILEXFER_TYPE_xxx} values
     * @return The matching POSIX permission mask value
     */
    public static int fileTypeToPermission(int type) {
        switch (type) {
            case SftpConstants.SSH_FILEXFER_TYPE_REGULAR:
                return SftpConstants.S_IFREG;
            case SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY:
                return SftpConstants.S_IFDIR;
            case SftpConstants.SSH_FILEXFER_TYPE_SYMLINK:
                return SftpConstants.S_IFLNK;
            case SftpConstants.SSH_FILEXFER_TYPE_SOCKET:
                return SftpConstants.S_IFSOCK;
            case SftpConstants.SSH_FILEXFER_TYPE_BLOCK_DEVICE:
                return SftpConstants.S_IFBLK;
            case SftpConstants.SSH_FILEXFER_TYPE_CHAR_DEVICE:
                return SftpConstants.S_IFCHR;
            case SftpConstants.SSH_FILEXFER_TYPE_FIFO:
                return SftpConstants.S_IFIFO;
            default:
                return 0;
        }
    }

    /**
     * Translates a mask of permissions into its enumeration values equivalents
     *
     * @param perms The permissions mask
     * @return A {@link Set} of the equivalent {@link PosixFilePermission}s
     */
    public static Set<PosixFilePermission> permissionsToAttributes(int perms) {
        Set<PosixFilePermission> p = EnumSet.noneOf(PosixFilePermission.class);
        if ((perms & SftpConstants.S_IRUSR) != 0) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & SftpConstants.S_IWUSR) != 0) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & SftpConstants.S_IXUSR) != 0) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & SftpConstants.S_IRGRP) != 0) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & SftpConstants.S_IWGRP) != 0) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & SftpConstants.S_IXGRP) != 0) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & SftpConstants.S_IROTH) != 0) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & SftpConstants.S_IWOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & SftpConstants.S_IXOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }
        return p;
    }

    /**
     * Returns the most adequate sub-status for the provided exception
     *
     * @param t The thrown {@link Throwable}
     * @return The matching sub-status
     */
    public static int resolveSubstatus(Throwable t) {
        if ((t instanceof NoSuchFileException) || (t instanceof FileNotFoundException)) {
            return SftpConstants.SSH_FX_NO_SUCH_FILE;
        } else if (t instanceof InvalidHandleException) {
            return SftpConstants.SSH_FX_INVALID_HANDLE;
        } else if (t instanceof FileAlreadyExistsException) {
            return SftpConstants.SSH_FX_FILE_ALREADY_EXISTS;
        } else if (t instanceof DirectoryNotEmptyException) {
            return SftpConstants.SSH_FX_DIR_NOT_EMPTY;
        } else if (t instanceof NotDirectoryException) {
            return SftpConstants.SSH_FX_NOT_A_DIRECTORY;
        } else if (t instanceof AccessDeniedException) {
            return SftpConstants.SSH_FX_PERMISSION_DENIED;
        } else if (t instanceof EOFException) {
            return SftpConstants.SSH_FX_EOF;
        } else if (t instanceof OverlappingFileLockException) {
            return SftpConstants.SSH_FX_LOCK_CONFLICT;
        } else if (t instanceof UnsupportedOperationException) {
            return SftpConstants.SSH_FX_OP_UNSUPPORTED;
        } else if (t instanceof InvalidPathException) {
            return SftpConstants.SSH_FX_INVALID_FILENAME;
        } else if (t instanceof IllegalArgumentException) {
            return SftpConstants.SSH_FX_INVALID_PARAMETER;
        } else if (t instanceof UnsupportedOperationException) {
            return SftpConstants.SSH_FX_OP_UNSUPPORTED;
        } else {
            return SftpConstants.SSH_FX_FAILURE;
        }
    }

    public static Map<String, Object> readAttrs(Buffer buffer, int version) {
        Map<String, Object> attrs = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        int flags = buffer.getInt();
        if (version >= SftpConstants.SFTP_V4) {
            int type = buffer.getUByte();
            switch (type) {
                case SftpConstants.SSH_FILEXFER_TYPE_REGULAR:
                    attrs.put("isRegular", Boolean.TRUE);
                    break;
                case SftpConstants.SSH_FILEXFER_TYPE_DIRECTORY:
                    attrs.put("isDirectory", Boolean.TRUE);
                    break;
                case SftpConstants.SSH_FILEXFER_TYPE_SYMLINK:
                    attrs.put("isSymbolicLink", Boolean.TRUE);
                    break;
                case SftpConstants.SSH_FILEXFER_TYPE_UNKNOWN:
                    attrs.put("isOther", Boolean.TRUE);
                    break;
                default:    // ignored
            }
        }
        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SIZE) != 0) {
            attrs.put("size", buffer.getLong());
        }

        if (version == SftpConstants.SFTP_V3) {
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_UIDGID) != 0) {
                attrs.put("uid", buffer.getInt());
                attrs.put("gid", buffer.getInt());
            }
        } else {
            if ((version >= SftpConstants.SFTP_V6) && ((flags & SftpConstants.SSH_FILEXFER_ATTR_ALLOCATION_SIZE) != 0)) {
                @SuppressWarnings("unused")
                long allocSize = buffer.getLong();    // TODO handle allocation size
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP) != 0) {
                attrs.put("owner", new DefaultGroupPrincipal(buffer.getString()));
                attrs.put("group", new DefaultGroupPrincipal(buffer.getString()));
            }
        }

        if ((flags & SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            attrs.put("permissions", permissionsToAttributes(buffer.getInt()));
        }

        if (version == SftpConstants.SFTP_V3) {
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, version, flags));
                attrs.put("lastModifiedTime", readTime(buffer, version, flags));
            }
        } else if (version >= SftpConstants.SFTP_V4) {
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME) != 0) {
                attrs.put("lastAccessTime", readTime(buffer, version, flags));
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_CREATETIME) != 0) {
                attrs.put("creationTime", readTime(buffer, version, flags));
            }
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME) != 0) {
                attrs.put("lastModifiedTime", readTime(buffer, version, flags));
            }
            if ((version >= SftpConstants.SFTP_V6) && (flags & SftpConstants.SSH_FILEXFER_ATTR_CTIME) != 0) {
                attrs.put("ctime", readTime(buffer, version, flags));
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_ACL) != 0) {
                attrs.put("acl", readACLs(buffer, version));
            }

            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_BITS) != 0) {
                @SuppressWarnings("unused")
                int bits = buffer.getInt();
                @SuppressWarnings("unused")
                int valid = 0xffffffff;
                if (version >= SftpConstants.SFTP_V6) {
                    valid = buffer.getInt();
                }
                // TODO: handle attrib bits
            }

            if (version >= SftpConstants.SFTP_V6) {
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_TEXT_HINT) != 0) {
                    @SuppressWarnings("unused")
                    boolean text = buffer.getBoolean(); // TODO: handle text
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_MIME_TYPE) != 0) {
                    @SuppressWarnings("unused")
                    String mimeType = buffer.getString(); // TODO: handle mime-type
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_LINK_COUNT) != 0) {
                    @SuppressWarnings("unused")
                    int nlink = buffer.getInt(); // TODO: handle link-count
                }
                if ((flags & SftpConstants.SSH_FILEXFER_ATTR_UNTRANSLATED_NAME) != 0) {
                    @SuppressWarnings("unused")
                    String untranslated = buffer.getString(); // TODO: handle untranslated-name
                }
            }
        }

        return attrs;
    }

    // for v4,5 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-05#page-15
    // for v6 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-21
    public static List<AclEntry> readACLs(Buffer buffer, int version) {
        int aclSize = buffer.getInt();
        int startPos = buffer.rpos();
        Buffer aclBuffer = new ByteArrayBuffer(buffer.array(), startPos, aclSize, true);
        List<AclEntry> acl = decodeACLs(aclBuffer, version);
        buffer.rpos(startPos + aclSize);
        return acl;
    }

    public static List<AclEntry> decodeACLs(Buffer buffer, int version) {
        @SuppressWarnings("unused")
        int aclFlags = 0;   // TODO handle ACL flags
        if (version >= SftpConstants.SFTP_V6) {
            aclFlags = buffer.getInt();
        }

        int count = buffer.getInt();
        // NOTE: although the value is defined as UINT32 we do not expected a count greater than Integer.MAX_VALUE
        ValidateUtils.checkTrue(count >= 0, "Invalid ACL entries count: %d", count);
        if (count == 0) {
            return Collections.emptyList();
        }

        List<AclEntry> acls = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int aclType = buffer.getInt();
            int aclFlag = buffer.getInt();
            int aclMask = buffer.getInt();
            String aclWho = buffer.getString();
            acls.add(buildAclEntry(aclType, aclFlag, aclMask, aclWho));
        }

        return acls;
    }

    public static AclEntry buildAclEntry(int aclType, int aclFlag, int aclMask, String aclWho) {
        UserPrincipal who = new DefaultGroupPrincipal(aclWho);
        return AclEntry.newBuilder()
                .setType(ValidateUtils.checkNotNull(decodeAclEntryType(aclType), "Unknown ACL type: %d", aclType))
                .setFlags(decodeAclFlags(aclFlag))
                .setPermissions(decodeAclMask(aclMask))
                .setPrincipal(who)
                .build();
    }

    /**
     * @param aclType The {@code ACE4_ACCESS_xxx_ACE_TYPE} value
     * @return The matching {@link AclEntryType} or {@code null} if unknown value
     */
    public static AclEntryType decodeAclEntryType(int aclType) {
        switch (aclType) {
            case SftpConstants.ACE4_ACCESS_ALLOWED_ACE_TYPE:
                return AclEntryType.ALLOW;
            case SftpConstants.ACE4_ACCESS_DENIED_ACE_TYPE:
                return AclEntryType.DENY;
            case SftpConstants.ACE4_SYSTEM_AUDIT_ACE_TYPE:
                return AclEntryType.AUDIT;
            case SftpConstants.ACE4_SYSTEM_ALARM_ACE_TYPE:
                return AclEntryType.ALARM;
            default:
                return null;
        }
    }

    public static Set<AclEntryFlag> decodeAclFlags(int aclFlag) {
        Set<AclEntryFlag> flags = EnumSet.noneOf(AclEntryFlag.class);
        if ((aclFlag & SftpConstants.ACE4_FILE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.FILE_INHERIT);
        }
        if ((aclFlag & SftpConstants.ACE4_DIRECTORY_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.DIRECTORY_INHERIT);
        }
        if ((aclFlag & SftpConstants.ACE4_NO_PROPAGATE_INHERIT_ACE) != 0) {
            flags.add(AclEntryFlag.NO_PROPAGATE_INHERIT);
        }
        if ((aclFlag & SftpConstants.ACE4_INHERIT_ONLY_ACE) != 0) {
            flags.add(AclEntryFlag.INHERIT_ONLY);
        }

        return flags;
    }

    public static Set<AclEntryPermission> decodeAclMask(int aclMask) {
        Set<AclEntryPermission> mask = EnumSet.noneOf(AclEntryPermission.class);
        if ((aclMask & SftpConstants.ACE4_READ_DATA) != 0) {
            mask.add(AclEntryPermission.READ_DATA);
        }
        if ((aclMask & SftpConstants.ACE4_LIST_DIRECTORY) != 0) {
            mask.add(AclEntryPermission.LIST_DIRECTORY);
        }
        if ((aclMask & SftpConstants.ACE4_WRITE_DATA) != 0) {
            mask.add(AclEntryPermission.WRITE_DATA);
        }
        if ((aclMask & SftpConstants.ACE4_ADD_FILE) != 0) {
            mask.add(AclEntryPermission.ADD_FILE);
        }
        if ((aclMask & SftpConstants.ACE4_APPEND_DATA) != 0) {
            mask.add(AclEntryPermission.APPEND_DATA);
        }
        if ((aclMask & SftpConstants.ACE4_ADD_SUBDIRECTORY) != 0) {
            mask.add(AclEntryPermission.ADD_SUBDIRECTORY);
        }
        if ((aclMask & SftpConstants.ACE4_READ_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.READ_NAMED_ATTRS);
        }
        if ((aclMask & SftpConstants.ACE4_WRITE_NAMED_ATTRS) != 0) {
            mask.add(AclEntryPermission.WRITE_NAMED_ATTRS);
        }
        if ((aclMask & SftpConstants.ACE4_EXECUTE) != 0) {
            mask.add(AclEntryPermission.EXECUTE);
        }
        if ((aclMask & SftpConstants.ACE4_DELETE_CHILD) != 0) {
            mask.add(AclEntryPermission.DELETE_CHILD);
        }
        if ((aclMask & SftpConstants.ACE4_READ_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.READ_ATTRIBUTES);
        }
        if ((aclMask & SftpConstants.ACE4_WRITE_ATTRIBUTES) != 0) {
            mask.add(AclEntryPermission.WRITE_ATTRIBUTES);
        }
        if ((aclMask & SftpConstants.ACE4_DELETE) != 0) {
            mask.add(AclEntryPermission.DELETE);
        }
        if ((aclMask & SftpConstants.ACE4_READ_ACL) != 0) {
            mask.add(AclEntryPermission.READ_ACL);
        }
        if ((aclMask & SftpConstants.ACE4_WRITE_ACL) != 0) {
            mask.add(AclEntryPermission.WRITE_ACL);
        }
        if ((aclMask & SftpConstants.ACE4_WRITE_OWNER) != 0) {
            mask.add(AclEntryPermission.WRITE_OWNER);
        }
        if ((aclMask & SftpConstants.ACE4_SYNCHRONIZE) != 0) {
            mask.add(AclEntryPermission.SYNCHRONIZE);
        }

        return mask;
    }

    public static void writeACLs(Buffer buffer, int version, Collection<? extends AclEntry> acl) {
        int lenPos = buffer.wpos();
        buffer.putInt(0);   // length placeholder
        encodeACLs(buffer, version, acl);
        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    public static void encodeACLs(Buffer buffer, int version, Collection<? extends AclEntry> acl) {
        ValidateUtils.checkNotNull(acl, "No ACL");
        if (version >= SftpConstants.SFTP_V6) {
            buffer.putInt(0);   // TODO handle ACL flags
        }

        int numEntries = GenericUtils.size(acl);
        buffer.putInt(numEntries);
        if (numEntries > 0) {
            for (AclEntry e : acl) {
                writeAclEntry(buffer, e);
            }
        }
    }

    public static void writeAclEntry(Buffer buffer, AclEntry acl) {
        ValidateUtils.checkNotNull(acl, "No ACL");

        AclEntryType type = acl.type();
        int aclType = encodeAclEntryType(type);
        ValidateUtils.checkTrue(aclType >= 0, "Unknown ACL type: %s", type);
        buffer.putInt(aclType);
        buffer.putInt(encodeAclFlags(acl.flags()));
        buffer.putInt(encodeAclMask(acl.permissions()));

        Principal user = acl.principal();
        buffer.putString(user.getName());
    }

    /**
     * Returns the equivalent SFTP value for the ACL type
     *
     * @param type The {@link AclEntryType}
     * @return The equivalent {@code ACE_SYSTEM_xxx_TYPE} or negative
     * if {@code null} or unknown type
     */
    public static int encodeAclEntryType(AclEntryType type) {
        if (type == null) {
            return Integer.MIN_VALUE;
        }

        switch(type) {
            case ALARM:
                return SftpConstants.ACE4_SYSTEM_ALARM_ACE_TYPE;
            case ALLOW:
                return SftpConstants.ACE4_ACCESS_ALLOWED_ACE_TYPE;
            case AUDIT:
                return SftpConstants.ACE4_SYSTEM_AUDIT_ACE_TYPE;
            case DENY:
                return SftpConstants.ACE4_ACCESS_DENIED_ACE_TYPE;
            default:
                return -1;
        }
    }

    public static long encodeAclFlags(Collection<AclEntryFlag> flags) {
        if (GenericUtils.isEmpty(flags)) {
            return 0L;
        }

        long aclFlag = 0L;
        if (flags.contains(AclEntryFlag.FILE_INHERIT)) {
            aclFlag |= SftpConstants.ACE4_FILE_INHERIT_ACE;
        }
        if (flags.contains(AclEntryFlag.DIRECTORY_INHERIT)) {
            aclFlag |= SftpConstants.ACE4_DIRECTORY_INHERIT_ACE;
        }
        if (flags.contains(AclEntryFlag.NO_PROPAGATE_INHERIT)) {
            aclFlag |= SftpConstants.ACE4_NO_PROPAGATE_INHERIT_ACE;
        }
        if (flags.contains(AclEntryFlag.INHERIT_ONLY)) {
            aclFlag |= SftpConstants.ACE4_INHERIT_ONLY_ACE;
        }

        return aclFlag;
    }

    public static long encodeAclMask(Collection<AclEntryPermission> mask) {
        if (GenericUtils.isEmpty(mask)) {
            return 0L;
        }

        long aclMask = 0L;
        if (mask.contains(AclEntryPermission.READ_DATA)) {
            aclMask |= SftpConstants.ACE4_READ_DATA;
        }
        if (mask.contains(AclEntryPermission.LIST_DIRECTORY)) {
            aclMask |= SftpConstants.ACE4_LIST_DIRECTORY;
        }
        if (mask.contains(AclEntryPermission.WRITE_DATA)) {
            aclMask |= SftpConstants.ACE4_WRITE_DATA;
        }
        if (mask.contains(AclEntryPermission.ADD_FILE)) {
            aclMask |= SftpConstants.ACE4_ADD_FILE;
        }
        if (mask.contains(AclEntryPermission.APPEND_DATA)) {
            aclMask |= SftpConstants.ACE4_APPEND_DATA;
        }
        if (mask.contains(AclEntryPermission.ADD_SUBDIRECTORY)) {
            aclMask |= SftpConstants.ACE4_ADD_SUBDIRECTORY;
        }
        if (mask.contains(AclEntryPermission.READ_NAMED_ATTRS)) {
            aclMask |= SftpConstants.ACE4_READ_NAMED_ATTRS;
        }
        if (mask.contains(AclEntryPermission.WRITE_NAMED_ATTRS)) {
            aclMask |= SftpConstants.ACE4_WRITE_NAMED_ATTRS;
        }
        if (mask.contains(AclEntryPermission.EXECUTE)) {
            aclMask |= SftpConstants.ACE4_EXECUTE;
        }
        if (mask.contains(AclEntryPermission.DELETE_CHILD)) {
            aclMask |= SftpConstants.ACE4_DELETE_CHILD;
        }
        if (mask.contains(AclEntryPermission.READ_ATTRIBUTES)) {
            aclMask |= SftpConstants.ACE4_READ_ATTRIBUTES;
        }
        if (mask.contains(AclEntryPermission.WRITE_ATTRIBUTES)) {
            aclMask |= SftpConstants.ACE4_WRITE_ATTRIBUTES;
        }
        if (mask.contains(AclEntryPermission.DELETE)) {
            aclMask |= SftpConstants.ACE4_DELETE;
        }
        if (mask.contains(AclEntryPermission.READ_ACL)) {
            aclMask |= SftpConstants.ACE4_READ_ACL;
        }
        if (mask.contains(AclEntryPermission.WRITE_ACL)) {
            aclMask |= SftpConstants.ACE4_WRITE_ACL;
        }
        if (mask.contains(AclEntryPermission.WRITE_OWNER)) {
            aclMask |= SftpConstants.ACE4_WRITE_OWNER;
        }
        if (mask.contains(AclEntryPermission.SYNCHRONIZE)) {
            aclMask |= SftpConstants.ACE4_SYNCHRONIZE;
        }

        return aclMask;
    }

    /**
     * Encodes a {@link FileTime} value into a buffer
     *
     * @param buffer The target {@link Buffer}
     * @param version The encoding version
     * @param flags The encoding flags
     * @param time The value to encode
     */
    public static void writeTime(Buffer buffer, int version, int flags, FileTime time) {
        // for v3 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#page-8
        // for v6 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-16
        if (version >= SftpConstants.SFTP_V4) {
            buffer.putLong(time.to(TimeUnit.SECONDS));
            if ((flags & SftpConstants.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0) {
                long nanos = time.to(TimeUnit.NANOSECONDS);
                nanos = nanos % TimeUnit.SECONDS.toNanos(1);
                buffer.putInt((int) nanos);
            }
        } else {
            buffer.putInt(time.to(TimeUnit.SECONDS));
        }
    }

    /**
     * Decodes a {@link FileTime} value from a buffer
     *
     * @param buffer The source {@link Buffer}
     * @param version The encoding version
     * @param flags The encoding flags
     * @return The decoded value
     */
    public static FileTime readTime(Buffer buffer, int version, int flags) {
        // for v3 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#page-8
        // for v6 see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-16
        long secs = (version >= SftpConstants.SFTP_V4) ? buffer.getLong() : buffer.getUInt();
        long millis = TimeUnit.SECONDS.toMillis(secs);
        if ((version >= SftpConstants.SFTP_V4) && ((flags & SftpConstants.SSH_FILEXFER_ATTR_SUBSECOND_TIMES) != 0)) {
            long nanoseconds = buffer.getUInt();
            millis += TimeUnit.NANOSECONDS.toMillis(nanoseconds);
        }
        return FileTime.from(millis, TimeUnit.MILLISECONDS);
    }
}
