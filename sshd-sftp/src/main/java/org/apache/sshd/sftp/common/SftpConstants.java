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
package org.apache.sshd.sftp.common;

import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@SuppressWarnings("PMD.AvoidUsingOctalValues")
public final class SftpConstants {
    public static final String SFTP_SUBSYSTEM_NAME = "sftp";

    public static final int SSH_FXP_INIT = 1;
    public static final int SSH_FXP_VERSION = 2;
    public static final int SSH_FXP_OPEN = 3;
    public static final int SSH_FXP_CLOSE = 4;
    public static final int SSH_FXP_READ = 5;
    public static final int SSH_FXP_WRITE = 6;
    public static final int SSH_FXP_LSTAT = 7;
    public static final int SSH_FXP_FSTAT = 8;
    public static final int SSH_FXP_SETSTAT = 9;
    public static final int SSH_FXP_FSETSTAT = 10;
    public static final int SSH_FXP_OPENDIR = 11;
    public static final int SSH_FXP_READDIR = 12;
    public static final int SSH_FXP_REMOVE = 13;
    public static final int SSH_FXP_MKDIR = 14;
    public static final int SSH_FXP_RMDIR = 15;
    public static final int SSH_FXP_REALPATH = 16;
    public static final int SSH_FXP_STAT = 17;
    public static final int SSH_FXP_RENAME = 18;
    public static final int SSH_FXP_READLINK = 19;
    public static final int SSH_FXP_SYMLINK = 20; // v3 -> v5
    public static final int SSH_FXP_LINK = 21; // v6
    public static final int SSH_FXP_BLOCK = 22; // v6
    public static final int SSH_FXP_UNBLOCK = 23; // v6
    public static final int SSH_FXP_STATUS = 101;
    public static final int SSH_FXP_HANDLE = 102;
    public static final int SSH_FXP_DATA = 103;
    public static final int SSH_FXP_NAME = 104;
    public static final int SSH_FXP_ATTRS = 105;
    public static final int SSH_FXP_EXTENDED = 200;
    public static final int SSH_FXP_EXTENDED_REPLY = 201;

    public static final int SSH_FX_OK = 0;
    public static final int SSH_FX_EOF = 1;
    public static final int SSH_FX_NO_SUCH_FILE = 2;
    public static final int SSH_FX_PERMISSION_DENIED = 3;
    public static final int SSH_FX_FAILURE = 4;
    public static final int SSH_FX_BAD_MESSAGE = 5;
    public static final int SSH_FX_NO_CONNECTION = 6;
    public static final int SSH_FX_CONNECTION_LOST = 7;
    public static final int SSH_FX_OP_UNSUPPORTED = 8;
    public static final int SSH_FX_INVALID_HANDLE = 9;
    public static final int SSH_FX_NO_SUCH_PATH = 10;
    public static final int SSH_FX_FILE_ALREADY_EXISTS = 11;
    public static final int SSH_FX_WRITE_PROTECT = 12;
    public static final int SSH_FX_NO_MEDIA = 13;
    public static final int SSH_FX_NO_SPACE_ON_FILESYSTEM = 14;
    public static final int SSH_FX_QUOTA_EXCEEDED = 15;
    public static final int SSH_FX_UNKNOWN_PRINCIPAL = 16;
    public static final int SSH_FX_LOCK_CONFLICT = 17;
    public static final int SSH_FX_DIR_NOT_EMPTY = 18;
    public static final int SSH_FX_NOT_A_DIRECTORY = 19;
    public static final int SSH_FX_INVALID_FILENAME = 20;
    public static final int SSH_FX_LINK_LOOP = 21;
    public static final int SSH_FX_CANNOT_DELETE = 22;
    public static final int SSH_FX_INVALID_PARAMETER = 23;
    public static final int SSH_FX_FILE_IS_A_DIRECTORY = 24;
    public static final int SSH_FX_BYTE_RANGE_LOCK_CONFLICT = 25;
    public static final int SSH_FX_BYTE_RANGE_LOCK_REFUSED = 26;
    public static final int SSH_FX_DELETE_PENDING = 27;
    public static final int SSH_FX_FILE_CORRUPT = 28;
    public static final int SSH_FX_OWNER_INVALID = 29;
    public static final int SSH_FX_GROUP_INVALID = 30;
    public static final int SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31;

    public static final int SSH_FILEXFER_ATTR_SIZE = 0x00000001;
    public static final int SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
    public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    public static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008; // v3 naming convention
    public static final int SSH_FILEXFER_ATTR_ACCESSTIME = 0x00000008; // v4
    public static final int SSH_FILEXFER_ATTR_CREATETIME = 0x00000010; // v4
    public static final int SSH_FILEXFER_ATTR_MODIFYTIME = 0x00000020; // v4
    public static final int SSH_FILEXFER_ATTR_ACL = 0x00000040; // v4
    public static final int SSH_FILEXFER_ATTR_OWNERGROUP = 0x00000080; // v4
    public static final int SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 0x00000100; // v5
    public static final int SSH_FILEXFER_ATTR_BITS = 0x00000200; // v5
    public static final int SSH_FILEXFER_ATTR_ALLOCATION_SIZE = 0x00000400; // v6
    public static final int SSH_FILEXFER_ATTR_TEXT_HINT = 0x00000800; // v6
    public static final int SSH_FILEXFER_ATTR_MIME_TYPE = 0x00001000; // v6
    public static final int SSH_FILEXFER_ATTR_LINK_COUNT = 0x00002000; // v6
    public static final int SSH_FILEXFER_ATTR_UNTRANSLATED_NAME = 0x00004000; // v6
    public static final int SSH_FILEXFER_ATTR_CTIME = 0x00008000; // v6
    public static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

    public static final int SSH_FILEXFER_ATTR_ALL = 0x0000FFFF; // All attributes

    public static final int SSH_FILEXFER_ATTR_FLAGS_READONLY = 0x00000001;
    public static final int SSH_FILEXFER_ATTR_FLAGS_SYSTEM = 0x00000002;
    public static final int SSH_FILEXFER_ATTR_FLAGS_HIDDEN = 0x00000004;
    public static final int SSH_FILEXFER_ATTR_FLAGS_CASE_INSENSITIVE = 0x00000008;
    public static final int SSH_FILEXFER_ATTR_FLAGS_ARCHIVE = 0x00000010;
    public static final int SSH_FILEXFER_ATTR_FLAGS_ENCRYPTED = 0x00000020;
    public static final int SSH_FILEXFER_ATTR_FLAGS_COMPRESSED = 0x00000040;
    public static final int SSH_FILEXFER_ATTR_FLAGS_SPARSE = 0x00000080;
    public static final int SSH_FILEXFER_ATTR_FLAGS_APPEND_ONLY = 0x00000100;
    public static final int SSH_FILEXFER_ATTR_FLAGS_IMMUTABLE = 0x00000200;
    public static final int SSH_FILEXFER_ATTR_FLAGS_SYNC = 0x00000400;

    public static final int SSH_FILEXFER_TYPE_REGULAR = 1;
    public static final int SSH_FILEXFER_TYPE_DIRECTORY = 2;
    public static final int SSH_FILEXFER_TYPE_SYMLINK = 3;
    public static final int SSH_FILEXFER_TYPE_SPECIAL = 4;
    public static final int SSH_FILEXFER_TYPE_UNKNOWN = 5;
    public static final int SSH_FILEXFER_TYPE_SOCKET = 6; // v5
    public static final int SSH_FILEXFER_TYPE_CHAR_DEVICE = 7; // v5
    public static final int SSH_FILEXFER_TYPE_BLOCK_DEVICE = 8; // v5
    public static final int SSH_FILEXFER_TYPE_FIFO = 9; // v5

    public static final int SSH_FXF_READ = 0x00000001;
    public static final int SSH_FXF_WRITE = 0x00000002;
    public static final int SSH_FXF_APPEND = 0x00000004;
    public static final int SSH_FXF_CREAT = 0x00000008;
    public static final int SSH_FXF_TRUNC = 0x00000010;
    public static final int SSH_FXF_EXCL = 0x00000020;
    public static final int SSH_FXF_TEXT = 0x00000040;

    public static final int SSH_FXF_ACCESS_DISPOSITION = 0x00000007;
    public static final int SSH_FXF_CREATE_NEW = 0x00000000;
    public static final int SSH_FXF_CREATE_TRUNCATE = 0x00000001;
    public static final int SSH_FXF_OPEN_EXISTING = 0x00000002;
    public static final int SSH_FXF_OPEN_OR_CREATE = 0x00000003;
    public static final int SSH_FXF_TRUNCATE_EXISTING = 0x00000004;
    public static final int SSH_FXF_APPEND_DATA = 0x00000008;
    public static final int SSH_FXF_APPEND_DATA_ATOMIC = 0x00000010;
    public static final int SSH_FXF_TEXT_MODE = 0x00000020;
    public static final int SSH_FXF_READ_LOCK = 0x00000040;
    public static final int SSH_FXF_WRITE_LOCK = 0x00000080;
    public static final int SSH_FXF_DELETE_LOCK = 0x00000100;
    public static final int SSH_FXF_BLOCK_ADVISORY = 0x00000200;
    public static final int SSH_FXF_NOFOLLOW = 0x00000400;
    public static final int SSH_FXF_DELETE_ON_CLOSE = 0x00000800;
    public static final int SSH_FXF_ACCESS_AUDIT_ALARM_INFO = 0x00001000;
    public static final int SSH_FXF_ACCESS_BACKUP = 0x00002000;
    public static final int SSH_FXF_BACKUP_STREAM = 0x00004000;
    public static final int SSH_FXF_OVERRIDE_OWNER = 0x00008000;

    public static final int SSH_FXP_RENAME_OVERWRITE = 0x00000001;
    public static final int SSH_FXP_RENAME_ATOMIC = 0x00000002;
    public static final int SSH_FXP_RENAME_NATIVE = 0x00000004;

    public static final int SSH_FXP_REALPATH_NO_CHECK = 0x00000001;
    public static final int SSH_FXP_REALPATH_STAT_IF = 0x00000002;
    public static final int SSH_FXP_REALPATH_STAT_ALWAYS = 0x00000003;

    public static final int SSH_FXF_RENAME_OVERWRITE = 0x00000001;
    public static final int SSH_FXF_RENAME_ATOMIC = 0x00000002;
    public static final int SSH_FXF_RENAME_NATIVE = 0x00000004;

    public static final int SFX_ACL_CONTROL_INCLUDED = 0x00000001;
    public static final int SFX_ACL_CONTROL_PRESENT = 0x00000002;
    public static final int SFX_ACL_CONTROL_INHERITED = 0x00000004;
    public static final int SFX_ACL_AUDIT_ALARM_INCLUDED = 0x00000010;
    public static final int SFX_ACL_AUDIT_ALARM_INHERITED = 0x00000020;

    public static final int ACE4_ACCESS_ALLOWED_ACE_TYPE = 0x00000000;
    public static final int ACE4_ACCESS_DENIED_ACE_TYPE = 0x00000001;
    public static final int ACE4_SYSTEM_AUDIT_ACE_TYPE = 0x00000002;
    public static final int ACE4_SYSTEM_ALARM_ACE_TYPE = 0x00000003;

    public static final int ACE4_FILE_INHERIT_ACE = 0x00000001;
    public static final int ACE4_DIRECTORY_INHERIT_ACE = 0x00000002;
    public static final int ACE4_NO_PROPAGATE_INHERIT_ACE = 0x00000004;
    public static final int ACE4_INHERIT_ONLY_ACE = 0x00000008;
    public static final int ACE4_SUCCESSFUL_ACCESS_ACE_FLAG = 0x00000010;
    public static final int ACE4_FAILED_ACCESS_ACE_FLAG = 0x00000020;
    public static final int ACE4_IDENTIFIER_GROUP = 0x00000040;

    public static final int ACE4_READ_DATA = 0x00000001;
    public static final int ACE4_LIST_DIRECTORY = 0x00000001;
    public static final int ACE4_WRITE_DATA = 0x00000002;
    public static final int ACE4_ADD_FILE = 0x00000002;
    public static final int ACE4_APPEND_DATA = 0x00000004;
    public static final int ACE4_ADD_SUBDIRECTORY = 0x00000004;
    public static final int ACE4_READ_NAMED_ATTRS = 0x00000008;
    public static final int ACE4_WRITE_NAMED_ATTRS = 0x00000010;
    public static final int ACE4_EXECUTE = 0x00000020;
    public static final int ACE4_DELETE_CHILD = 0x00000040;
    public static final int ACE4_READ_ATTRIBUTES = 0x00000080;
    public static final int ACE4_WRITE_ATTRIBUTES = 0x00000100;
    public static final int ACE4_DELETE = 0x00010000;
    public static final int ACE4_READ_ACL = 0x00020000;
    public static final int ACE4_WRITE_ACL = 0x00040000;
    public static final int ACE4_WRITE_OWNER = 0x00080000;
    public static final int ACE4_SYNCHRONIZE = 0x00100000;

    public static final int S_IFMT = 0170000; // bitmask for the file type bitfields
    public static final int S_IFSOCK = 0140000; // socket
    public static final int S_IFLNK = 0120000; // symbolic link
    public static final int S_IFREG = 0100000; // regular file
    public static final int S_IFBLK = 0060000; // block device
    public static final int S_IFDIR = 0040000; // directory
    public static final int S_IFCHR = 0020000; // character device
    public static final int S_IFIFO = 0010000; // fifo
    public static final int S_ISUID = 0004000; // set UID bit
    public static final int S_ISGID = 0002000; // set GID bit
    public static final int S_ISVTX = 0001000; // sticky bit
    public static final int S_IRUSR = 0000400;
    public static final int S_IWUSR = 0000200;
    public static final int S_IXUSR = 0000100;
    public static final int S_IRGRP = 0000040;
    public static final int S_IWGRP = 0000020;
    public static final int S_IXGRP = 0000010;
    public static final int S_IROTH = 0000004;
    public static final int S_IWOTH = 0000002;
    public static final int S_IXOTH = 0000001;

    public static final int SFTP_V3 = 3;
    public static final int SFTP_V4 = 4;
    public static final int SFTP_V5 = 5;
    public static final int SFTP_V6 = 6;

    // (Some) names of known extensions
    public static final String EXT_VERSIONS = "versions";
    public static final String EXT_NEWLINE = "newline";
    public static final String EXT_VENDOR_ID = "vendor-id";
    public static final String EXT_SUPPORTED = "supported";
    public static final String EXT_SUPPORTED2 = "supported2";
    public static final String EXT_TEXT_SEEK = "text-seek";
    public static final String EXT_VERSION_SELECT = "version-select";
    public static final String EXT_COPY_FILE = "copy-file";

    public static final String EXT_MD5_HASH = "md5-hash";
    public static final String EXT_MD5_HASH_HANDLE = "md5-hash-handle";
    public static final int MD5_QUICK_HASH_SIZE = 2048;

    public static final String EXT_CHECK_FILE_HANDLE = "check-file-handle";
    public static final String EXT_CHECK_FILE_NAME = "check-file-name";
    public static final int MIN_CHKFILE_BLOCKSIZE = 256;

    public static final String EXT_CHECK_FILE = "check-file";
    public static final String EXT_COPY_DATA = "copy-data";
    public static final String EXT_SPACE_AVAILABLE = "space-available";

    // see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-11 section 5.4
    public static final String EXT_ACL_SUPPORTED = "acl-supported";
    public static final int SSH_ACL_CAP_ALLOW = 0x00000001;
    public static final int SSH_ACL_CAP_DENY = 0x00000002;
    public static final int SSH_ACL_CAP_AUDIT = 0x00000004;
    public static final int SSH_ACL_CAP_ALARM = 0x00000008;
    public static final int SSH_ACL_CAP_INHERIT_ACCESS = 0x00000010;
    public static final int SSH_ACL_CAP_INHERIT_AUDIT_ALARM = 0x00000020;

    private SftpConstants() {
        throw new UnsupportedOperationException("No instance");
    }

    private static final class LazyCommandNameHolder {
        private static final Map<Integer, String> NAMES_MAP = Collections.unmodifiableMap(
                LoggingUtils.generateMnemonicMap(SftpConstants.class, f -> {
                    String name = f.getName();
                    return name.startsWith("SSH_FXP_")
                            // exclude the rename modes which are not opcodes
                            && (!name.startsWith("SSH_FXP_RENAME_"))
                    // exclude the realpath modes wich are not opcodes
                            && (!name.startsWith("SSH_FXP_REALPATH_"));
                }));

        private LazyCommandNameHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts a command value to a user-friendly name
     *
     * @param  cmd The command value
     * @return     The user-friendly name - if not one of the defined {@code SSH_FXP_XXX} values then returns the string
     *             representation of the command's value
     */
    public static String getCommandMessageName(int cmd) {
        @SuppressWarnings("synthetic-access")
        String name = LazyCommandNameHolder.NAMES_MAP.get(cmd);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(cmd);
        } else {
            return name;
        }
    }

    private static final class LazyStatusNameHolder {
        private static final Map<Integer, String> STATUS_MAP = Collections.unmodifiableMap(
                LoggingUtils.generateMnemonicMap(SftpConstants.class, "SSH_FX_"));

        private LazyStatusNameHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * Converts a return status value to a user-friendly name
     *
     * @param  status The status value
     * @return        The user-friendly name - if not one of the defined {@code SSH_FX_XXX} values then returns the
     *                string representation of the status value
     */
    public static String getStatusName(int status) {
        @SuppressWarnings("synthetic-access")
        String name = LazyStatusNameHolder.STATUS_MAP.get(status);
        if (GenericUtils.isEmpty(name)) {
            return Integer.toString(status);
        } else {
            return name;
        }
    }
}
