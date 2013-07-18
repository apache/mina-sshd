/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.sftp.subsystem;

public final class SftpConstants {

    private SftpConstants() { }

    //
    // Packet types
    //

    public enum Type {

        SSH_FXP_INIT(1),
        SSH_FXP_VERSION(2),
        SSH_FXP_OPEN(3),
        SSH_FXP_CLOSE(4),
        SSH_FXP_READ(5),
        SSH_FXP_WRITE(6),
        SSH_FXP_LSTAT(7),
        SSH_FXP_FSTAT(8),
        SSH_FXP_SETSTAT(9),
        SSH_FXP_FSETSTAT(10),
        SSH_FXP_OPENDIR(11),
        SSH_FXP_READDIR(12),
        SSH_FXP_REMOVE(13),
        SSH_FXP_MKDIR(14),
        SSH_FXP_RMDIR(15),
        SSH_FXP_REALPATH(16),
        SSH_FXP_STAT(17),
        SSH_FXP_RENAME(18),
        SSH_FXP_READLINK(19),
        SSH_FXP_LINK(21),
        SSH_FXP_BLOCK(22),
        SSH_FXP_UNBLOCK(23),

        SSH_FXP_STATUS(101),
        SSH_FXP_HANDLE(102),
        SSH_FXP_DATA(103),
        SSH_FXP_NAME(104),
        SSH_FXP_ATTRS(105),

        SSH_FXP_EXTENDED(200),
        SSH_FXP_EXTENDED_REPLY(201);

        private byte b;
        private Type(int b) {
            this.b = (byte) b;
        }

        public byte toByte() {
            return b;
        }

        /*
        static Type[] commands;
        static {
            commands = new Type[256];
            for (Type c : Type.values()) {
                if (commands[c.toByte()] == null) {
                    commands[c.toByte()] = c;
                }
            }
        }
        public static Type fromByte(byte b) {
            return commands[b];
        }
        */
    }
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
    public static final int SSH_FXP_LINK = 21;
    public static final int SSH_FXP_BLOCK = 22;
    public static final int SSH_FXP_UNBLOCK = 23;

    public static final int SSH_FXP_STATUS = 101;
    public static final int SSH_FXP_HANDLE = 102;
    public static final int SSH_FXP_DATA = 103;
    public static final int SSH_FXP_NAME = 104;
    public static final int SSH_FXP_ATTRS = 105;

    public static final int SSH_FXP_EXTENDED = 200;
    public static final int SSH_FXP_EXTENDED_REPLY = 201;


    //
    // Error codes
    //
    public enum ErrorCode {

        SSH_FX_OK(0),
        SSH_FX_EOF(1),
        SSH_FX_NO_SUCH_FILE(2),
        SSH_FX_PERMISSION_DENIED(3),
        SSH_FX_FAILURE(4),
        SSH_FX_BAD_MESSAGE(5),
        SSH_FX_NO_CONNECTION(6),
        SSH_FX_CONNECTION_LOST(7),
        SSH_FX_OP_UNSUPPORTED(8),
        SSH_FX_INVALID_HANDLE(9),
        SSH_FX_NO_SUCH_PATH(10),
        SSH_FX_FILE_ALREADY_EXISTS(11),
        SSH_FX_WRITE_PROTECT(12),
        SSH_FX_NO_MEDIA(13),
        SSH_FX_NO_SPACE_ON_FILESYSTEM(14),
        SSH_FX_QUOTA_EXCEEDED(15),
        SSH_FX_UNKNOWN_PRINCIPAL(16),
        SSH_FX_LOCK_CONFLICT(17),
        SSH_FX_DIR_NOT_EMPTY(18),
        SSH_FX_NOT_A_DIRECTORY(19),
        SSH_FX_INVALID_FILENAME(20),
        SSH_FX_LINK_LOOP(21),
        SSH_FX_CANNOT_DELETE(22),
        SSH_FX_INVALID_PARAMETER(23),
        SSH_FX_FILE_IS_A_DIRECTORY(24),
        SSH_FX_BYTE_RANGE_LOCK_CONFLICT(25),
        SSH_FX_BYTE_RANGE_LOCK_REFUSED(26),
        SSH_FX_DELETE_PENDING(27),
        SSH_FX_FILE_CORRUPT(28),
        SSH_FX_OWNER_INVALID(29),
        SSH_FX_GROUP_INVALID(30),
        SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK(31);

        private byte b;
        private ErrorCode(int b) {
            this.b = (byte) b;
        }

        public byte toByte() {
            return b;
        }

        static ErrorCode[] codes;
        static {
            codes = new ErrorCode[256];
            for (ErrorCode c : ErrorCode.values()) {
                if (codes[c.toByte()] == null) {
                    codes[c.toByte()] = c;
                }
            }
        }
        public static ErrorCode fromByte(byte b) {
            return codes[b];
        }
    }

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
    public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    public static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008; //v3 naming convention
    public static final int SSH_FILEXFER_ATTR_ACCESSTIME = 0x00000008;
    public static final int SSH_FILEXFER_ATTR_CREATETIME = 0x00000010;
    public static final int SSH_FILEXFER_ATTR_MODIFYTIME = 0x00000020;
    public static final int SSH_FILEXFER_ATTR_ACL = 0x00000040;
    public static final int SSH_FILEXFER_ATTR_OWNERGROUP = 0x00000080;
    public static final int SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 0x00000100;
    public static final int SSH_FILEXFER_ATTR_BITS = 0x00000200;
    public static final int SSH_FILEXFER_ATTR_ALLOCATION_SIZE = 0x00000400;
    public static final int SSH_FILEXFER_ATTR_TEXT_HINT = 0x00000800;
    public static final int SSH_FILEXFER_ATTR_MIME_TYPE = 0x00001000;
    public static final int SSH_FILEXFER_ATTR_LINK_COUNT = 0x00002000;
    public static final int SSH_FILEXFER_ATTR_UNTRANSLATED_NAME = 0x00004000;
    public static final int SSH_FILEXFER_ATTR_CTIME = 0x00008000;
    public static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

    public static final int SSH_FILEXFER_TYPE_REGULAR = 1;
    public static final int SSH_FILEXFER_TYPE_DIRECTORY = 2;
    public static final int SSH_FILEXFER_TYPE_SYMLINK = 3;
    public static final int SSH_FILEXFER_TYPE_SPECIAL = 4;
    public static final int SSH_FILEXFER_TYPE_UNKNOWN = 5;
    public static final int SSH_FILEXFER_TYPE_SOCKET = 6;
    public static final int SSH_FILEXFER_TYPE_CHAR_DEVICE = 7;
    public static final int SSH_FILEXFER_TYPE_BLOCK_DEVICE = 8;
    public static final int SSH_FILEXFER_TYPE_FIFO = 9;


    public static final int SSH_FXF_ACCESS_DISPOSITION = 0x00000007;
    public static final int SSH_FXF_CREATE_NEW = 0x00000000;
    public static final int SSH_FXF_CREATE_TRUNCATE = 0x00000001;
    public static final int SSH_FXF_OPEN_EXISTING = 0x00000002;
    public static final int SSH_FXF_OPEN_OR_CREATE = 0x00000003;
    public static final int SSH_FXF_TRUNCATE_EXISTING = 0x00000004;
    public static final int SSH_FXF_APPEND_DATA = 0x00000008;
    public static final int SSH_FXF_APPEND_DATA_ATOMIC = 0x00000010;
    public static final int SSH_FXF_TEXT_MODE = 0x00000020;
    public static final int SSH_FXF_BLOCK_READ = 0x00000040;
    public static final int SSH_FXF_BLOCK_WRITE = 0x00000080;
    public static final int SSH_FXF_BLOCK_DELETE = 0x00000100;
    public static final int SSH_FXF_BLOCK_ADVISORY = 0x00000200;
    public static final int SSH_FXF_NOFOLLOW = 0x00000400;
    public static final int SSH_FXF_DELETE_ON_CLOSE = 0x00000800;
    public static final int SSH_FXF_ACCESS_AUDIT_ALARM_INFO = 0x00001000;
    public static final int SSH_FXF_ACCESS_BACKUP = 0x00002000;
    public static final int SSH_FXF_BACKUP_STREAM = 0x00004000;
    public static final int SSH_FXF_OVERRIDE_OWNER = 0x00008000;

    public static final int SSH_FXF_READ = 0x00000001;
    public static final int SSH_FXF_WRITE = 0x00000002;
    public static final int SSH_FXF_APPEND = 0x00000004;
    public static final int SSH_FXF_CREAT = 0x00000008;
    public static final int SSH_FXF_TRUNC = 0x00000010;
    public static final int SSH_FXF_EXCL = 0x00000020;
    public static final int SSH_FXF_TEXT = 0x00000040;

    public static final int SSH_FXP_REALPATH_NO_CHECK =    0x00000001;
    public static final int SSH_FXP_REALPATH_STAT_IF =     0x00000002;
    public static final int SSH_FXP_REALPATH_STAT_ALWAYS = 0x00000003;

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

    public static final int S_IRUSR = 0000400;
    public static final int S_IWUSR = 0000200;
    public static final int S_IXUSR = 0000100;
    public static final int S_IRGRP = 0000040;
    public static final int S_IWGRP = 0000020;
    public static final int S_IXGRP = 0000010;
    public static final int S_IROTH = 0000004;
    public static final int S_IWOTH = 0000002;
    public static final int S_IXOTH = 0000001;
    public static final int S_ISUID = 0004000;
    public static final int S_ISGID = 0002000;
    public static final int S_ISVTX = 0001000;

}
