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

package org.apache.sshd.sftp.client.extensions;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.helpers.CheckFileHandleExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.CheckFileNameExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.CopyDataExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.CopyFileExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.MD5FileExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.MD5HandleExtensionImpl;
import org.apache.sshd.sftp.client.extensions.helpers.SpaceAvailableExtensionImpl;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHFsyncExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHPosixRenameExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatHandleExtension;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHStatPathExtension;
import org.apache.sshd.sftp.client.extensions.openssh.helpers.OpenSSHFsyncExtensionImpl;
import org.apache.sshd.sftp.client.extensions.openssh.helpers.OpenSSHPosixRenameExtensionImpl;
import org.apache.sshd.sftp.client.extensions.openssh.helpers.OpenSSHStatHandleExtensionImpl;
import org.apache.sshd.sftp.client.extensions.openssh.helpers.OpenSSHStatPathExtensionImpl;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.extensions.ParserUtils;
import org.apache.sshd.sftp.common.extensions.openssh.FstatVfsExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.PosixRenameExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.StatVfsExtensionParser;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinSftpClientExtensions implements SftpClientExtensionFactory {
    COPY_FILE(SftpConstants.EXT_COPY_FILE, CopyFileExtension.class) {
        @Override // co-variant return
        public CopyFileExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new CopyFileExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    COPY_DATA(SftpConstants.EXT_COPY_DATA, CopyDataExtension.class) {
        @Override // co-variant return
        public CopyDataExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new CopyDataExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    MD5_FILE(SftpConstants.EXT_MD5_HASH, MD5FileExtension.class) {
        @Override // co-variant return
        public MD5FileExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new MD5FileExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    MD5_HANDLE(SftpConstants.EXT_MD5_HASH_HANDLE, MD5HandleExtension.class) {
        @Override // co-variant return
        public MD5HandleExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new MD5HandleExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    CHECK_FILE_NAME(SftpConstants.EXT_CHECK_FILE_NAME, CheckFileNameExtension.class) {
        @Override // co-variant return
        public CheckFileNameExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new CheckFileNameExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    CHECK_FILE_HANDLE(SftpConstants.EXT_CHECK_FILE_HANDLE, CheckFileHandleExtension.class) {
        @Override // co-variant return
        public CheckFileHandleExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new CheckFileHandleExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    SPACE_AVAILABLE(SftpConstants.EXT_SPACE_AVAILABLE, SpaceAvailableExtension.class) {
        @Override // co-variant return
        public SpaceAvailableExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new SpaceAvailableExtensionImpl(client, raw, ParserUtils.supportedExtensions(parsed));
        }
    },
    OPENSSH_FSYNC(FsyncExtensionParser.NAME, OpenSSHFsyncExtension.class) {
        @Override // co-variant return
        public OpenSSHFsyncExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new OpenSSHFsyncExtensionImpl(client, raw, extensions);
        }
    },
    OPENSSH_STAT_HANDLE(FstatVfsExtensionParser.NAME, OpenSSHStatHandleExtension.class) {
        @Override // co-variant return
        public OpenSSHStatHandleExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new OpenSSHStatHandleExtensionImpl(client, raw, extensions);
        }
    },
    OPENSSH_STAT_PATH(StatVfsExtensionParser.NAME, OpenSSHStatPathExtension.class) {
        @Override // co-variant return
        public OpenSSHStatPathExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new OpenSSHStatPathExtensionImpl(client, raw, extensions);
        }
    },
    OPENSSH_POSIX_RENAME(PosixRenameExtensionParser.NAME, OpenSSHPosixRenameExtension.class) {
        @Override // co-variant return
        public OpenSSHPosixRenameExtension create(
                SftpClient client, RawSftpClient raw, Map<String, byte[]> extensions, Map<String, ?> parsed) {
            return new OpenSSHPosixRenameExtensionImpl(client, raw, extensions);
        }
    };

    public static final Set<BuiltinSftpClientExtensions> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(BuiltinSftpClientExtensions.class));

    private final String name;

    private final Class<? extends SftpClientExtension> type;

    BuiltinSftpClientExtensions(String name, Class<? extends SftpClientExtension> type) {
        this.name = name;
        this.type = type;
    }

    @Override
    public final String getName() {
        return name;
    }

    public final Class<? extends SftpClientExtension> getType() {
        return type;
    }

    public static BuiltinSftpClientExtensions fromName(String n) {
        return NamedResource.findByName(n, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    public static BuiltinSftpClientExtensions fromInstance(Object o) {
        return fromType((o == null) ? null : o.getClass());
    }

    public static BuiltinSftpClientExtensions fromType(Class<?> type) {
        if ((type == null) || (!SftpClientExtension.class.isAssignableFrom(type))) {
            return null;
        }

        // the base class is assignable to everybody so we cannot distinguish between the enum(s)
        if (SftpClientExtension.class == type) {
            return null;
        }

        for (BuiltinSftpClientExtensions v : VALUES) {
            Class<?> vt = v.getType();
            if (vt.isAssignableFrom(type)) {
                return v;
            }
        }

        return null;
    }
}
