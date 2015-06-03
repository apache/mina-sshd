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

package org.apache.sshd.server.config.keys;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * Monitors the {@code ~/.ssh/authorized_keys} file of the user currently running
 * the server, re-loading it if necessary. It also (optionally) enforces the same
 * permissions regime as {@code OpenSSH} does for the file permissions. By default
 * also compares the current username with the authenticated one.
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultAuthorizedKeysAuthenticator extends AuthorizedKeysAuthenticator {
    /**
     * The {@link Set} of {@link PosixFilePermission} <U>not</U> allowed if strict
     * permissions are enforced
     */
    public static final Set<PosixFilePermission> STRICTLY_PROHIBITED_FILE_PERMISSION =
            Collections.unmodifiableSet(
                    EnumSet.of(PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                               PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE));

    /**
     * The default instance that enforces the same permissions regime as {@code OpenSSH}
     */
    public static final DefaultAuthorizedKeysAuthenticator INSTANCE = new DefaultAuthorizedKeysAuthenticator(true);

    private final boolean strict;
    private final String user;

    /**
     * @param strict If {@code true} then makes sure that the containing folder
     * has 0700 access and the file 0600. <B>Note:</B> for <I>Windows</I> it
     * does not check these permissions 
     */
    public DefaultAuthorizedKeysAuthenticator(boolean strict) {
        this(System.getProperty("user.name"), strict);
    }

    public DefaultAuthorizedKeysAuthenticator(String user, boolean strict) {
        this(user, AuthorizedKeyEntry.getDefaultAuthorizedKeysFile(), strict);
    }

    public DefaultAuthorizedKeysAuthenticator(File file, boolean strict) {
        this(ValidateUtils.checkNotNull(file, "No file provided", GenericUtils.EMPTY_OBJECT_ARRAY).toPath(), strict, IoUtils.getLinkOptions(false));
    }

    public DefaultAuthorizedKeysAuthenticator(String user, File file, boolean strict) {
        this(user, ValidateUtils.checkNotNull(file, "No file provided", GenericUtils.EMPTY_OBJECT_ARRAY).toPath(), strict, IoUtils.getLinkOptions(false));
    }

    public DefaultAuthorizedKeysAuthenticator(Path path, boolean strict, LinkOption ... options) {
        this(System.getProperty("user.name"), path, strict, options);
    }

    public DefaultAuthorizedKeysAuthenticator(String user, Path path, boolean strict, LinkOption ... options) {
        super(path, options);
        this.user = ValidateUtils.checkNotNullAndNotEmpty(user, "No username provided", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.strict = strict;
    }

    public final String getUsername() {
        return user;
    }

    public final boolean isStrict() {
        return strict;
    }

    @Override
    protected boolean isValidUsername(String username, ServerSession session) {
        if (!super.isValidUsername(username, session)) {
            return false;
        }
        
        String expected = getUsername();
        if (username.equals(expected)) {
            return true;
        } else {
            return false;   // debug breakpoint
        }
    }

    @Override
    protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(Path path, String username, ServerSession session) throws IOException {
        if (isStrict()) {
            if (log.isDebugEnabled()) {
                log.info("reloadAuthorizedKeys(" + username + ")[" + session + "] check permissions of " + path);
            }
            
            Collection<PosixFilePermission> perms = IoUtils.getPermissions(path);
            // this is true for Windows as well
            if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                throw new FileSystemException(path.toString(), path.toString(), "File is not allowed to have e(x)ecute permission");
            }

            if (OsUtils.isUNIX()) {
                validateFilePath(path, perms, STRICTLY_PROHIBITED_FILE_PERMISSION);

                Path parent=path.getParent();
                validateFilePath(parent, IoUtils.getPermissions(parent), STRICTLY_PROHIBITED_FILE_PERMISSION);
            }
        }

        return super.reloadAuthorizedKeys(path, username, session);
    }
    
    /**
     * @param path The {@link Path} to be validated
     * @param perms The current {@link PosixFilePermission}s
     * @param excluded The permissions <U>not</U> allowed to exist
     * @return The original path
     * @throws IOException If an excluded permission appears in the current ones
     */
    protected Path validateFilePath(Path path, Collection<PosixFilePermission> perms, Collection<PosixFilePermission> excluded) throws IOException {
        if (GenericUtils.isEmpty(perms) || GenericUtils.isEmpty(excluded)) {
            return path;
        }

        for (PosixFilePermission p : excluded) {
            if (perms.contains(p)) {
                throw new FileSystemException(path.toString(), path.toString(), "File is not allowed to have permission=" + p);
            }
        }
        
        return path;
    }
}