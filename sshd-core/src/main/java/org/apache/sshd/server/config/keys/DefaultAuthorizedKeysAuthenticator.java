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

package org.apache.sshd.server.config.keys;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * Monitors the {@code ~/.ssh/authorized_keys} file of the user currently running the server, re-loading it if
 * necessary. It also (optionally) enforces the same permissions regime as {@code OpenSSH} does for the file
 * permissions. By default also compares the current username with the authenticated one.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultAuthorizedKeysAuthenticator extends AuthorizedKeysAuthenticator implements UsernameHolder {

    /**
     * The default instance that enforces the same permissions regime as {@code OpenSSH}
     */
    public static final DefaultAuthorizedKeysAuthenticator INSTANCE = new DefaultAuthorizedKeysAuthenticator(true);

    private final boolean strict;
    private final String user;

    /**
     * @param strict If {@code true} then makes sure that the containing folder has 0700 access and the file 0600.
     *               <B>Note:</B> for <I>Windows</I> it does not check these permissions
     */
    public DefaultAuthorizedKeysAuthenticator(boolean strict) {
        this(OsUtils.getCurrentUser(), strict);
    }

    public DefaultAuthorizedKeysAuthenticator(String user, boolean strict) {
        this(user, getDefaultAuthorizedKeysFile(), strict);
    }

    public DefaultAuthorizedKeysAuthenticator(Path path, boolean strict, LinkOption... options) {
        this(OsUtils.getCurrentUser(), path, strict, options);
    }

    public DefaultAuthorizedKeysAuthenticator(String user, Path path, boolean strict, LinkOption... options) {
        super(path, options);
        this.user = ValidateUtils.checkNotNullAndNotEmpty(user, "No username provided");
        this.strict = strict;
    }

    @Override
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
        return username.equals(expected);
    }

    @Override
    protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(
            Path path, String username, ServerSession session)
            throws IOException, GeneralSecurityException {
        if (isStrict()) {
            if (log.isDebugEnabled()) {
                log.debug("reloadAuthorizedKeys({})[{}] check permissions of {}", username, session, path);
            }

            Map.Entry<String, ?> violation = KeyUtils.validateStrictKeyFilePermissions(path);
            if (violation != null) {
                log.warn("reloadAuthorizedKeys({})[{}] invalid file={} permissions: {}",
                        username, session, path, violation.getKey());
                updateReloadAttributes();
                return Collections.emptyList();
            }
        }

        return super.reloadAuthorizedKeys(path, username, session);
    }

    /**
     * @param  path        The {@link Path} to be validated
     * @param  perms       The current {@link PosixFilePermission}s
     * @param  excluded    The permissions <U>not</U> allowed to exist
     * @return             The original path
     * @throws IOException If an excluded permission appears in the current ones
     */
    protected Path validateFilePath(Path path, Collection<PosixFilePermission> perms, Collection<PosixFilePermission> excluded)
            throws IOException {
        PosixFilePermission p = IoUtils.validateExcludedPermissions(perms, excluded);
        if (p != null) {
            String filePath = path.toString();
            throw new FileSystemException(filePath, filePath, "File not allowed to have " + p + " permission: " + filePath);
        }

        return path;
    }
}
