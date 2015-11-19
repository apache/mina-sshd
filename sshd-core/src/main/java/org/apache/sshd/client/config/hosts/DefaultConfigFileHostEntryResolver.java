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

package org.apache.sshd.client.config.hosts;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Monitors the {@code ~/.ssh/config} file of the user currently running
 * the server, re-loading it if necessary. It also (optionally) enforces the same
 * permissions regime as {@code OpenSSH} does for the file permissions.

 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultConfigFileHostEntryResolver extends ConfigFileHostEntryResolver {

    /**
     * The default instance that enforces the same permissions regime as {@code OpenSSH}
     */
    public static final DefaultConfigFileHostEntryResolver INSTANCE = new DefaultConfigFileHostEntryResolver(true);

    /**
     * The {@link Set} of {@link PosixFilePermission} <U>not</U> allowed if strict
     * permissions are enforced on key files
     */
    public static final Set<PosixFilePermission> STRICTLY_PROHIBITED_FILE_PERMISSION =
            Collections.unmodifiableSet(
                    EnumSet.of(PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE));

    private final boolean strict;

    /**
     * @param strict If {@code true} then makes sure that the containing folder
     *               has 0700 access and the file 0600. <B>Note:</B> for <I>Windows</I> it
     *               does not check these permissions
     */
    public DefaultConfigFileHostEntryResolver(boolean strict) {
        this(HostConfigEntry.getDefaultHostConfigFile(), strict);
    }

    public DefaultConfigFileHostEntryResolver(File file, boolean strict) {
        this(ValidateUtils.checkNotNull(file, "No file provided").toPath(), strict, IoUtils.getLinkOptions(false));
    }

    public DefaultConfigFileHostEntryResolver(Path path, boolean strict, LinkOption ... options) {
        super(path, options);
        this.strict = strict;
    }

    public final boolean isStrict() {
        return strict;
    }

    @Override
    protected List<HostConfigEntry> reloadHostConfigEntries(Path path, String host, int port, String username) throws IOException {
        if (isStrict()) {
            if (log.isDebugEnabled()) {
                log.debug("reloadHostConfigEntries({}@{}:{}) check permissions of {}", username, host, port, path);
            }

            PosixFilePermission violation = validateStrictConfigFilePermissions(path);
            if (violation != null) {
                throw new IOException("String permission violation (" + violation + ") for " + path);
            }

            String ownerViolation = validateStrictConfigFileOwner(path);
            if (ownerViolation != null) {
                throw new IOException("String owner violation (" + ownerViolation + ") for " + path);
            }
        }

        return super.reloadHostConfigEntries(path, host, port, username);
    }

    /**
     * <P>Checks if a path has strict permissions</P>
     * <UL>
     *
     * <LI><P>
     * (For {@code Unix}) The path may not have group or others write permissions
     * </P></LI>
     *
     * </UL>
     *
     * @param path    The {@link Path} to be checked - ignored if {@code null}
     *                or does not exist
     * @param options The {@link LinkOption}s to use to query the file's permissions
     * @return The violated {@link PosixFilePermission} - {@code null} if
     * no violations detected
     * @throws IOException If failed to retrieve the permissions
     * @see #STRICTLY_PROHIBITED_FILE_PERMISSION
     */
    public static PosixFilePermission validateStrictConfigFilePermissions(Path path, LinkOption... options) throws IOException {
        if ((path == null) || (!Files.exists(path, options))) {
            return null;
        }

        Collection<PosixFilePermission> perms = IoUtils.getPermissions(path, options);
        if (GenericUtils.isEmpty(perms)) {
            return null;
        }

        if (OsUtils.isUNIX()) {
            PosixFilePermission p = IoUtils.validateExcludedPermissions(perms, STRICTLY_PROHIBITED_FILE_PERMISSION);
            if (p != null) {
                return p;
            }
        }

        return null;
    }

    /**
     * <P>Checks if a path has strict ownership</P>
     * <UL>
     *
     * <LI><P>
     * The path must be owned by current user.
     * </P></LI>
     *
     * <LI><P>
     * (For {@code Unix}) The path may be owned by root.
     * </P></LI>
     *
     * </UL>
     *
     * @param path    The {@link Path} to be checked - ignored if {@code null}
     *                or does not exist
     * @param options The {@link LinkOption}s to use to query the file's permissions
     * @return The violated owner - {@code null} if
     * no violations detected
     * @throws IOException If failed to retrieve the ownership
     */
    public static String validateStrictConfigFileOwner(Path path, LinkOption... options) throws IOException {
        if ((path == null) || (!Files.exists(path, options))) {
            return null;
        }

        String current = IoUtils.getCurrentUser();
        String owner = IoUtils.getFileOwner(path, options);

        if (current == null &&  owner == null) {
            // we cannot detect permissions
            return null;
        }

        Set<String> expected = new HashSet<>();
        if (current != null) {
            expected.add(current);
        }
        if (OsUtils.isUNIX()) {
            expected.add(OsUtils.ROOT_USER);
        }

        if (!expected.contains(owner)) {
            return owner;
        }

        return null;
    }

}
