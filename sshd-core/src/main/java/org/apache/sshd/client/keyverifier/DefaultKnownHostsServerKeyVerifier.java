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

package org.apache.sshd.client.keyverifier;

import java.io.File;
import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Monitors the {@code ~/.ssh/known_hosts} file of the user currently running the client, updating and re-loading it if
 * necessary. It also (optionally) enforces the same permissions regime as {@code OpenSSH}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultKnownHostsServerKeyVerifier extends KnownHostsServerKeyVerifier {
    private final boolean strict;

    public DefaultKnownHostsServerKeyVerifier(ServerKeyVerifier delegate) {
        this(delegate, true);
    }

    public DefaultKnownHostsServerKeyVerifier(ServerKeyVerifier delegate, boolean strict) {
        this(delegate, strict, KnownHostEntry.getDefaultKnownHostsFile(), IoUtils.getLinkOptions(true));
    }

    public DefaultKnownHostsServerKeyVerifier(ServerKeyVerifier delegate, boolean strict, File file) {
        this(delegate, strict, Objects.requireNonNull(file, "No file provided").toPath(), IoUtils.getLinkOptions(true));
    }

    public DefaultKnownHostsServerKeyVerifier(ServerKeyVerifier delegate, boolean strict, Path file, LinkOption... options) {
        super(delegate, file, options);
        this.strict = strict;
    }

    /**
     * @return If {@code true} then makes sure that the containing folder has 0700 access and the file 0644.
     *         <B>Note:</B> for <I>Windows</I> it does not check these permissions
     * @see    #validateStrictConfigFilePermissions(Path, LinkOption...)
     */
    public final boolean isStrict() {
        return strict;
    }

    @Override
    protected List<HostEntryPair> reloadKnownHosts(ClientSession session, Path file)
            throws IOException, GeneralSecurityException {
        if (isStrict()) {
            if (log.isDebugEnabled()) {
                log.debug("reloadKnownHosts({}) check permissions", file);
            }

            Map.Entry<String, ?> violation = validateStrictConfigFilePermissions(file);
            if (violation != null) {
                log.warn("reloadKnownHosts({}) invalid file permissions: {}", file, violation.getKey());
                updateReloadAttributes();
                return Collections.emptyList();
            }
        }

        return super.reloadKnownHosts(session, file);
    }
}
