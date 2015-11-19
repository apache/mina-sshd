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
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;

import org.apache.sshd.common.util.Pair;
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

            Pair<String, Object> violation = validateStrictConfigFilePermissions(path);
            if (violation != null) {
                throw new IOException(String.format("%s for %s", violation.getFirst(), path));
            }
        }

        return super.reloadHostConfigEntries(path, host, port, username);
    }

}
