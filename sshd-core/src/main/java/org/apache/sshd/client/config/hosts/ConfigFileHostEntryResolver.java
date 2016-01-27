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
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;

/**
 * Watches for changes in a configuration file and automatically reloads any changes
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ConfigFileHostEntryResolver extends ModifiableFileWatcher implements HostConfigEntryResolver {
    private final AtomicReference<HostConfigEntryResolver> delegateHolder = // assumes initially empty
            new AtomicReference<HostConfigEntryResolver>(HostConfigEntryResolver.EMPTY);

    public ConfigFileHostEntryResolver(File file) {
        this(ValidateUtils.checkNotNull(file, "No file to watch").toPath());
    }

    public ConfigFileHostEntryResolver(Path file) {
        this(file, IoUtils.EMPTY_LINK_OPTIONS);
    }

    public ConfigFileHostEntryResolver(Path file, LinkOption... options) {
        super(file, options);
    }

    @Override
    public HostConfigEntry resolveEffectiveHost(String host, int port, String username) throws IOException {
        try {
            HostConfigEntryResolver delegate = ValidateUtils.checkNotNull(resolveEffectiveResolver(host, port, username), "No delegate");
            HostConfigEntry entry = delegate.resolveEffectiveHost(host, port, username);
            if (log.isDebugEnabled()) {
                log.debug("resolveEffectiveHost({}@{}:{}) => {}", username, host, port, entry);
            }

            return entry;
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("resolveEffectiveHost({}@{}:{}) failed ({}) to resolve: {}",
                          username, host, port, e.getClass().getSimpleName(), e.getMessage());
            }

            if (log.isTraceEnabled()) {
                log.trace("resolveEffectiveHost(" + username + "@" + host + ":" + port + ") resolution failure details", e);
            }
            if (e instanceof IOException) {
                throw (IOException) e;
            } else {
                throw new IOException(e);
            }
        }
    }

    protected HostConfigEntryResolver resolveEffectiveResolver(String host, int port, String username) throws IOException {
        if (checkReloadRequired()) {
            delegateHolder.set(HostConfigEntryResolver.EMPTY);  // start fresh

            Path path = getPath();
            if (exists()) {
                Collection<HostConfigEntry> entries = reloadHostConfigEntries(path, host, port, username);
                if (GenericUtils.size(entries) > 0) {
                    delegateHolder.set(HostConfigEntry.toHostConfigEntryResolver(entries));
                }
            } else {
                log.info("resolveEffectiveResolver({}@{}:{}) no configuration file at {}", username, host, port, path);
            }
        }

        return delegateHolder.get();
    }

    protected List<HostConfigEntry> reloadHostConfigEntries(Path path, String host, int port, String username) throws IOException {
        List<HostConfigEntry> entries = HostConfigEntry.readHostConfigEntries(path);
        log.info("resolveEffectiveResolver({}@{}:{}) loaded {} entries from {}", username, host, port, GenericUtils.size(entries), path);
        updateReloadAttributes();
        return entries;
    }
}
