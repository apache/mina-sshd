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

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;

/**
 * Watches for changes in a configuration file and automatically reloads any changes
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ConfigFileHostEntryResolver extends ModifiableFileWatcher implements HostConfigEntryResolver {
    private final AtomicReference<HostConfigEntryResolver> delegateHolder = // assumes initially empty
            new AtomicReference<>(HostConfigEntryResolver.EMPTY);

    public ConfigFileHostEntryResolver(Path file) {
        this(file, IoUtils.EMPTY_LINK_OPTIONS);
    }

    public ConfigFileHostEntryResolver(Path file, LinkOption... options) {
        super(file, options);
    }

    @Override
    public HostConfigEntry resolveEffectiveHost(
            String host, int port, SocketAddress localAddress, String username, String proxyJump, AttributeRepository context)
            throws IOException {
        try {
            HostConfigEntryResolver delegate
                    = Objects.requireNonNull(resolveEffectiveResolver(host, port, username, proxyJump), "No delegate");
            HostConfigEntry entry = delegate.resolveEffectiveHost(host, port, localAddress, username, proxyJump, context);
            if (log.isDebugEnabled()) {
                log.debug("resolveEffectiveHost({}@{}:{}/{}) => {}", username, host, port, proxyJump, entry);
            }

            return entry;
        } catch (Throwable e) {
            debug("resolveEffectiveHost({}@{}:{}/{}) failed ({}) to resolve: {}",
                    username, host, port, proxyJump, e.getClass().getSimpleName(), e.getMessage(), e);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else {
                throw new IOException(e);
            }
        }
    }

    protected HostConfigEntryResolver resolveEffectiveResolver(String host, int port, String username, String proxyJump)
            throws IOException {
        if (checkReloadRequired()) {
            delegateHolder.set(HostConfigEntryResolver.EMPTY); // start fresh

            Path path = getPath();
            if (exists()) {
                Collection<HostConfigEntry> entries = reloadHostConfigEntries(path, host, port, username, proxyJump);
                if (GenericUtils.size(entries) > 0) {
                    delegateHolder.set(HostConfigEntry.toHostConfigEntryResolver(entries));
                }
            } else {
                log.info("resolveEffectiveResolver({}@{}:{}/{}) no configuration file at {}", username, host, port, proxyJump,
                        path);
            }
        }

        return delegateHolder.get();
    }

    protected List<HostConfigEntry> reloadHostConfigEntries(
            Path path, String host, int port, String username, String proxyJump)
            throws IOException {
        List<HostConfigEntry> entries = HostConfigEntry.readHostConfigEntries(path);
        log.info("resolveEffectiveResolver({}@{}:{}) loaded {} entries from {}", username, host, port,
                GenericUtils.size(entries), path);
        updateReloadAttributes();
        return entries;
    }
}
