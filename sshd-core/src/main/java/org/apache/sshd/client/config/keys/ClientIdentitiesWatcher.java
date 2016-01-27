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

package org.apache.sshd.client.config.keys;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Watches over a group of files that contains client identities
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientIdentitiesWatcher extends AbstractKeyPairProvider implements KeyPairProvider {
    private final Collection<ClientIdentityProvider> providers;

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
            ClientIdentityLoader loader, FilePasswordProvider provider) {
        this(paths, loader, provider, true);
    }

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
            ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(paths,
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(loader, "No client identity loader")),
             GenericUtils.supplierOf(ValidateUtils.checkNotNull(provider, "No password provider")),
             strict);
    }

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
            Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider) {
        this(paths, loader, provider, true);
    }

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
            Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        this(buildProviders(paths, loader, provider, strict));
    }

    public ClientIdentitiesWatcher(Collection<ClientIdentityProvider> providers) {
        this.providers = providers;
    }

    @Override
    public List<KeyPair> loadKeys() {
        if (GenericUtils.isEmpty(providers)) {
            return Collections.emptyList();
        }

        List<KeyPair> keys = new ArrayList<>(providers.size()); // optimistic initialization
        for (ClientIdentityProvider p : providers) {
            try {
                KeyPair kp = p.getClientIdentity();
                if (kp == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("loadKeys({}) no key loaded", p);
                    }
                    continue;
                }

                keys.add(kp);
            } catch (Throwable e) {
                log.warn("loadKeys({}) failed ({}) to load key: {}", p, e.getClass().getSimpleName(), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("loadKeys(" + p + ") key load failure details", e);
                }
            }
        }

        return keys;
    }

    public static List<ClientIdentityProvider> buildProviders(
            Collection<? extends Path> paths, ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        return buildProviders(paths,
                GenericUtils.supplierOf(ValidateUtils.checkNotNull(loader, "No client identity loader")),
                GenericUtils.supplierOf(ValidateUtils.checkNotNull(provider, "No password provider")),
                strict);
    }

    public static List<ClientIdentityProvider> buildProviders(
            Collection<? extends Path> paths, Supplier<ClientIdentityLoader> loader, Supplier<FilePasswordProvider> provider, boolean strict) {
        if (GenericUtils.isEmpty(paths)) {
            return Collections.emptyList();
        }

        List<ClientIdentityProvider> providers = new ArrayList<>(paths.size());
        for (Path p : paths) {
            providers.add(new ClientIdentityFileWatcher(p, loader, provider, strict));
        }

        return providers;
    }
}
