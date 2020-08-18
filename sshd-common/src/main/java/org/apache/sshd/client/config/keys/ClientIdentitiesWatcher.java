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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderHolder;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

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
             ClientIdentityLoaderHolder.loaderHolderOf(Objects.requireNonNull(loader, "No client identity loader")),
             FilePasswordProviderHolder.providerHolderOf(Objects.requireNonNull(provider, "No password provider")),
             strict);
    }

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
                                   ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider) {
        this(paths, loader, provider, true);
    }

    public ClientIdentitiesWatcher(Collection<? extends Path> paths,
                                   ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider, boolean strict) {
        this(buildProviders(paths, loader, provider, strict));
    }

    public ClientIdentitiesWatcher(Collection<ClientIdentityProvider> providers) {
        this.providers = providers;
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return loadKeys(session, null);
    }

    protected Iterable<KeyPair> loadKeys(SessionContext session, Predicate<? super KeyPair> filter) {
        return ClientIdentityProvider.lazyKeysLoader(providers, p -> doGetKeyPairs(session, p), filter);
    }

    protected Iterable<KeyPair> doGetKeyPairs(SessionContext session, ClientIdentityProvider p) {
        try {
            Iterable<KeyPair> kp = p.getClientIdentities(session);
            if (kp == null) {
                if (log.isDebugEnabled()) {
                    log.debug("loadKeys({}) no key loaded", p);
                }
            }

            return kp;
        } catch (Throwable e) {
            warn("loadKeys({}) failed ({}) to load key: {}",
                    p, e.getClass().getSimpleName(), e.getMessage(), e);
            return null;
        }
    }

    public static List<ClientIdentityProvider> buildProviders(
            Collection<? extends Path> paths, ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        return buildProviders(paths,
                ClientIdentityLoaderHolder.loaderHolderOf(Objects.requireNonNull(loader, "No client identity loader")),
                FilePasswordProviderHolder.providerHolderOf(Objects.requireNonNull(provider, "No password provider")),
                strict);
    }

    public static List<ClientIdentityProvider> buildProviders(
            Collection<? extends Path> paths, ClientIdentityLoaderHolder loader,
            FilePasswordProviderHolder provider, boolean strict) {
        if (GenericUtils.isEmpty(paths)) {
            return Collections.emptyList();
        }

        return GenericUtils.map(paths, p -> new ClientIdentityFileWatcher(p, loader, provider, strict));
    }
}
