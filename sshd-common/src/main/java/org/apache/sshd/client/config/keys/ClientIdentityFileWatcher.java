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

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderHolder;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.common.util.io.resource.PathResource;

/**
 * A {@link ClientIdentityProvider} that watches a given key file re-loading its contents if it is ever modified,
 * deleted or (re-)created
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientIdentityFileWatcher
        extends ModifiableFileWatcher
        implements ClientIdentityProvider, ClientIdentityLoaderHolder, FilePasswordProviderHolder {
    private final AtomicReference<Iterable<KeyPair>> identitiesHolder = new AtomicReference<>(null);
    private final ClientIdentityLoaderHolder loaderHolder;
    private final FilePasswordProviderHolder providerHolder;
    private final boolean strict;

    public ClientIdentityFileWatcher(Path path, ClientIdentityLoader loader, FilePasswordProvider provider) {
        this(path, loader, provider, true);
    }

    public ClientIdentityFileWatcher(Path path, ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        this(path,
             ClientIdentityLoaderHolder.loaderHolderOf(Objects.requireNonNull(loader, "No client identity loader")),
             FilePasswordProviderHolder.providerHolderOf(Objects.requireNonNull(provider, "No password provider")),
             strict);
    }

    public ClientIdentityFileWatcher(
                                     Path path, ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider) {
        this(path, loader, provider, true);
    }

    public ClientIdentityFileWatcher(
                                     Path path, ClientIdentityLoaderHolder loader, FilePasswordProviderHolder provider,
                                     boolean strict) {
        super(path);
        this.loaderHolder = Objects.requireNonNull(loader, "No client identity loader");
        this.providerHolder = Objects.requireNonNull(provider, "No password provider");
        this.strict = strict;
    }

    public boolean isStrict() {
        return strict;
    }

    @Override
    public ClientIdentityLoader getClientIdentityLoader() {
        return loaderHolder.getClientIdentityLoader();
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return providerHolder.getFilePasswordProvider();
    }

    @Override
    public Iterable<KeyPair> getClientIdentities(SessionContext session)
            throws IOException, GeneralSecurityException {
        if (!checkReloadRequired()) {
            return identitiesHolder.get();
        }

        Iterable<KeyPair> kp = identitiesHolder.getAndSet(null); // start fresh
        Path path = getPath();
        if (!exists()) {
            return identitiesHolder.get();
        }

        kp = reloadClientIdentities(session, path);
        updateReloadAttributes();
        identitiesHolder.set(kp);
        return kp;
    }

    protected Iterable<KeyPair> reloadClientIdentities(SessionContext session, Path path)
            throws IOException, GeneralSecurityException {
        if (isStrict()) {
            Map.Entry<String, Object> violation = KeyUtils.validateStrictKeyFilePermissions(path, IoUtils.EMPTY_LINK_OPTIONS);
            if (violation != null) {
                if (log.isDebugEnabled()) {
                    log.debug("reloadClientIdentity({}) ignore due to {}", path, violation.getKey());
                }
                return null;
            }
        }

        PathResource location = new PathResource(path);
        ClientIdentityLoader idLoader = Objects.requireNonNull(getClientIdentityLoader(), "No client identity loader");
        if (idLoader.isValidLocation(location)) {
            Iterable<KeyPair> ids = idLoader.loadClientIdentities(session, location, getFilePasswordProvider());
            if (log.isTraceEnabled()) {
                if (ids == null) {
                    log.trace("reloadClientIdentity({}) no keys loaded", location);
                } else {
                    for (KeyPair kp : ids) {
                        PublicKey key = (kp == null) ? null : kp.getPublic();
                        if (key != null) {
                            log.trace("reloadClientIdentity({}) loaded {}-{}",
                                    location, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
                        }
                    }
                }
            }

            return ids;
        }

        if (log.isDebugEnabled()) {
            log.debug("reloadClientIdentity({}) invalid location", location);
        }

        return null;
    }
}
