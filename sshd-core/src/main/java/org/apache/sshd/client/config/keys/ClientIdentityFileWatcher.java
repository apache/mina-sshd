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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;

/**
 * A {@link ClientIdentityProvider} that watches a given key file re-loading
 * its contents if it is ever modified, deleted or (re-)created
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientIdentityFileWatcher extends ModifiableFileWatcher implements ClientIdentityProvider {
    private final AtomicReference<KeyPair> identityHolder = new AtomicReference<>(null);
    private final ClientIdentityLoader loader;
    private final FilePasswordProvider provider;
    private final boolean strict;

    public ClientIdentityFileWatcher(Path path, ClientIdentityLoader loader, FilePasswordProvider provider) {
        this(path, loader, provider, true);
    }

    public ClientIdentityFileWatcher(Path path, ClientIdentityLoader loader, FilePasswordProvider provider, boolean strict) {
        super(path);
        this.loader = ValidateUtils.checkNotNull(loader, "No client identity loader");
        this.provider = ValidateUtils.checkNotNull(provider, "No password provided");
        this.strict = strict;
    }

    public final boolean isStrict() {
        return strict;
    }

    public final ClientIdentityLoader getClientIdentityLoader() {
        return loader;
    }

    public final FilePasswordProvider getFilePasswordProvider() {
        return provider;
    }

    @Override
    public KeyPair getClientIdentity() throws IOException, GeneralSecurityException {
        if (checkReloadRequired()) {
            KeyPair kp = identityHolder.getAndSet(null);     // start fresh
            Path path = getPath();

            if (exists()) {
                KeyPair id = reloadClientIdentity(path);
                if (!KeyUtils.compareKeyPairs(kp, id)) {
                    if (log.isDebugEnabled()) {
                        log.debug("getClientIdentity({}) identity {}", path, (kp == null) ? "loaded" : "re-loaded");
                    }
                }

                updateReloadAttributes();
                identityHolder.set(id);
            }
        }

        return identityHolder.get();
    }

    protected KeyPair reloadClientIdentity(Path path) throws IOException, GeneralSecurityException {
        if (isStrict()) {
            Pair<String, Object> violation = KeyUtils.validateStrictKeyFilePermissions(path, IoUtils.EMPTY_LINK_OPTIONS);
            if (violation != null) {
                if (log.isDebugEnabled()) {
                    log.debug("reloadClientIdentity({}) ignore due to {}", path, violation.getFirst());
                }
                return null;
            }
        }

        String location = path.toString();
        ClientIdentityLoader idLoader = getClientIdentityLoader();
        if (idLoader.isValidLocation(location)) {
            return idLoader.loadClientIdentity(location, getFilePasswordProvider());
        }

        if (log.isDebugEnabled()) {
            log.debug("reloadClientIdentity({}) invalid location", location);
        }
        return null;
    }
}
