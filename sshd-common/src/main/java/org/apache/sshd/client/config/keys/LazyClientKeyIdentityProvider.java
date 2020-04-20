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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderHolder;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LazyClientKeyIdentityProvider
        implements KeyIdentityProvider, ClientIdentityLoaderHolder, FilePasswordProviderHolder {
    private final ClientIdentityLoader clientIdentityLoader;
    private final Collection<? extends NamedResource> locations;
    private final FilePasswordProvider passwordProvider;
    private final boolean ignoreNonExisting;

    public LazyClientKeyIdentityProvider(
                                         ClientIdentityLoader loader, Collection<? extends NamedResource> locations,
                                         FilePasswordProvider passwordProvider, boolean ignoreNonExisting) {
        this.clientIdentityLoader = Objects.requireNonNull(loader, "No client identity loader provided");
        this.locations = locations;
        this.passwordProvider = passwordProvider;
        this.ignoreNonExisting = ignoreNonExisting;
    }

    @Override
    public ClientIdentityLoader getClientIdentityLoader() {
        return clientIdentityLoader;
    }

    public Collection<? extends NamedResource> getLocations() {
        return locations;
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return passwordProvider;
    }

    public boolean isIgnoreNonExisting() {
        return ignoreNonExisting;
    }

    @Override
    @SuppressWarnings("checkstyle:anoninnerlength")
    public Iterable<KeyPair> loadKeys(SessionContext session)
            throws IOException, GeneralSecurityException {
        Collection<? extends NamedResource> locs = getLocations();
        if (GenericUtils.isEmpty(locs)) {
            return Collections.emptyList();
        }

        return () -> new Iterator<KeyPair>() {
            private final Iterator<? extends NamedResource> iter = locs.iterator();
            private Iterator<KeyPair> currentIdentities;
            private KeyPair currentPair;
            private boolean finished;

            @Override
            public boolean hasNext() {
                if (finished) {
                    return false;
                }

                currentPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
                if (currentPair != null) {
                    return true;
                }

                while (iter.hasNext()) {
                    NamedResource l = iter.next();
                    Iterable<KeyPair> ids;
                    try {
                        ids = loadClientIdentities(session, l);
                    } catch (IOException | GeneralSecurityException e) {
                        throw new RuntimeException(
                                "Failed (" + e.getClass().getSimpleName() + ")"
                                                   + " to load key from " + l.getName() + ": " + e.getMessage(),
                                e);
                    }

                    currentIdentities = (ids == null) ? null : ids.iterator();
                    currentPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
                    if (currentPair != null) {
                        return true;
                    }
                }

                finished = true;
                return false;
            }

            @Override
            public KeyPair next() {
                if (finished) {
                    throw new NoSuchElementException("All identities have been exhausted");
                }
                if (currentPair == null) {
                    throw new IllegalStateException("'next()' called without asking 'hasNext()'");
                }

                KeyPair kp = currentPair;
                currentPair = null;
                return kp;
            }

            @Override
            public String toString() {
                return Iterator.class.getSimpleName() + "[" + LazyClientKeyIdentityProvider.class.getSimpleName() + "]";
            }
        };
    }

    protected Iterable<KeyPair> loadClientIdentities(SessionContext session, NamedResource location)
            throws IOException, GeneralSecurityException {
        ClientIdentityLoader loader = getClientIdentityLoader();
        boolean ignoreInvalid = isIgnoreNonExisting();
        try {
            if (!loader.isValidLocation(location)) {
                if (ignoreInvalid) {
                    return null;
                }

                throw new FileNotFoundException("Invalid identity location: " + location.getName());
            }
        } catch (IOException e) {
            if (ignoreInvalid) {
                return null;
            }

            throw e;
        }

        return loader.loadClientIdentities(session, location, getFilePasswordProvider());
    }
}
