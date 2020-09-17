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

package org.apache.sshd.common.keyprovider;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.ResourceStreamProvider;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @param  <R> Type of resource from which the {@link KeyPair} is generated
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractResourceKeyPairProvider<R> extends AbstractKeyPairProvider {
    private FilePasswordProvider passwordFinder;
    /*
     * NOTE: the map is case insensitive even for Linux, as it is (very) bad practice to have 2 key files that differ
     * from one another only in their case...
     */
    private final Map<String, Iterable<KeyPair>> cacheMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    protected AbstractResourceKeyPairProvider() {
        super();
    }

    public FilePasswordProvider getPasswordFinder() {
        return passwordFinder;
    }

    public void setPasswordFinder(FilePasswordProvider passwordFinder) {
        this.passwordFinder = passwordFinder;
    }

    /**
     * Checks which of the new resources we already loaded and can keep the associated key pair
     *
     * @param resources The collection of new resources - can be {@code null}/empty in which case the cache is cleared
     */
    protected void resetCacheMap(Collection<?> resources) {
        // if have any cached pairs then see what we can keep from previous load
        Collection<String> toDelete = Collections.emptySet();
        synchronized (cacheMap) {
            if (cacheMap.size() <= 0) {
                return; // already empty - nothing to keep
            }

            if (GenericUtils.isEmpty(resources)) {
                cacheMap.clear();
                return;
            }

            for (Object r : resources) {
                String resourceKey = ValidateUtils.checkNotNullAndNotEmpty(Objects.toString(r, null), "No resource key value");
                if (cacheMap.containsKey(resourceKey)) {
                    continue;
                }

                if (toDelete.isEmpty()) {
                    toDelete = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                }

                if (!toDelete.add(resourceKey)) {
                    continue; // debug breakpoint
                }
            }

            if (GenericUtils.size(toDelete) > 0) {
                toDelete.forEach(cacheMap::remove);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("resetCacheMap(" + resources + ") removed previous cached keys for " + toDelete);
        }
    }

    protected Iterable<KeyPair> loadKeys(SessionContext session, Collection<? extends R> resources) {
        if (GenericUtils.isEmpty(resources)) {
            return Collections.emptyList();
        } else {
            return () -> new KeyPairIterator(session, resources);
        }
    }

    protected IoResource<?> getIoResource(SessionContext session, R resource) {
        return IoResource.forResource(resource);
    }

    protected Iterable<KeyPair> doLoadKeys(SessionContext session, R resource)
            throws IOException, GeneralSecurityException {
        IoResource<?> ioResource
                = ValidateUtils.checkNotNull(getIoResource(session, resource), "No I/O resource available for %s", resource);
        String resourceKey
                = ValidateUtils.checkNotNullAndNotEmpty(ioResource.getName(), "No resource string value for %s", resource);
        Iterable<KeyPair> ids;
        synchronized (cacheMap) {
            // check if lucky enough to have already loaded this file
            ids = cacheMap.get(resourceKey);
        }

        if (ids != null) {
            if (log.isTraceEnabled()) {
                log.trace("doLoadKeys({}) using cached identifiers", resourceKey);
            }
            return ids;
        }

        ids = doLoadKeys(session, ioResource, resource, getPasswordFinder());
        if (ids != null) {
            boolean reusedKey;
            synchronized (cacheMap) {
                // if somebody else beat us to it, use the cached key - just in case file contents changed
                reusedKey = cacheMap.containsKey(resourceKey);
                if (reusedKey) {
                    ids = cacheMap.get(resourceKey);
                } else {
                    cacheMap.put(resourceKey, ids);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("doLoadKeys({}) {}", resourceKey, reusedKey ? "re-loaded" : "loaded");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("doLoadKeys({}) no key loaded", resourceKey);
            }
        }

        return ids;
    }

    protected Iterable<KeyPair> doLoadKeys(
            SessionContext session, NamedResource resourceKey, R resource, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        try (InputStream inputStream = openKeyPairResource(session, resourceKey, resource)) {
            return doLoadKeys(session, resourceKey, inputStream, provider);
        }
    }

    protected InputStream openKeyPairResource(
            SessionContext session, NamedResource resourceKey, R resource)
            throws IOException {
        if (resourceKey instanceof ResourceStreamProvider) {
            return ((ResourceStreamProvider) resourceKey).openInputStream();
        }

        throw new StreamCorruptedException("Cannot open resource data for " + resource);
    }

    protected Iterable<KeyPair> doLoadKeys(
            SessionContext session, NamedResource resourceKey, InputStream inputStream, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        return SecurityUtils.loadKeyPairIdentities(session, resourceKey, inputStream, provider);
    }

    protected class KeyPairIterator implements Iterator<KeyPair> {
        protected final SessionContext session;
        private final Iterator<? extends R> iterator;
        private Iterator<KeyPair> currentIdentities;
        private KeyPair nextKeyPair;
        private boolean nextKeyPairSet;

        protected KeyPairIterator(SessionContext session, Collection<? extends R> resources) {
            this.session = session;
            this.iterator = resources.iterator();
        }

        @Override
        public boolean hasNext() {
            return nextKeyPairSet || setNextObject();
        }

        @Override
        public KeyPair next() {
            if (!nextKeyPairSet) {
                if (!setNextObject()) {
                    throw new NoSuchElementException("Out of files to try");
                }
            }
            nextKeyPairSet = false;
            return nextKeyPair;
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("loadKeys(files) Iterator#remove() N/A");
        }

        @SuppressWarnings("synthetic-access")
        private boolean setNextObject() {
            nextKeyPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
            if (nextKeyPair != null) {
                nextKeyPairSet = true;
                return true;
            }

            while (iterator.hasNext()) {
                R r = iterator.next();
                try {
                    Iterable<KeyPair> ids = doLoadKeys(session, r);
                    currentIdentities = (ids == null) ? null : ids.iterator();
                    nextKeyPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
                } catch (Throwable e) {
                    warn("Failed ({}) to load key resource={}: {}", e.getClass().getSimpleName(), r, e.getMessage(), e);
                    nextKeyPair = null;
                    continue;
                }

                if (nextKeyPair != null) {
                    nextKeyPairSet = true;
                    return true;
                }
            }

            return false;
        }
    }
}
