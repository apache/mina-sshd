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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @param <R> Type of resource from which the {@link KeyPair} is generated
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractResourceKeyPairProvider<R> extends AbstractKeyPairProvider {

    private FilePasswordProvider passwordFinder;
    /*
     * NOTE: the map is case insensitive even for Linux, as it is (very) bad
     * practice to have 2 key files that differ from one another only in their
     * case...
     */
    private final Map<String, KeyPair> cacheMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

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
     * Checks which of the new resources we already loaded and can keep the
     * associated key pair
     *
     * @param resources The collection of new resources - can be {@code null}/empty
     * in which case the cache is cleared
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
                    continue;   // debug breakpoint
                }
            }

            if (GenericUtils.size(toDelete) > 0) {
                for (String f : toDelete) {
                    cacheMap.remove(f);
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("resetCacheMap(" + resources + ") removed previous cached keys for " + toDelete);
        }
    }

    protected Iterable<KeyPair> loadKeys(final Collection<? extends R> resources) {
        if (GenericUtils.isEmpty(resources)) {
            return Collections.emptyList();
        } else {
            return new Iterable<KeyPair>() {
                @Override
                public Iterator<KeyPair> iterator() {
                    return new KeyPairIterator(resources);
                }
            };
        }
    }

    protected KeyPair doLoadKey(R resource) throws IOException, GeneralSecurityException {
        String resourceKey = ValidateUtils.checkNotNullAndNotEmpty(Objects.toString(resource, null), "No resource string value");
        KeyPair kp;
        synchronized (cacheMap) {
            // check if lucky enough to have already loaded this file
            kp = cacheMap.get(resourceKey);
        }

        if (kp != null) {
            if (log.isTraceEnabled()) {
                PublicKey key = kp.getPublic();
                log.trace("doLoadKey({}) use cached key {}-{}",
                          resourceKey, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
            return kp;
        }

        kp = doLoadKey(resourceKey, resource, getPasswordFinder());
        if (kp != null) {
            boolean reusedKey;
            synchronized (cacheMap) {
                // if somebody else beat us to it, use the cached key - just in case file contents changed
                reusedKey = cacheMap.containsKey(resourceKey);
                if (reusedKey) {
                    kp = cacheMap.get(resourceKey);
                } else {
                    cacheMap.put(resourceKey, kp);
                }
            }

            if (log.isDebugEnabled()) {
                PublicKey key = kp.getPublic();
                log.debug("doLoadKey({}) {} {}-{}",
                          resourceKey, reusedKey ? "re-loaded" : "loaded",
                          KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("doLoadKey({}) no key loaded", resourceKey);
            }
        }

        return kp;
    }

    protected KeyPair doLoadKey(String resourceKey, R resource, FilePasswordProvider provider) throws IOException, GeneralSecurityException {
        try (InputStream inputStream = openKeyPairResource(resourceKey, resource)) {
            return doLoadKey(resourceKey, inputStream, provider);
        }
    }

    protected abstract InputStream openKeyPairResource(String resourceKey, R resource) throws IOException;

    protected abstract KeyPair doLoadKey(String resourceKey, InputStream inputStream, FilePasswordProvider provider) throws IOException, GeneralSecurityException;

    protected class KeyPairIterator implements Iterator<KeyPair> {
        private final Iterator<? extends R> iterator;
        private KeyPair nextKeyPair;
        private boolean nextKeyPairSet;

        protected KeyPairIterator(Collection<? extends R> resources) {
            iterator = resources.iterator();
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
            while (iterator.hasNext()) {
                R r = iterator.next();
                try {
                    nextKeyPair = doLoadKey(r);
                } catch (Throwable e) {
                    log.warn("Failed (" + e.getClass().getSimpleName() + ")"
                           + " to load key resource=" + r + ": " + e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("Key resource=" + r + " load failure details", e);
                    }
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
