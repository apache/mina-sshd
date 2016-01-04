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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Supplier;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyIdentityProvider {
    KeyIdentityProvider EMPTY_KEYS_PROVIDER = new KeyIdentityProvider() {
        @Override
        public Iterable<KeyPair> loadKeys() {
            return Collections.emptyList();
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * Load available keys.
     *
     * @return an {@link Iterable} instance of available keys - ignored if {@code null}
     */
    Iterable<KeyPair> loadKeys();

    /**
     * A helper class for key identity provider related operations
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON
        public static final Transformer<KeyIdentityProvider, Iterable<KeyPair>> LOADER =
            new Transformer<KeyIdentityProvider, Iterable<KeyPair>>() {
                @Override
                public Iterable<KeyPair> transform(KeyIdentityProvider p) {
                    return (p == null) ? null : p.loadKeys();
                }
            };

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static Iterator<KeyPair> iteratorOf(ClientSession session) {
            ValidateUtils.checkNotNull(session, "No session");
            return iteratorOf(session.getRegisteredIdentities(), session.getKeyPairProvider());
        }

        public static Iterator<KeyPair> iteratorOf(KeyIdentityProvider identities, KeyIdentityProvider keys) {
            return iteratorOf(resolveKeyIdentityProvider(identities, keys));
        }

        /**
         * Resolves a non-{@code null} iterator of the available keys
         *
         * @param provider The {@link KeyIdentityProvider} - ignored if {@code null}
         * @return A non-{@code null} iterator - which may be empty if no provider or no keys
         */
        public static Iterator<KeyPair> iteratorOf(KeyIdentityProvider provider) {
            return GenericUtils.iteratorOf((provider == null) ? null : provider.loadKeys());
        }

        public static KeyIdentityProvider resolveKeyIdentityProvider(KeyIdentityProvider identities, KeyIdentityProvider keys) {
            if ((keys == null) || (identities == keys)) {
                return identities;
            } else if (identities == null) {
                return keys;
            } else {
                return multiProvider(identities, keys);
            }
        }

        public static KeyIdentityProvider multiProvider(KeyIdentityProvider ... providers) {
            return multiProvider(GenericUtils.isEmpty(providers) ? Collections.<KeyIdentityProvider>emptyList() : Arrays.asList(providers));
        }

        public static KeyIdentityProvider multiProvider(Collection<? extends KeyIdentityProvider> providers) {
            return wrap(iterableOf(providers));
        }

        public static Iterable<KeyPair> iterableOf(Collection<? extends KeyIdentityProvider> providers) {
            if (GenericUtils.isEmpty(providers)) {
                return Collections.emptyList();
            }

            Collection<Supplier<Iterable<KeyPair>>> suppliers = new ArrayList<Supplier<Iterable<KeyPair>>>(providers.size());
            for (final KeyIdentityProvider p : providers) {
                if (p == null) {
                    continue;
                }

                suppliers.add(new Supplier<Iterable<KeyPair>>() {
                    @Override
                    public Iterable<KeyPair> get() {
                        return p.loadKeys();
                    }
                });
            }

            if (GenericUtils.isEmpty(suppliers)) {
                return Collections.emptyList();
            }

            return GenericUtils.multiIterableSuppliers(suppliers);
        }

        public static KeyIdentityProvider wrap(KeyPair ... pairs) {
            return wrap(GenericUtils.isEmpty(pairs) ? Collections.<KeyPair>emptyList() : Arrays.asList(pairs));
        }

        public static KeyIdentityProvider wrap(final Iterable<KeyPair> keys) {
            return new KeyIdentityProvider() {
                @Override
                public Iterable<KeyPair> loadKeys() {
                    return keys;
                }
            };
        }
    }
}
