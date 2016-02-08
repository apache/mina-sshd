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

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyIdentityProvider {
    /**
     * An &quot;empty&quot; implementation of {@link KeyIdentityProvider} that
     * returns an empty group of key pairs
     */
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
        /**
         * Invokes {@link KeyIdentityProvider#loadKeys()} and returns the result - ignores
         * {@code null} providers (i.e., returns an empty iterable instance)
         */
        public static final Transformer<KeyIdentityProvider, Iterable<KeyPair>> LOADER =
            new Transformer<KeyIdentityProvider, Iterable<KeyPair>>() {
                @Override
                public Iterable<KeyPair> transform(KeyIdentityProvider p) {
                    return (p == null) ? Collections.<KeyPair>emptyList() : p.loadKeys();
                }
            };

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        /**
         * Creates a &quot;unified&quot; {@link Iterator} of key pairs out of the registered
         * {@link KeyPair} identities and the extra available ones as a single iterator
         * of key pairs
         *
         * @param session The {@link ClientSession} - ignored if {@code null} (i.e., empty
         * iterator returned)
         * @return The wrapping iterator
         * @see ClientSession#getRegisteredIdentities()
         * @see ClientSession#getKeyPairProvider()
         */
        public static Iterator<KeyPair> iteratorOf(ClientSession session) {
            return (session == null) ? Collections.<KeyPair>emptyIterator() : iteratorOf(session.getRegisteredIdentities(), session.getKeyPairProvider());
        }

        /**
         * Creates a &quot;unified&quot; {@link Iterator} of {@link KeyPair}s out of 2 possible
         * {@link KeyIdentityProvider}
         *
         * @param identities The registered keys identities
         * @param keys Extra available key pairs
         * @return The wrapping iterator
         * @see #resolveKeyIdentityProvider(KeyIdentityProvider, KeyIdentityProvider)
         */
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

        /**
         * <P>Creates a &quot;unified&quot; {@link KeyIdentityProvider} out of 2 possible ones
         * as follows:</P></BR>
         * <UL>
         *      <LI>If both are {@code null} then return {@code null}.</LI>
         *      <LI>If either one is {@code null} then use the non-{@code null} one.</LI>
         *      <LI>If both are the same instance then use it.</U>
         *      <LI>Otherwise, returns a wrapper that groups both providers.</LI>
         * </UL>
         * @param identities The registered key pair identities
         * @param keys The extra available key pairs
         * @return The resolved provider
         * @see #multiProvider(KeyIdentityProvider...)
         */
        public static KeyIdentityProvider resolveKeyIdentityProvider(KeyIdentityProvider identities, KeyIdentityProvider keys) {
            if ((keys == null) || (identities == keys)) {
                return identities;
            } else if (identities == null) {
                return keys;
            } else {
                return multiProvider(identities, keys);
            }
        }

        /**
         * Wraps a group of {@link KeyIdentityProvider} into a single one
         *
         * @param providers The providers - ignored if {@code null}/empty (i.e., returns
         * {@link #EMPTY_KEYS_PROVIDER})
         * @return The wrapping provider
         * @see #multiProvider(Collection)
         */
        public static KeyIdentityProvider multiProvider(KeyIdentityProvider ... providers) {
            return GenericUtils.isEmpty(providers) ? EMPTY_KEYS_PROVIDER : multiProvider(Arrays.asList(providers));
        }

        /**
         * Wraps a group of {@link KeyIdentityProvider} into a single one
         *
         * @param providers The providers - ignored if {@code null}/empty (i.e., returns
         * {@link #EMPTY_KEYS_PROVIDER})
         * @return The wrapping provider
         */
        public static KeyIdentityProvider multiProvider(Collection<? extends KeyIdentityProvider> providers) {
            return GenericUtils.isEmpty(providers) ? EMPTY_KEYS_PROVIDER : wrap(iterableOf(providers));
        }

        /**
         * Wraps a group of {@link KeyIdentityProvider} into an {@link Iterable} of {@link KeyPair}s
         *
         * @param providers The group of providers - ignored if {@code null}/empty (i.e., returns an
         * empty iterable instance)
         * @return The wrapping iterable
         */
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

        /**
         * Wraps a group of {@link KeyPair}s into a {@link KeyIdentityProvider}
         *
         * @param pairs The key pairs - ignored if {@code null}/empty (i.e., returns
         * {@link #EMPTY_KEYS_PROVIDER}).
         * @return The provider wrapper
         */
        public static KeyIdentityProvider wrap(KeyPair ... pairs) {
            return GenericUtils.isEmpty(pairs) ? EMPTY_KEYS_PROVIDER : wrap(Arrays.asList(pairs));
        }

        /**
         * Wraps a group of {@link KeyPair}s into a {@link KeyIdentityProvider}
         *
         * @param pairs The key pairs {@link Iterable} - ignored if {@code null} (i.e., returns
         * {@link #EMPTY_KEYS_PROVIDER}).
         * @return The provider wrapper
         */
        public static KeyIdentityProvider wrap(final Iterable<KeyPair> pairs) {
            return (pairs == null) ? EMPTY_KEYS_PROVIDER : new KeyIdentityProvider() {
                @Override
                public Iterable<KeyPair> loadKeys() {
                    return pairs;
                }
            };
        }
    }
}
