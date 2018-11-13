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
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface KeyIdentityProvider {
    /**
     * An &quot;empty&quot; implementation of {@link KeyIdentityProvider} that
     * returns an empty group of key pairs
     */
    KeyIdentityProvider EMPTY_KEYS_PROVIDER = new KeyIdentityProvider() {
        @Override
        public Iterable<KeyPair> loadKeys(SessionContext session) {
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
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool or session unknown).
     * @return an {@link Iterable} instance of available keys - ignored if {@code null}
     */
    Iterable<KeyPair> loadKeys(SessionContext session);

    /**
     * Creates a &quot;unified&quot; {@link Iterator} of {@link KeyPair}s out of 2 possible
     * {@link KeyIdentityProvider}
     *
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool or session unknown).
     * @param identities The registered keys identities
     * @param keys Extra available key pairs
     * @return The wrapping iterator
     * @see #resolveKeyIdentityProvider(KeyIdentityProvider, KeyIdentityProvider)
     */
    static Iterator<KeyPair> iteratorOf(
            SessionContext session, KeyIdentityProvider identities, KeyIdentityProvider keys) {
        return iteratorOf(session, resolveKeyIdentityProvider(identities, keys));
    }

    /**
     * Resolves a non-{@code null} iterator of the available keys
     *
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool or session unknown).
     * @param provider The {@link KeyIdentityProvider} - ignored if {@code null}
     * @return A non-{@code null} iterator - which may be empty if no provider or no keys
     */
    static Iterator<KeyPair> iteratorOf(SessionContext session, KeyIdentityProvider provider) {
        return GenericUtils.iteratorOf((provider == null) ? null : provider.loadKeys(session));
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
     *
     * @param identities The registered key pair identities
     * @param keys The extra available key pairs
     * @return The resolved provider
     * @see #multiProvider(KeyIdentityProvider...)
     */
    static KeyIdentityProvider resolveKeyIdentityProvider(
            KeyIdentityProvider identities, KeyIdentityProvider keys) {
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
    static KeyIdentityProvider multiProvider(KeyIdentityProvider... providers) {
        return multiProvider(GenericUtils.asList(providers));
    }

    /**
     * Wraps a group of {@link KeyIdentityProvider} into a single one
     *
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool or session unknown).
     * @param providers The providers - ignored if {@code null}/empty (i.e., returns
     * {@link #EMPTY_KEYS_PROVIDER})
     * @return The wrapping provider
     * @see MultiKeyIdentityProvider
     */
    static KeyIdentityProvider multiProvider(Collection<? extends KeyIdentityProvider> providers) {
        int numProviders = GenericUtils.size(providers);
        if (numProviders <= 0) {
            return EMPTY_KEYS_PROVIDER;
        } else if (numProviders == 1) {
            return GenericUtils.head(providers);
        } else {
            return new MultiKeyIdentityProvider(providers);
        }
    }

    /**
     * Wraps a group of {@link KeyIdentityProvider} into an {@link Iterable} of {@link KeyPair}s
     *
     * @param session The {@link SessionContext} for invoking this load command - may
     * be {@code null} if not invoked within a session context (e.g., offline tool or session unknown).
     * @param providers The group of providers - ignored if {@code null}/empty (i.e., returns an
     * empty iterable instance)
     * @return The wrapping iterable
     */
    static Iterable<KeyPair> iterableOf(SessionContext session, Collection<? extends KeyIdentityProvider> providers) {
        int numProviders = GenericUtils.size(providers);
        if (numProviders <= 0) {
            return Collections.emptyList();
        } else if (numProviders == 1) {
            KeyIdentityProvider p = GenericUtils.head(providers);
            return p.loadKeys(session);
        } else {
            return new Iterable<KeyPair>() {
                @Override
                public Iterator<KeyPair> iterator() {
                    return new MultiKeyIdentityIterator(session, providers);
                }

                @Override
                public String toString() {
                    return Iterable.class.getSimpleName() + "[of(providers)]";
                }
            };
        }
    }

    /**
     * Wraps a group of {@link KeyPair}s into a {@link KeyIdentityProvider}
     *
     * @param pairs The key pairs - ignored if {@code null}/empty (i.e., returns
     * {@link #EMPTY_KEYS_PROVIDER}).
     * @return The provider wrapper
     */
    static KeyIdentityProvider wrapKeyPairs(KeyPair... pairs) {
        return wrapKeyPairs(GenericUtils.asList(pairs));
    }

    /**
     * Wraps a group of {@link KeyPair}s into a {@link KeyIdentityProvider}
     *
     * @param pairs The key pairs {@link Iterable} - ignored if {@code null} (i.e., returns
     * {@link #EMPTY_KEYS_PROVIDER}).
     * @return The provider wrapper
     */
    static KeyIdentityProvider wrapKeyPairs(Iterable<KeyPair> pairs) {
        return (pairs == null) ? EMPTY_KEYS_PROVIDER : session -> pairs;
    }
}
