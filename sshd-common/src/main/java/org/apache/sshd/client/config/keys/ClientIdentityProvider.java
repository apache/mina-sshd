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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;

import org.apache.sshd.common.session.SessionContext;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ClientIdentityProvider {
    /**
     * Provides a {@link KeyPair} representing the client identity
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool).
     * @return                          The client identities - may be {@code null}/empty if no currently available
     *                                  identity from this provider. <B>Note:</B> the provider may return a
     *                                  <U>different</U> value every time this method is called - e.g., if it is
     *                                  (re-)loading contents from a file.
     * @throws IOException              If failed to load the identity
     * @throws GeneralSecurityException If failed to parse the identity
     */
    Iterable<KeyPair> getClientIdentities(SessionContext session)
            throws IOException, GeneralSecurityException;

    /**
     * Wraps a {@link KeyPair} into a {@link ClientIdentityProvider} that simply returns this value as it
     * {@link #getClientIdentities(SessionContext)}.
     *
     * @param  kp The {@link KeyPair} instance (including {@code null})
     * @return    The wrapping provider
     */
    static ClientIdentityProvider of(KeyPair kp) {
        return session -> Collections.singletonList(kp);
    }

    /**
     * Wraps several {@link ClientIdentityProvider} into a {@link KeyPair} {@link Iterable} that invokes each provider
     * &quot;lazily&quot; - i.e., only when {@link Iterator#hasNext()} is invoked. This prevents password protected
     * private keys to be decrypted until they are actually needed.
     *
     * @param  providers   The providers - ignored if {@code null}
     * @param  kpExtractor The (never {@code null}) extractor of the {@link KeyPair} from the
     *                     {@link ClientIdentityProvider} argument. If returned pair is {@code null} then next provider
     *                     is queried.
     * @param  filter      Any further filter to apply on (non-{@code null}) key pairs before returning it as the
     *                     {@link Iterator#next()} result.
     * @return             The wrapper {@link Iterable}. <b>Note:</b> a <u>new</u> {@link Iterator} instance is returned
     *                     on each {@link Iterable#iterator()} call - i.e., any encrypted private key may require the
     *                     user to re-enter the relevant password. If the default {@code ClientIdentityFileWatcher} is
     *                     used, this is not a problem since it caches the decoded result (unless the file has changed).
     */
    static Iterable<KeyPair> lazyKeysLoader(
            Iterable<? extends ClientIdentityProvider> providers,
            Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> kpExtractor,
            Predicate<? super KeyPair> filter) {
        Objects.requireNonNull(kpExtractor, "No key pair extractor provided");
        if (providers == null) {
            return Collections.emptyList();
        }

        return new Iterable<KeyPair>() {
            @Override
            public Iterator<KeyPair> iterator() {
                return lazyKeysIterator(providers.iterator(), kpExtractor, filter);
            }

            @Override
            public String toString() {
                return ClientIdentityProvider.class.getSimpleName() + "[lazy-iterable]";
            }
        };
    }

    /**
     * Wraps several {@link ClientIdentityProvider} into a {@link KeyPair} {@link Iterator} that invokes each provider
     * &quot;lazily&quot; - i.e., only when {@link Iterator#hasNext()} is invoked. This prevents password protected
     * private keys to be decrypted until they are actually needed.
     *
     * @param  providers   The providers - ignored if {@code null}
     * @param  kpExtractor The (never {@code null}) extractor of the {@link KeyPair} from the
     *                     {@link ClientIdentityProvider} argument. If returned pair is {@code null} then next provider
     *                     is queried.
     * @param  filter      Any further filter to apply on (non-{@code null}) key pairs before returning it as the
     *                     {@link Iterator#next()} result.
     * @return             The wrapper {@link Iterator}
     */
    static Iterator<KeyPair> lazyKeysIterator(
            Iterator<? extends ClientIdentityProvider> providers,
            Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> kpExtractor,
            Predicate<? super KeyPair> filter) {
        Objects.requireNonNull(kpExtractor, "No key pair extractor provided");
        return (providers == null)
                ? Collections.emptyIterator()
                : new LazyClientIdentityIterator(providers, kpExtractor, filter);
    }
}
