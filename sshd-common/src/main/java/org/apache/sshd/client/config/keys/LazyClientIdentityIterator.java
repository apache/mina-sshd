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

import java.security.KeyPair;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;

import org.apache.sshd.common.keyprovider.KeyIdentityProvider;

/**
 * Wraps several {@link ClientIdentityProvider} into a {@link KeyPair} {@link Iterator} that invokes each provider
 * &quot;lazily&quot; - i.e., only when {@link Iterator#hasNext()} is invoked. This prevents password protected private
 * keys to be decrypted until they are actually needed.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LazyClientIdentityIterator implements Iterator<KeyPair> {
    protected boolean finished;
    protected Iterator<? extends KeyPair> currentIdentities;
    protected KeyPair currentPair;

    private final Iterator<? extends ClientIdentityProvider> providers;
    private final Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> kpExtractor;
    private final Predicate<? super KeyPair> filter;

    /**
     * @param providers   The providers - ignored if {@code null}
     * @param kpExtractor The (never {@code null}) extractor of the {@link KeyPair} from the
     *                    {@link ClientIdentityProvider} argument. If returned pair is {@code null} then next provider
     *                    is queried.
     * @param filter      Any further filter to apply on (non-{@code null}) key pairs before returning it as the
     *                    {@link Iterator#next()} result.
     */
    public LazyClientIdentityIterator(
                                      Iterator<? extends ClientIdentityProvider> providers,
                                      Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> kpExtractor,
                                      Predicate<? super KeyPair> filter) {
        this.providers = providers;
        this.kpExtractor = Objects.requireNonNull(kpExtractor, "No key pair extractor provided");
        this.filter = filter;
    }

    public Iterator<? extends ClientIdentityProvider> getProviders() {
        return providers;
    }

    public Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> getIdentitiesExtractor() {
        return kpExtractor;
    }

    public Predicate<? super KeyPair> getFilter() {
        return filter;
    }

    @Override
    public boolean hasNext() {
        if (finished) {
            return false;
        }

        Iterator<? extends ClientIdentityProvider> provs = getProviders();
        if (provs == null) {
            finished = true;
            return false;
        }

        currentPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
        if (currentPair != null) {
            return true;
        }

        Function<? super ClientIdentityProvider, ? extends Iterable<? extends KeyPair>> x = getIdentitiesExtractor();
        Predicate<? super KeyPair> f = getFilter();
        while (provs.hasNext()) {
            ClientIdentityProvider p = provs.next();
            if (p == null) {
                continue;
            }

            Iterable<? extends KeyPair> ids = x.apply(p);
            currentIdentities = (ids == null) ? null : ids.iterator();
            currentPair = KeyIdentityProvider.exhaustCurrentIdentities(currentIdentities);
            if (currentPair == null) {
                continue;
            }

            if ((f != null) && (!f.test(currentPair))) {
                continue;
            }

            return true;
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
        return ClientIdentityProvider.class.getSimpleName() + "[lazy-iterator]";
    }
}
