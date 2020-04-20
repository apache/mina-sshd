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
import java.util.Collections;
import java.util.Iterator;

import org.apache.sshd.common.session.SessionContext;

/**
 * Aggregates several {@link KeyIdentityProvider}-s into a single logical one that (lazily) exposes the keys from each
 * aggregated provider
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MultiKeyIdentityProvider implements KeyIdentityProvider {
    protected final Iterable<? extends KeyIdentityProvider> providers;

    public MultiKeyIdentityProvider(Iterable<? extends KeyIdentityProvider> providers) {
        this.providers = providers;
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return new Iterable<KeyPair>() {
            @Override
            public Iterator<KeyPair> iterator() {
                return (providers == null) ? Collections.emptyIterator() : new MultiKeyIdentityIterator(session, providers);
            }

            @Override
            public String toString() {
                return Iterable.class.getSimpleName() + "[" + MultiKeyIdentityProvider.class.getSimpleName() + "]";
            }
        };
    }
}
