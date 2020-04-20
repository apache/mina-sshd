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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionContextHolder;

/**
 * Iterates over several {@link KeyIdentityProvider}-s exhausting their keys one by one (lazily).
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MultiKeyIdentityIterator implements Iterator<KeyPair>, SessionContextHolder {
    protected Iterator<KeyPair> currentProvider;
    protected boolean finished;
    private final SessionContext sessionContext;
    private final Iterator<? extends KeyIdentityProvider> providers;

    public MultiKeyIdentityIterator(SessionContext session, Iterable<? extends KeyIdentityProvider> providers) {
        this.providers = (providers == null) ? null : providers.iterator();
        this.sessionContext = session;
    }

    public Iterator<? extends KeyIdentityProvider> getProviders() {
        return providers;
    }

    @Override
    public SessionContext getSessionContext() {
        return sessionContext;
    }

    @Override
    public boolean hasNext() {
        if (finished) {
            return false;
        }

        Iterator<? extends KeyIdentityProvider> provs = getProviders();
        if (provs == null) {
            finished = true;
            return false;
        }

        if ((currentProvider != null) && currentProvider.hasNext()) {
            return true;
        }

        SessionContext session = getSessionContext();
        while (provs.hasNext()) {
            KeyIdentityProvider p = provs.next();
            Iterable<KeyPair> keys;
            try {
                keys = (p == null) ? null : p.loadKeys(session);
            } catch (IOException | GeneralSecurityException e) {
                throw new RuntimeException(
                        "Unexpected " + e.getClass().getSimpleName() + ")"
                                           + " keys loading exception: " + e.getMessage(),
                        e);
            }
            currentProvider = (keys == null) ? null : keys.iterator();

            if ((currentProvider != null) && currentProvider.hasNext()) {
                return true;
            }
        }

        // exhausted all providers
        finished = false;
        return false;
    }

    @Override
    public KeyPair next() {
        if (finished) {
            throw new NoSuchElementException("All identities have been exhausted");
        }

        if (currentProvider == null) {
            throw new IllegalStateException("'next()' called without asking 'hasNext()'");
        }

        return currentProvider.next();
    }
}
