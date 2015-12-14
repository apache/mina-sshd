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

package org.apache.sshd.client.auth.pubkey;

import java.security.KeyPair;
import java.util.Iterator;

import org.apache.sshd.common.kex.KexFactoryManager;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SessionKeyPairIterator implements Iterator<KeyPairIdentity> {

    private final KexFactoryManager manager;
    private final Iterator<KeyPair> keys;

    public SessionKeyPairIterator(KexFactoryManager manager, Iterator<KeyPair> keys) {
        this.manager = ValidateUtils.checkNotNull(manager, "No KEX factory manager");
        this.keys = keys;   // OK if null
    }

    @Override
    public boolean hasNext() {
        return (keys != null) && keys.hasNext();
    }

    @Override
    public KeyPairIdentity next() {
        return new KeyPairIdentity(manager, keys.next());
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("No removal allowed");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + manager + "]";
    }
}
