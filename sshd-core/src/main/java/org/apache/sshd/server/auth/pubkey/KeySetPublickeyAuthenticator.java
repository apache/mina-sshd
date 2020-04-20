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
package org.apache.sshd.server.auth.pubkey;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Checks against a {@link Collection} of {@link PublicKey}s
 */
public class KeySetPublickeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator {
    private final Collection<? extends PublicKey> keySet;
    private final Object id;

    public KeySetPublickeyAuthenticator(Object id, Collection<? extends PublicKey> keySet) {
        this.id = id;
        this.keySet = (keySet == null) ? Collections.emptyList() : keySet;
    }

    /**
     * @return Some kind of mnemonic identifier for the authenticator - used also in {@code toString()}
     */
    public Object getId() {
        return id;
    }

    public final Collection<? extends PublicKey> getKeySet() {
        return keySet;
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        return authenticate(username, key, session, getKeySet());
    }

    public boolean authenticate(String username, PublicKey key, ServerSession session, Collection<? extends PublicKey> keys) {
        if (GenericUtils.isEmpty(keys)) {
            if (log.isDebugEnabled()) {
                log.debug("authenticate(" + username + ")[" + session + "] no keys");
            }

            return false;
        }

        PublicKey matchKey = KeyUtils.findMatchingKey(key, keys);
        boolean matchFound = matchKey != null;
        if (log.isDebugEnabled()) {
            log.debug("authenticate(" + username + ")[" + session + "] match found=" + matchFound);
        }
        return matchFound;
    }

    @Override
    public String toString() {
        return Objects.toString(getId());
    }
}
