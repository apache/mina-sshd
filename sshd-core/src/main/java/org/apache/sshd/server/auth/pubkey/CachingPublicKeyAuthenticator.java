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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Caches the result per session - compensates for {@code OpenSSH} behavior where it sends 2 requests with the same key
 * (see {@code SSHD-300}).
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CachingPublicKeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator {
    /**
     * The {@link org.apache.sshd.common.AttributeRepository.AttributeKey AttributeKey} used to store the cached
     * authentication results on the session instance
     */
    public static final AttributeRepository.AttributeKey<Map<PublicKey, Boolean>> CACHE_ATTRIBUTE
            = new AttributeRepository.AttributeKey<>();

    protected final PublickeyAuthenticator authenticator;

    public CachingPublicKeyAuthenticator(PublickeyAuthenticator authenticator) {
        this.authenticator = Objects.requireNonNull(authenticator, "No delegate authenticator");
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        Map<PublicKey, Boolean> map = resolveCachedResults(username, key, session);
        Boolean result = map.get(key);
        if (result == null) {
            try {
                result = authenticator.authenticate(username, key, session);
            } catch (Error e) {
                warn("authenticate({}@{}) failed ({}) to consult delegate for {} key={}: {}",
                        username, session, e.getClass().getSimpleName(),
                        KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key), e.getMessage(), e);
                throw new RuntimeSshException(e);
            }
            if (log.isDebugEnabled()) {
                log.debug("authenticate({}@{}) cache result={} for {} key={}",
                        username, session, result, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
            map.put(key, result);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("authenticate({}@{}) use cached result={} for {} key={}",
                        username, session, result, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
        }

        return result;
    }

    protected Map<PublicKey, Boolean> resolveCachedResults(String username, PublicKey key, ServerSession session) {
        return session.computeAttributeIfAbsent(CACHE_ATTRIBUTE, attr -> new ConcurrentHashMap<>());
    }
}
