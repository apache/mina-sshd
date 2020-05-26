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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Checks against a {@link Collection} of {@link AuthorizedKeyEntry}s
 *
 * Records the matched entry under a session attribute.
 */
public class AuthorizedKeyEntriesPublickeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator {
    public static final AttributeRepository.AttributeKey<AuthorizedKeyEntry> AUTHORIZED_KEY
            = new AttributeRepository.AttributeKey<>();

    private Map<AuthorizedKeyEntry, PublicKey> resolvedKeys;
    private Object id;

    public AuthorizedKeyEntriesPublickeyAuthenticator(
                                                      Object id, ServerSession session,
                                                      Collection<? extends AuthorizedKeyEntry> entries,
                                                      PublicKeyEntryResolver fallbackResolver)
                                                                                               throws IOException,
                                                                                               GeneralSecurityException {
        this.id = id;
        int numEntries = GenericUtils.size(entries);
        if (numEntries <= 0) {
            resolvedKeys = Collections.emptyMap();
        } else {
            resolvedKeys = new HashMap<>(numEntries);
            for (AuthorizedKeyEntry e : entries) {
                Map<String, String> headers = e.getLoginOptions();
                PublicKey k = e.resolvePublicKey(session, headers, fallbackResolver);
                if (k != null) {
                    resolvedKeys.put(e, k);
                }
            }
        }
    }

    /**
     * @return Some kind of mnemonic identifier for the authenticator - used also in {@code toString()}
     */
    public Object getId() {
        return id;
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        if (GenericUtils.isEmpty(resolvedKeys)) {
            if (log.isDebugEnabled()) {
                log.debug("authenticate(" + username + ")[" + session + "] no entries");
            }

            return false;
        }

        for (Map.Entry<AuthorizedKeyEntry, PublicKey> e : resolvedKeys.entrySet()) {
            if (KeyUtils.compareKeys(key, e.getValue())) {
                if (log.isDebugEnabled()) {
                    log.debug("authenticate(" + username + ")[" + session + "] match found");
                }
                if (session != null) {
                    session.setAttribute(AUTHORIZED_KEY, e.getKey());
                }
                return true;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("authenticate(" + username + ")[" + session + "] match not found");
        }
        return false;
    }

    @Override
    public String toString() {
        return Objects.toString(getId());
    }
}
