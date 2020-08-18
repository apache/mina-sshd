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

package org.apache.sshd.ldap;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.naming.NamingException;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * Uses LDAP to retrieve a user's registered public key and compare it with the provided one. The default search pattern
 * attempts to retrieve the user's SSH public key value which is assumed to be in {@code OpenSSH} format. The default
 * assumes that the value resides in the {@link #DEFAULT_PUBKEY_ATTR_NAME} attribute and can be either a single or a
 * multi-valued one
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LdapPublickeyAuthenticator extends LdapAuthenticator implements PublickeyAuthenticator {
    public static final String DEFAULT_SEARCH_FILTER_PATTERN = DEFAULT_USERNAME_ATTR_NAME + "={0}";
    // this seems to be the most commonly used attribute name
    public static final String DEFAULT_PUBKEY_ATTR_NAME = "sshPublicKey";

    private String keyAttributeName = DEFAULT_PUBKEY_ATTR_NAME;

    public LdapPublickeyAuthenticator() {
        setSearchFilterPattern(DEFAULT_SEARCH_FILTER_PATTERN);
        setRetrievedAttributes(DEFAULT_PUBKEY_ATTR_NAME);
        setAccumulateMultiValues(true); // in case multiple keys registered
    }

    /**
     * @return The LDAP attribute name containing the public key - assumed by default to be in {@code OpenSSH} format
     */
    public String getKeyAttributeName() {
        return keyAttributeName;
    }

    public void setKeyAttributeName(String keyAttributeName) {
        this.keyAttributeName = ValidateUtils.checkNotNullAndNotEmpty(keyAttributeName, "No attribute name");
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        try {
            Map<String, ?> attrs = resolveAttributes(username, null, session);
            return authenticate(username, key, session, attrs);
        } catch (NamingException | GeneralSecurityException | IOException | RuntimeException e) {
            warn("authenticate({}@{}) failed ({}) to query: {}",
                    username, session, e.getClass().getSimpleName(), e.getMessage(), e);
            return false;
        }
    }

    /**
     * @param  username                 The SSH username attempting to authenticate
     * @param  expected                 The provided {@link PublicKey}
     * @param  session                  The {@link ServerSession}
     * @param  attrs                    The extracted LDAP attributes {@link Map}
     * @return                          {@code true} whether to accept the presented public key
     * @throws GeneralSecurityException If failed to recover the public key(s)
     * @throws IOException              If failed to parse the public key(s) data
     * @see                             #recoverPublicKeys(String, PublicKey, ServerSession, Map, Object)
     * @see                             #authenticate(String, PublicKey, ServerSession, Map, Collection)
     */
    protected boolean authenticate(String username, PublicKey expected, ServerSession session, Map<String, ?> attrs)
            throws GeneralSecurityException, IOException {
        String attrName = getKeyAttributeName();
        Collection<PublicKey> keys = recoverPublicKeys(username, expected, session, attrs, attrs.get(attrName));
        return authenticate(username, expected, session, attrs, keys);
    }

    /**
     * @param  username The SSH username attempting to authenticate
     * @param  expected The provided {@link PublicKey}
     * @param  session  The {@link ServerSession}
     * @param  attrs    The extracted LDAP attributes {@link Map}
     * @param  keys     The {@link Collection} of recovered {@link PublicKey}s - may be {@code null}/empty
     * @return          {@code true} whether to accept the presented public key
     */
    protected boolean authenticate(
            String username, PublicKey expected, ServerSession session, Map<String, ?> attrs,
            Collection<? extends PublicKey> keys) {
        boolean debugEnabled = log.isDebugEnabled();
        if (GenericUtils.isEmpty(keys)) {
            if (debugEnabled) {
                log.debug("authenticate({}@{}) no registered keys", username, session);
            }
            return false;
        }

        if (debugEnabled) {
            log.debug("authenticate({}@{}) check {} registered keys", username, session, keys.size());
        }

        boolean traceEnabled = log.isTraceEnabled();
        for (PublicKey actual : keys) {
            if (traceEnabled) {
                log.trace("authenticate({}@{}) expected={}-{}, actual={}-{}",
                        username, session,
                        KeyUtils.getKeyType(expected), KeyUtils.getFingerPrint(expected),
                        KeyUtils.getKeyType(actual), KeyUtils.getFingerPrint(actual));
            }

            if (KeyUtils.compareKeys(expected, actual)) {
                return true;
            }
        }

        if (debugEnabled) {
            log.debug("authenticate({}@{}) no matching keys", username, session);
        }

        return false;
    }

    /**
     * @param  username                 The SSH username attempting to authenticate
     * @param  expected                 The provided {@link PublicKey}
     * @param  session                  The {@link ServerSession}
     * @param  attrs                    The extracted LDAP attributes {@link Map}
     * @param  keyData                  The value of the {@link #getKeyAttributeName()} attribute - may be {@code null},
     *                                  a single object or a collection of such (if multi-valued attribute)
     * @return                          A {@link List} of the recovered {@link PublicKey}s - may be {@code null}/empty
     * @throws GeneralSecurityException If failed to recover the public key(s)
     * @throws IOException              If failed to parse the public key(s) data
     * @see                             #parsePublicKeyValue(String, PublicKey, ServerSession, Map, Object)
     */
    protected List<PublicKey> recoverPublicKeys(
            String username, PublicKey expected, ServerSession session, Map<String, ?> attrs, Object keyData)
            throws GeneralSecurityException, IOException {
        // handle case of multi-valued attribute
        if (keyData instanceof Collection<?>) {
            Collection<?> values = (Collection<?>) keyData;
            List<PublicKey> keys = new ArrayList<>(values.size());
            for (Object v : values) {
                PublicKey k = parsePublicKeyValue(username, expected, session, attrs, v);
                if (k == null) {
                    continue; // debug breakpoint
                }

                keys.add(k);
            }

            return keys;
        }

        PublicKey k = parsePublicKeyValue(username, expected, session, attrs, keyData);
        return (k == null) ? Collections.emptyList() : Collections.singletonList(k);
    }

    /**
     * @param  username                 The SSH username attempting to authenticate
     * @param  expected                 The provided {@link PublicKey}
     * @param  session                  The {@link ServerSession}
     * @param  attrs                    The extracted LDAP attributes {@link Map}
     * @param  keyData                  One of the values (if multi-valued attribute) - may be {@code null}
     * @return                          The extracted {@link PublicKey} or {@code null} if none available
     * @throws GeneralSecurityException If failed to recover the public key
     * @throws IOException              If failed to parse the public key data
     */
    protected PublicKey parsePublicKeyValue(
            String username, PublicKey expected, ServerSession session, Map<String, ?> attrs, Object keyData)
            throws GeneralSecurityException, IOException {
        if (keyData == null) {
            return null;
        }

        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(Objects.toString(keyData, null));
        PublicKey key
                = Objects.requireNonNull(entry, "No key extracted").resolvePublicKey(session, PublicKeyEntryResolver.FAILING);
        if (log.isTraceEnabled()) {
            log.trace("parsePublicKeyValue({}@{}) {}-{}",
                    username, session, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }
        return key;
    }
}
