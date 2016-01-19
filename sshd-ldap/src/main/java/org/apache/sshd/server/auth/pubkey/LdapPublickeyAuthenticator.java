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
import java.util.Map;
import java.util.Objects;

import javax.naming.NamingException;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.net.LdapNetworkConnector;
import org.apache.sshd.server.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LdapPublickeyAuthenticator extends LdapNetworkConnector implements PublickeyAuthenticator {
    public static final String DEFAULT_USERNAME_ATTR_NAME = "uid";
    public static final String DEFAULT_AUTHENTICATION_MODE = "none";
    public static final String DEFAULT_SEARCH_FILTER_PATTERN = DEFAULT_USERNAME_ATTR_NAME + "={0}";
    public static final String DEFAULT_PUBKEY_ATTR_NAME = "sshPublicKey";

    private String keyAttributeName = DEFAULT_PUBKEY_ATTR_NAME;

    public LdapPublickeyAuthenticator() {
        setAuthenticationMode(DEFAULT_AUTHENTICATION_MODE);
        setSearchFilterPattern(DEFAULT_SEARCH_FILTER_PATTERN);
        setRetrievedAttributes(DEFAULT_PUBKEY_ATTR_NAME);
    }

    /**
     * @return The LDAP attribute name containing the public key in {@code OpenSSH} format
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
            log.warn("authenticate({}@{}) failed ({}) to query: {}",
                      username, session, e.getClass().getSimpleName(), e.getMessage());

            if (log.isDebugEnabled()) {
                log.debug("authenticate(" + username + "@" + session + ") query failure details", e);
            }

            return false;
        }
    }

    protected boolean authenticate(String username, PublicKey expected, ServerSession session, Map<String, ?> attrs)
            throws GeneralSecurityException, IOException {
        String attrName = getKeyAttributeName();
        Object keyData = ValidateUtils.checkNotNull(attrs.get(attrName), "No data for attribute=%s", attrName);
        PublicKey actual = recoverPublicKey(username, expected, session, keyData);
        return KeyUtils.compareKeys(expected, actual);
    }

    protected PublicKey recoverPublicKey(String username, PublicKey expected, ServerSession session, Object keyData)
            throws GeneralSecurityException, IOException {
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(Objects.toString(keyData, null));
        return ValidateUtils.checkNotNull(entry, "No key extracted").resolvePublicKey(PublicKeyEntryResolver.FAILING);
    }
}
