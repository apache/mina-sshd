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
import java.util.stream.Stream;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
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

    public AuthorizedKeyEntriesPublickeyAuthenticator(Object id, ServerSession session,
                                                      Collection<? extends AuthorizedKeyEntry> entries,
                                                      PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
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
        if (MapEntryUtils.isEmpty(resolvedKeys)) {
            if (log.isDebugEnabled()) {
                log.debug("authenticate({})[{}] no entries", username, session);
            }

            return false;
        }

        PublicKey keyToCheck = key;
        boolean isCert = false;
        if (key instanceof OpenSshCertificate) {
            keyToCheck = ((OpenSshCertificate) key).getCaPubKey();
            isCert = true;
        }
        for (Map.Entry<AuthorizedKeyEntry, PublicKey> e : resolvedKeys.entrySet()) {
            AuthorizedKeyEntry entry = e.getKey();
            if (isCert == entry.getLoginOptions().containsKey("cert-authority")
                    && KeyUtils.compareKeys(keyToCheck, e.getValue())) {
                if (log.isDebugEnabled()) {
                    log.debug("authenticate({})[{}] match found", username, session);
                }
                // TODO: the entry might have an "expiry-time" option.
                // See https://man.openbsd.org/sshd.8#expiry-time=_timespec_
                // (Certificate expiration as stored in the certificate itself has been checked already.)
                // TODO: the entry might have a "from" option limiting possible source addresses by IP, hostnames,
                // patterns, or CIDRs.
                // See https://man.openbsd.org/sshd.8#from=_pattern-list_
                if (isCert && !matchesPrincipals(entry, username, (OpenSshCertificate) key, session)) {
                    continue;
                }
                if (session != null) {
                    session.setAttribute(AUTHORIZED_KEY, entry);
                }
                return true;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("authenticate({})[{}] no match found", username, session);
        }
        return false;
    }

    protected boolean matchesPrincipals(
            AuthorizedKeyEntry entry, String username, OpenSshCertificate cert,
            ServerSession session) {
        Collection<String> certPrincipals = cert.getPrincipals();
        if (!GenericUtils.isEmpty(certPrincipals)) {
            // "As a special case, a zero-length "valid principals" field means the certificate is valid for
            // any principal of the specified type."
            // See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
            //
            // This is true for user certificates unless they are checked via a TrustedUserCAKeys file, but
            // that is not what we implement here.
            // See https://man.openbsd.org/sshd_config#TrustedUserCAKeys
            String allowedPrincipals = entry.getLoginOptions().get("principals");
            if (!GenericUtils.isEmpty(allowedPrincipals)) {
                if (Stream.of(allowedPrincipals.split(",")) //
                        .map(String::trim) //
                        .filter(s -> !GenericUtils.isEmpty(s)) //
                        .noneMatch(certPrincipals::contains)) {
                    log.debug("authenticate({})[{}] certificate match ignored, none of the allowed principals matched: {}",
                            username, session, allowedPrincipals);
                    return false;
                }
            } else {
                // We have a match for the certificate, but no principals from the entry: check that given
                // user name is in the certificate's principals.
                if (!GenericUtils.isEmpty(certPrincipals) && !certPrincipals.contains(username)) {
                    log.debug("authenticate({})[{}] certificate match rejected, user not in certificate principals: {}",
                            username, session, username);
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return Objects.toString(getId());
    }
}
