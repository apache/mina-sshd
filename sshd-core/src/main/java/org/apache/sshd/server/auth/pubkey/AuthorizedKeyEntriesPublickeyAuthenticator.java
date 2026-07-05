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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.sshd.client.config.hosts.HostPatternValue;
import org.apache.sshd.client.config.hosts.HostPatternsHolder;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.net.InetAddressRange;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;
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
                PublicKey k = e.resolvePublicKey(session, Collections.emptyMap(), fallbackResolver);
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
                if (!matchesLoginOptions(entry, username, session)) {
                    continue;
                }
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

    protected boolean matchesLoginOptions(AuthorizedKeyEntry entry, String username, ServerSession session) {
        Map<String, String> options = entry.getLoginOptions();
        if (MapEntryUtils.isEmpty(options)) {
            return true;
        }
        if (!matchesExpiryTime(username, session, options.get("expiry-time"))) {
            return false;
        }
        return matchesFrom(username, session, options.get("from"));
    }

    protected boolean matchesExpiryTime(String username, ServerSession session, String expiryTime) {
        if (GenericUtils.isEmpty(expiryTime)) {
            return true;
        }
        try {
            Instant expiry = parseExpiryTime(expiryTime);
            if (Instant.now().isBefore(expiry)) {
                return true;
            }
            log.debug("authenticate({})[{}] authorized key rejected, expiry-time has passed: {}", username, session,
                    expiryTime);
        } catch (DateTimeException | IllegalArgumentException e) {
            log.debug("authenticate({})[{}] authorized key rejected, invalid expiry-time: {}", username, session,
                    expiryTime, e);
        }
        return false;
    }

    protected Instant parseExpiryTime(String expiryTime) {
        String value = GenericUtils.trimToEmpty(expiryTime);
        boolean utc = value.endsWith("Z");
        if (utc) {
            value = value.substring(0, value.length() - 1);
        }
        ZoneId zone = utc ? ZoneOffset.UTC : ZoneId.systemDefault();
        switch (value.length()) {
            case 8:
                return LocalDate.parse(value, DateTimeFormatter.BASIC_ISO_DATE).atStartOfDay(zone).toInstant();
            case 12:
                return LocalDateTime.parse(value, DateTimeFormatter.ofPattern("yyyyMMddHHmm")).atZone(zone).toInstant();
            case 14:
                return LocalDateTime.parse(value, DateTimeFormatter.ofPattern("yyyyMMddHHmmss")).atZone(zone).toInstant();
            default:
                throw new IllegalArgumentException("Unsupported expiry-time format: " + expiryTime);
        }
    }

    protected boolean matchesFrom(String username, ServerSession session, String from) {
        if (GenericUtils.isEmpty(from)) {
            return true;
        }
        InetSocketAddress remote = resolveClientAddress(session);
        if (remote == null) {
            log.debug("authenticate({})[{}] authorized key rejected, no client address for from={}", username, session, from);
            return false;
        }
        InetAddress remoteAddress = remote.getAddress();
        String remoteHostAddress = (remoteAddress == null) ? remote.getHostString() : remoteAddress.getHostAddress();
        String remoteCanonicalHostName = (remoteAddress == null)
                ? remote.getHostString()
                : remoteAddress.getCanonicalHostName();
        boolean matchFound = false;

        for (String pattern : from.split(",")) {
            try {
                String candidate = GenericUtils.trimToEmpty(pattern);
                if (GenericUtils.isEmpty(candidate)) {
                    continue;
                }
                boolean negated = candidate.charAt(0) == HostPatternsHolder.NEGATION_CHAR_PATTERN;
                String rawPattern = negated ? candidate.substring(1) : candidate;
                if (GenericUtils.isEmpty(rawPattern)) {
                    return false;
                }
                boolean matched;
                if (InetAddressRange.isCIDR(rawPattern)) {
                    matched = (remoteAddress != null) && InetAddressRange.fromCIDR(rawPattern).contains(remoteAddress);
                } else {
                    HostPatternValue hostPattern = HostPatternsHolder.toPattern(candidate);
                    matched = HostPatternsHolder.isHostMatch(remoteHostAddress, hostPattern.getPattern())
                            || HostPatternsHolder.isHostMatch(remoteCanonicalHostName, hostPattern.getPattern());
                }
                if (!matched) {
                    continue;
                }
                if (negated) {
                    log.debug("authenticate({})[{}] authorized key rejected, client address matched negated from pattern: {}",
                            username, session, candidate);
                    return false;
                }
                matchFound = true;
            } catch (RuntimeException e) {
                log.debug("authenticate({})[{}] authorized key rejected, invalid from pattern: {}", username, session,
                        pattern, e);
                return false;
            }
        }

        if (!matchFound) {
            log.debug("authenticate({})[{}] authorized key rejected, client address did not match from={}", username,
                    session, from);
        }
        return matchFound;
    }

    protected InetSocketAddress resolveClientAddress(ServerSession session) {
        if (session == null) {
            return null;
        }
        SocketAddress address = session.getClientAddress();
        if (!(address instanceof InetSocketAddress)) {
            address = session.getRemoteAddress();
        }
        return (address instanceof InetSocketAddress) ? (InetSocketAddress) address : null;
    }

    protected boolean matchesPrincipals(
            AuthorizedKeyEntry entry, String username, OpenSshCertificate cert,
            ServerSession session) {
        Collection<String> certPrincipals = cert.getPrincipals();
        // OpenSSH < 10.3:
        //
        // "As a special case, a zero-length "valid principals" field means the certificate is valid for
        // any principal of the specified type."
        // See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
        //
        // This is true for user certificates unless they are checked via a TrustedUserCAKeys file, but
        // that is not what we implement here.
        // See https://man.openbsd.org/sshd_config#TrustedUserCAKeys
        //
        // OpenSSH >= 10.3: certificates without principals never match
        if (!GenericUtils.isEmpty(certPrincipals)) {
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
                if (!certPrincipals.contains(username)) {
                    log.debug("authenticate({})[{}] certificate match rejected, user not in certificate principals: {}",
                            username, session, certPrincipals);
                    return false;
                }
            }
        } else if (!CoreModuleProperties.ALLOW_EMPTY_CERTIFICATE_PRINCIPALS.getRequired(session)) {
            log.debug("authenticate({})[{}] certificate match rejected because the certificate has no principals", username,
                    session);
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return Objects.toString(getId());
    }
}
