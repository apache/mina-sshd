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

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.session.ServerSession;

/**
 * The <code>PublickeyAuthenticator</code> is used on the server side to authenticate user public keys.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PublickeyAuthenticator {

    /**
     * Check the validity of a public key.
     *
     * @param  username           the username
     * @param  key                the key
     * @param  session            the server session
     * @return                    a boolean indicating if authentication succeeded or not
     * @throws AsyncAuthException If the authentication is performed asynchronously
     */
    boolean authenticate(String username, PublicKey key, ServerSession session) throws AsyncAuthException;

    /**
     * @param  id                       Some kind of mnemonic identifier for the authenticator - used also in
     *                                  {@code toString()}
     * @param  session                  The {@link ServerSession} that triggered this call - may be {@code null} if
     *                                  invoked by offline tool (e.g., unit test) or session context unknown to caller.
     * @param  entries                  The entries to parse - ignored if {@code null}/empty
     * @param  fallbackResolver         The public key resolver to use if none of the default registered ones works
     * @return                          A wrapper with all the parsed keys
     * @throws IOException              If failed to parse the keys data
     * @throws GeneralSecurityException If failed to generate the relevant keys from the parsed data
     */
    static PublickeyAuthenticator fromAuthorizedEntries(
            Object id, ServerSession session,
            Collection<? extends AuthorizedKeyEntry> entries,
            PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(entries)) {
            return RejectAllPublickeyAuthenticator.INSTANCE;
        } else {
            return new AuthorizedKeyEntriesPublickeyAuthenticator(id, session, entries, fallbackResolver);
        }
    }
}
