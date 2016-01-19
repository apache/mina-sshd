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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.auth.BaseAuthenticatorTest;
import org.apache.sshd.server.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.server.session.ServerSession;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LdapPublickeyAuthenticatorTest extends BaseAuthenticatorTest {
    private static final AtomicReference<Pair<LdapServer, DirectoryService>> ldapContextHolder = new AtomicReference<>();
    private static final Map<String, PublicKey> keysMap = new HashMap<>();
    // we use this instead of the default since the default requires some extra LDIF manipulation which we don't need
    private static final String TEST_ATTR_NAME = "description";

    public LdapPublickeyAuthenticatorTest() {
        super();
    }

    @BeforeClass
    public static void startApacheDs() throws Exception {
        ldapContextHolder.set(startApacheDs(LdapPublickeyAuthenticatorTest.class));
        Map<String, String> credentials =
                populateUsers(ldapContextHolder.get().getSecond(), LdapPublickeyAuthenticatorTest.class, TEST_ATTR_NAME);
        assertFalse("No keys retrieved", GenericUtils.isEmpty(credentials));

        for (Map.Entry<String, String> ce : credentials.entrySet()) {
            String username = ce.getKey();
            AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(ce.getValue());
            PublicKey key = ValidateUtils.checkNotNull(entry, "No key extracted").resolvePublicKey(PublicKeyEntryResolver.FAILING);
            keysMap.put(username, key);
        }
    }

    @AfterClass
    public static void stopApacheDs() throws Exception {
        stopApacheDs(ldapContextHolder.getAndSet(null));
    }

    @Test
    public void testPublicKeyComparison() throws Exception {
        LdapPublickeyAuthenticator auth = new LdapPublickeyAuthenticator();
        auth.setBaseDN(BASE_DN_TEST);
        auth.setPort(getPort(ldapContextHolder.get()));
        auth.setKeyAttributeName(TEST_ATTR_NAME);
        auth.setRetrievedAttributes(TEST_ATTR_NAME);

        ServerSession session = Mockito.mock(ServerSession.class);
        for (Map.Entry<String, PublicKey> ke : keysMap.entrySet()) {
            String username = ke.getKey();
            PublicKey key = ke.getValue();
            outputDebugMessage("Authenticate: user=%s, key-type=%s, fingerprint=%s",
                               username, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            assertTrue("Failed to authenticate user=" + username, auth.authenticate(username, key, session));
        }
    }
}
