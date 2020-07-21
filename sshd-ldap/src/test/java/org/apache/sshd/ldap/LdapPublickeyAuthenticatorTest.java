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

import java.security.PublicKey;
import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.session.ServerSession;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@CreateDS(name = "myDS",
          partitions = { @CreatePartition(name = "users", suffix = BaseAuthenticatorTest.BASE_DN_TEST) })
@CreateLdapServer(allowAnonymousAccess = true,
                  transports = { @CreateTransport(protocol = "LDAP", address = "localhost") })
@ApplyLdifFiles({ "auth-users.ldif" })
public class LdapPublickeyAuthenticatorTest extends BaseAuthenticatorTest {

    @ClassRule
    public static CreateLdapServerRule serverRule = new CreateLdapServerRule();

    private static final Map<String, PublicKey> KEYS_MAP = new TreeMap<>(Comparator.naturalOrder());
    // we use this instead of the default since the default requires some extra LDIF manipulation which we don't need
    private static final String TEST_ATTR_NAME = "description";

    public LdapPublickeyAuthenticatorTest() {
        super();
    }

    @Test
    public void testPublicKeyComparison() throws Exception {
        Map<String, String> credentials = populateUsers(serverRule.getLdapServer().getDirectoryService(),
                LdapPublickeyAuthenticatorTest.class, TEST_ATTR_NAME);
        assertFalse("No keys retrieved", GenericUtils.isEmpty(credentials));

        // Cannot use forEach because of the potential GeneraSecurityException being thrown
        for (Map.Entry<String, String> ce : credentials.entrySet()) {
            String username = ce.getKey();
            AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(ce.getValue());
            PublicKey key = Objects.requireNonNull(entry, "No key extracted")
                    .resolvePublicKey(null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING);
            KEYS_MAP.put(username, key);
        }

        LdapPublickeyAuthenticator auth = new LdapPublickeyAuthenticator();
        auth.setHost(getHost(serverRule.getLdapServer()));
        auth.setPort(getPort(serverRule.getLdapServer()));
        auth.setBaseDN(BASE_DN_TEST);
        auth.setKeyAttributeName(TEST_ATTR_NAME);
        auth.setRetrievedAttributes(TEST_ATTR_NAME);

        ServerSession session = Mockito.mock(ServerSession.class);
        outputDebugMessage("%s: %s", getCurrentTestName(), auth);
        KEYS_MAP.forEach((username, key) -> {
            outputDebugMessage("Authenticate: user=%s, key-type=%s, fingerprint=%s",
                    username, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            assertTrue("Failed to authenticate user=" + username, auth.authenticate(username, key, session));
        });
    }
}
