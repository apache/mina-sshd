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

package org.apache.sshd.server.auth.password;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.server.auth.BaseAuthenticatorTest;
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
public class LdapPasswordAuthenticatorTest extends BaseAuthenticatorTest {
    private static final AtomicReference<Pair<LdapServer, DirectoryService>> LDAP_CONTEX_HOLDER = new AtomicReference<>();
    private static Map<String, String> usersMap;

    public LdapPasswordAuthenticatorTest() {
        super();
    }

    @BeforeClass
    public static void startApacheDs() throws Exception {
        LDAP_CONTEX_HOLDER.set(startApacheDs(LdapPasswordAuthenticatorTest.class));
        usersMap = populateUsers(LDAP_CONTEX_HOLDER.get().getSecond(), LdapPasswordAuthenticatorTest.class, LdapPasswordAuthenticator.DEFAULT_PASSWORD_ATTR_NAME);
        assertFalse("No users retrieved", GenericUtils.isEmpty(usersMap));
    }

    @AfterClass
    public static void stopApacheDs() throws Exception {
        stopApacheDs(LDAP_CONTEX_HOLDER.getAndSet(null));
    }

    @Test   // the user's password is compared with the LDAP stored one
    public void testPasswordComparison() throws Exception {
        Pair<LdapServer, DirectoryService> ldapContext = LDAP_CONTEX_HOLDER.get();
        LdapPasswordAuthenticator auth = new LdapPasswordAuthenticator();
        auth.setHost(getHost(ldapContext));
        auth.setPort(getPort(ldapContext));
        auth.setBaseDN(BASE_DN_TEST);

        ServerSession session = Mockito.mock(ServerSession.class);
        outputDebugMessage("%s: %s", getCurrentTestName(), auth);
        for (Map.Entry<String, String> ue : usersMap.entrySet()) {
            String username = ue.getKey();
            String password = ue.getValue();
            outputDebugMessage("Authenticate: user=%s, password=%s", username, password);
            assertTrue("Failed to authenticate " + username, auth.authenticate(username, password, session));
        }
    }
}
