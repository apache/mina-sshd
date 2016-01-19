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
    private static final AtomicReference<Pair<LdapServer, DirectoryService>> ldapContextHolder = new AtomicReference<>();
    private static Map<String, String> usersMap;

    public LdapPasswordAuthenticatorTest() {
        super();
    }

    @BeforeClass
    public static void startApacheDs() throws Exception {
        ldapContextHolder.set(startApacheDs(LdapPasswordAuthenticatorTest.class));
        usersMap = populateUsers(ldapContextHolder.get().getSecond(), LdapPasswordAuthenticatorTest.class, LdapPasswordAuthenticator.DEFAULT_PASSWORD_ATTR_NAME);
    }

    @AfterClass
    public static void stopApacheDs() throws Exception {
        stopApacheDs(ldapContextHolder.getAndSet(null));
    }

    @Test   // the user's password is compared with the LDAP stored one
    public void testPasswordComparison() throws Exception {
        LdapPasswordAuthenticator auth = new LdapPasswordAuthenticator();
        auth.setBaseDN(BASE_DN_TEST);
        auth.setPort(getPort(ldapContextHolder.get()));

        ServerSession session = Mockito.mock(ServerSession.class);
        for (Map.Entry<String, String> ue : usersMap.entrySet()) {
            String username = ue.getKey();
            String password = ue.getValue();
            outputDebugMessage("Authenticate: user=%s, password=%s", username, password);
            assertTrue("Failed to authenticate " + username, auth.authenticate(username, password, session));
        }
    }
}
