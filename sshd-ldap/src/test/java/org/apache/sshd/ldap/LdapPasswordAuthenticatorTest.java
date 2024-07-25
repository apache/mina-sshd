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

import java.util.Map;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.server.session.ServerSession;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@ExtendWith(ApacheDSTestExtension.class)
@TestMethodOrder(MethodName.class)
@CreateDS(name = "myDS",
          partitions = { @CreatePartition(name = "users", suffix = BaseAuthenticatorTest.BASE_DN_TEST) })
@CreateLdapServer(allowAnonymousAccess = true,
                  transports = { @CreateTransport(protocol = "LDAP", address = "localhost") })
@ApplyLdifFiles({ "auth-users.ldif" })
public class LdapPasswordAuthenticatorTest extends BaseAuthenticatorTest {

    private static Map<String, String> usersMap;

    public LdapPasswordAuthenticatorTest() {
        super();
    }

    // the user's password is compared with the LDAP stored one
    @Test
    void passwordComparison() throws Exception {
        usersMap = populateUsers(classLdapServer.getDirectoryService(),
                LdapPasswordAuthenticatorTest.class, LdapPasswordAuthenticator.DEFAULT_PASSWORD_ATTR_NAME);
        assertFalse(MapEntryUtils.isEmpty(usersMap), "No users retrieved");

        LdapPasswordAuthenticator auth = new LdapPasswordAuthenticator();
        auth.setHost(getHost(classLdapServer));
        auth.setPort(getPort(classLdapServer));
        auth.setBaseDN(BASE_DN_TEST);

        ServerSession session = Mockito.mock(ServerSession.class);
        outputDebugMessage("%s: %s", getCurrentTestName(), auth);
        usersMap.forEach((username, password) -> {
            outputDebugMessage("Authenticate: user=%s, password=%s", username, password);
            assertTrue(auth.authenticate(username, password, session), "Failed to authenticate " + username);
        });
    }
}
