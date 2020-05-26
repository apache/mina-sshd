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

package org.apache.sshd.server.config.keys;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.AuthorizedKeysTestSupport;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultAuthorizedKeysAuthenticatorTest extends AuthorizedKeysTestSupport {
    public DefaultAuthorizedKeysAuthenticatorTest() {
        super();
    }

    @Test
    public void testUsernameValidation() throws Exception {
        Path file = getTempTargetRelativeFile(getCurrentTestName());
        writeDefaultSupportedKeys(file);

        Collection<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(file);
        Collection<PublicKey> keySet = PublicKeyEntry.resolvePublicKeyEntries(null, entries, PublicKeyEntryResolver.FAILING);
        PublickeyAuthenticator auth = new DefaultAuthorizedKeysAuthenticator(file, false);
        String thisUser = OsUtils.getCurrentUser();
        ServerSession session = Mockito.mock(ServerSession.class);
        for (String username : new String[] { null, "", thisUser, getClass().getName() + "#" + getCurrentTestName() }) {
            boolean expected = thisUser.equals(username);
            for (PublicKey key : keySet) {
                boolean actual = auth.authenticate(username, key, session);
                assertEquals("Mismatched authentication results for user='" + username + "'", expected, actual);
            }
        }
    }
}
