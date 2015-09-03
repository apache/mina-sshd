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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultAuthorizedKeysAuthenticatorTest extends BaseTestSupport {
    public DefaultAuthorizedKeysAuthenticatorTest() {
        super();
    }

    @Test
    public void testUsernameValidation() throws Exception {
        Path file = getTargetRelativeFile(TEMP_SUBFOLDER_NAME, getCurrentTestName()).toPath();
        URL url = getClass().getResource(AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME);
        assertNotNull("Missing " + AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME + " resource", url);

        try (InputStream input = url.openStream();
             OutputStream output = Files.newOutputStream(file)) {
            IoUtils.copy(input, output);
        }

        Collection<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(file);
        Collection<PublicKey> keySet = AuthorizedKeyEntry.resolveAuthorizedKeys(entries);
        PublickeyAuthenticator auth = new DefaultAuthorizedKeysAuthenticator(file, false);
        String thisUser = System.getProperty("user.name");
        for (String username : new String[]{null, "", thisUser, getClass().getName() + "#" + getCurrentTestName()}) {
            boolean expected = thisUser.equals(username);
            for (PublicKey key : keySet) {
                boolean actual = auth.authenticate(username, key, null);
                assertEquals("Mismatched authentication results for user='" + username + "'", expected, actual);
            }
        }
    }
}
