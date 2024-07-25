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

package org.apache.sshd.client.auth.password;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class PasswordIdentityProviderTest extends JUnitTestSupport {
    public PasswordIdentityProviderTest() {
        super();
    }

    @Test
    void multiProvider() throws IOException, GeneralSecurityException {
        String[][] values = {
                { getClass().getSimpleName(), getCurrentTestName() },
                { new Date(System.currentTimeMillis()).toString() },
                { getClass().getPackage().getName() }
        };
        List<String> expected = new ArrayList<>();
        Collection<PasswordIdentityProvider> providers = new LinkedList<>();
        for (String[] va : values) {
            Collection<String> passwords = Arrays.asList(va);
            expected.addAll(passwords);

            PasswordIdentityProvider p = PasswordIdentityProvider.wrapPasswords(passwords);
            assertProviderContents("Wrapped", p, passwords);
            providers.add(p);
        }

        PasswordIdentityProvider p = PasswordIdentityProvider.multiProvider(null, providers);
        assertProviderContents("Multi", p, expected);
    }

    private static void assertProviderContents(String message, PasswordIdentityProvider p, Iterable<String> expected)
            throws IOException, GeneralSecurityException {
        assertNotNull(p, message + ": no provider");
        assertEquals(message, expected, p.loadPasswords(null));
    }
}
