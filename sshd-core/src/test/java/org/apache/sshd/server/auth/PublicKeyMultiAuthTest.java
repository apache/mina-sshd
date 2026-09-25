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
package org.apache.sshd.server.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.hostbased.RejectAllHostBasedAuthenticator;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PublicKeyMultiAuthTest extends BaseTestSupport {

    private static final String USER_NAME = "single-key-user";

    private SshServer sshd;
    private SshClient client;
    private KeyPair firstAuthorizedKey;
    private KeyPair secondAuthorizedKey;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyUtils.RSA_ALGORITHM);
        generator.initialize(2048);
        firstAuthorizedKey = generator.generateKeyPair();
        secondAuthorizedKey = generator.generateKeyPair();

        sshd = CoreTestSupportUtils.setupTestServer(PublicKeyMultiAuthTest.class);
        sshd.setHostBasedAuthenticator(RejectAllHostBasedAuthenticator.INSTANCE);
        AuthorizedKeyEntry firstEntry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(
                PublicKeyEntry.toString(firstAuthorizedKey.getPublic()));
        AuthorizedKeyEntry secondEntry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(
                PublicKeyEntry.toString(secondAuthorizedKey.getPublic()));
        sshd.setPublickeyAuthenticator(new AuthorizedKeyEntriesPublickeyAuthenticator(
                "two-authorized-keys", null, Arrays.asList(firstEntry, secondEntry), PublicKeyEntryResolver.FAILING));
        CoreModuleProperties.AUTH_METHODS.set(sshd, "publickey,publickey");
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(PublicKeyMultiAuthTest.class);
        client.setUserAuthFactoriesNames(UserAuthMethodFactory.PUBLIC_KEY);
        client.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (client != null) {
            client.stop();
        }
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    void singleOfferedIdentityDoesNotSatisfyTwoPublicKeySteps() throws Exception {
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(context -> Collections.singletonList(firstAuthorizedKey));
            assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT));
            assertFalse(session.isAuthenticated());
        }
    }

    @Test
    void repeatedSameKeyDoesNotSatisfyTwoPublicKeySteps() throws Exception {
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(context -> {
                List<KeyPair> maliciousIdentities = new ArrayList<>();
                maliciousIdentities.add(firstAuthorizedKey);
                maliciousIdentities.add(firstAuthorizedKey);
                return maliciousIdentities;
            });

            SshException e = assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT),
                    "one key must not satisfy two-key authentication policy");
            assertEquals(e.getMessage(), "No more authentication methods available");
        }
    }

    @Test
    void twoDistinctAuthorizedKeysSatisfyTwoPublicKeySteps() throws Exception {
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(context -> Arrays.asList(firstAuthorizedKey, secondAuthorizedKey));

            session.auth().verify(AUTH_TIMEOUT);
            assertTrue(session.isAuthenticated());
        }
    }
}
