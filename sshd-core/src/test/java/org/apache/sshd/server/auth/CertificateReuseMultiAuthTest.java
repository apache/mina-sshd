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
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.Test;

class CertificateReuseMultiAuthTest extends BaseTestSupport {

    @Test
    void twoCertificatesForOnePrivateKeyMustNotSatisfyTwoPublicKeySteps() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyUtils.RSA_ALGORITHM);
        generator.initialize(2048);
        KeyPair ca = generator.generateKeyPair();
        KeyPair user = generator.generateKeyPair();
        KeyPair independentUser = generator.generateKeyPair();
        String username = "single-key-user";
        long expiry = System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1);

        OpenSshCertificate cert1 = OpenSshCertificateBuilder.userCertificate()
                .serial(1L).publicKey(user.getPublic()).id("first")
                .validBefore(expiry).principals(Collections.singletonList(username))
                .sign(ca, "rsa-sha2-256");
        OpenSshCertificate cert2 = OpenSshCertificateBuilder.userCertificate()
                .serial(2L).publicKey(user.getPublic()).id("second")
                .validBefore(expiry).principals(Collections.singletonList(username))
                .sign(ca, "rsa-sha2-256");
        OpenSshCertificate independentCert = OpenSshCertificateBuilder.userCertificate()
                .serial(3L).publicKey(independentUser.getPublic()).id("independent")
                .validBefore(expiry).principals(Collections.singletonList(username))
                .sign(ca, "rsa-sha2-256");
        assertFalse(KeyUtils.compareKeys((PublicKey) cert1, (PublicKey) cert2));
        assertTrue(KeyUtils.compareKeys(cert1.getCertPubKey(), cert2.getCertPubKey()));

        SshServer sshd = CoreTestSupportUtils.setupTestServer(CertificateReuseMultiAuthTest.class);
        SshClient client = CoreTestSupportUtils.setupTestClient(CertificateReuseMultiAuthTest.class);
        try {
            CoreTestSupportUtils.setupFullSignaturesSupport(sshd);
            CoreTestSupportUtils.setupFullSignaturesSupport(client);
            AuthorizedKeyEntry caEntry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(
                    "cert-authority " + PublicKeyEntry.toString(ca.getPublic()));
            sshd.setPublickeyAuthenticator(new AuthorizedKeyEntriesPublickeyAuthenticator(
                    "test-ca", null, Collections.singletonList(caEntry), PublicKeyEntryResolver.FAILING));
            CoreModuleProperties.AUTH_METHODS.set(sshd, "publickey,publickey");
            sshd.start();
            client.setUserAuthFactoriesNames(UserAuthMethodFactory.PUBLIC_KEY);
            client.start();

            try (ClientSession session = createClientSession(username, client, sshd.getPort())) {
                session.setKeyIdentityProvider(context -> Collections.singletonList(
                        new KeyPair(cert1, user.getPrivate())));
                assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT),
                        "one certificate alone should not meet a two-key policy");
                assertFalse(session.isAuthenticated());
            }
            try (ClientSession session = createClientSession(username, client, sshd.getPort())) {
                session.setKeyIdentityProvider(context -> Arrays.asList(
                        new KeyPair(cert1, user.getPrivate()),
                        new KeyPair(independentCert, independentUser.getPrivate())));
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated(), "two independent private keys should authenticate");
            }
            try (ClientSession session = createClientSession(username, client, sshd.getPort())) {
                session.setKeyIdentityProvider(context -> Arrays.asList(
                        new KeyPair(cert1, user.getPrivate()),
                        new KeyPair(cert2, user.getPrivate())));
                assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT),
                        "two certificates for the same private key must not count as two keys");
            }
        } finally {
            client.stop();
            sshd.stop(true);
        }
    }
}
