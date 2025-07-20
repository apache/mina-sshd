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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for user certificate authentication with checking an OpenSSH-style authorized_keys file.
 */
class AuthorizedKeysCertificateTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    @TempDir
    private Path tmp;

    private KeyPair caKey;
    private KeyPair userKey;
    private OpenSshCertificate userCert;

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(AuthorizedKeysCertificateTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(AuthorizedKeysCertificateTest.class);
        client.start();
    }

    @AfterAll
    static void tearDownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }

        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    private static Stream<Arguments> options() {
        return Stream.of(Arguments.of("", "", false), // Not CA: fail
                Arguments.of("", "user", false), // Not CA: fail
                Arguments.of("cert-authority", "user", true), // CA, principal=user: success
                Arguments.of("cert-authority", "", true), // CA, no principal: success
                Arguments.of("cert-authority", "other", false), // CA, wrong principal: fail
                Arguments.of("cert-authority,principals=\"other\"", "user", false), // CA, principal overridden
                Arguments.of("cert-authority,principals=\"other\"", "other", true) // CA, principal overridden
        );
    }

    private void initCert(String caMarker, String... principals) throws Exception {
        caKey = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 2048);
        userKey = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        // Generate a user certificate.
        userCert = OpenSshCertificateBuilder.userCertificate() //
                .serial(System.currentTimeMillis()) //
                .publicKey(userKey.getPublic()) //
                .id("test-cert") //
                .validBefore(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)) //
                .principals(Arrays.asList(principals)) //
                .sign(caKey, "rsa-sha2-256");
        Path authorizedKeys = tmp.resolve("authorized_keys");
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        if (!GenericUtils.isEmpty(caMarker)) {
            line.append(caMarker).append(' ');
        }
        line.append(PublicKeyEntry.toString(caKey.getPublic()));
        lines.add(line.toString());
        lines.add(PublicKeyEntry.toString(userKey.getPublic()));
        Files.write(authorizedKeys, lines);

        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPublickeyAuthenticator(new AuthorizedKeyEntriesPublickeyAuthenticator(authorizedKeys, null,
                AuthorizedKeyEntry.readAuthorizedKeys(authorizedKeys), PublicKeyEntryResolver.FAILING));
        client.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
    }

    @ParameterizedTest(name = "test {0} CA key with {1}")
    @MethodSource("options")
    void testCertificate(String marker, String principals, boolean expectSuccess) throws Exception {
        String[] certPrincipals = GenericUtils.isEmpty(principals) ? new String[0] : principals.split(",");
        initCert(marker, certPrincipals);
        try (ClientSession s = client.connect("user", TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            KeyPair certKeyPair = new KeyPair(userCert, userKey.getPrivate());
            s.addPublicKeyIdentity(certKeyPair);
            AuthFuture auth = s.auth();
            if (expectSuccess) {
                auth.verify(AUTH_TIMEOUT);
            } else {
                assertThrows(SshException.class, () -> auth.verify(AUTH_TIMEOUT));
            }
        }
    }

    private static Stream<Arguments> plainOptions() {
        return Stream.of(Arguments.of("", true), // Not CA: success
                Arguments.of("cert-authority", false) // CA: fail
        );
    }

    private void initKeys(String marker) throws Exception {
        caKey = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 2048);
        userKey = CommonTestSupportUtils.generateKeyPair(KeyUtils.EC_ALGORITHM, 256);
        Path authorizedKeys = tmp.resolve("authorized_keys");
        StringBuilder line = new StringBuilder();
        if (!GenericUtils.isEmpty(marker)) {
            line.append(marker).append(' ');
        }
        line.append(PublicKeyEntry.toString(userKey.getPublic()));
        Files.write(authorizedKeys, Collections.singletonList(line.toString()));

        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
        sshd.setPublickeyAuthenticator(new AuthorizedKeyEntriesPublickeyAuthenticator(authorizedKeys, null,
                AuthorizedKeyEntry.readAuthorizedKeys(authorizedKeys), PublicKeyEntryResolver.FAILING));
        client.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
    }

    @ParameterizedTest(name = "test plain key with {0}")
    @MethodSource("plainOptions")
    void testPlainKey(String marker, boolean expectSuccess) throws Exception {
        initKeys(marker);
        try (ClientSession s = client.connect("user", TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
            s.addPublicKeyIdentity(userKey);
            AuthFuture auth = s.auth();
            if (expectSuccess) {
                auth.verify(AUTH_TIMEOUT);
            } else {
                assertThrows(SshException.class, () -> auth.verify(AUTH_TIMEOUT));
            }
        }
    }
}
