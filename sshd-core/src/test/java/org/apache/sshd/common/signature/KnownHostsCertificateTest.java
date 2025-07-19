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
package org.apache.sshd.common.signature;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for KEX with host certificates with host key validation through a {@link KnownHostsServerKeyVerifier}.
 */
class KnownHostsCertificateTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    @TempDir
    private Path tmp;

    private KeyPair hostKey;
    private KeyPair caKey;

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(KnownHostsCertificateTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(KnownHostsCertificateTest.class);
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

    private static Stream<String> markers() {
        return Stream.of("rejected", "", null);
    }

    private void initKeys(String keyType, int keySize, String caType, int caSize, String signatureAlgorithm, String marker)
            throws Exception {
        initKeys(keyType, keySize, caType, caSize, signatureAlgorithm, marker, "localhost", "127.0.0.1");
    }

    private void initKeys(
            String keyType, int keySize, String caType, int caSize, String signatureAlgorithm, String marker,
            String... principals) throws Exception {
        caKey = CommonTestSupportUtils.generateKeyPair(caType, caSize);
        KeyPair hostKeyPair = CommonTestSupportUtils.generateKeyPair(keyType, keySize);
        // Generate a host certificate.
        OpenSshCertificate signedCert = OpenSshCertificateBuilder.hostCertificate() //
                .serial(System.currentTimeMillis()) //
                .publicKey(hostKeyPair.getPublic()) //
                .id("test-cert-" + signatureAlgorithm) //
                .validBefore(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)) //
                .principals(Arrays.asList(principals)) //
                .sign(caKey, signatureAlgorithm);
        hostKey = hostKeyPair;
        // new KeyPair(signedCert, hostKeyPair.getPrivate());
        sshd.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
        sshd.setHostKeyCertificateProvider(session -> Collections.singletonList(signedCert));
        Path knownHosts = tmp.resolve("known_hosts");
        if (marker != null) {
            StringBuilder line = new StringBuilder();
            if (!GenericUtils.isEmpty(marker)) {
                line.append('@').append(marker).append(' ');
            }
            line.append("[localhost]:").append(port).append(",[127.0.0.1]:").append(port).append(' ');
            line.append(PublicKeyEntry.toString(caKey.getPublic()));
            line.append('\n');
            Files.write(knownHosts, Collections.singletonList(line.toString()));
        }
        client.setServerKeyVerifier(new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, knownHosts));
    }

    @ParameterizedTest(name = "test {0} CA key")
    @MethodSource("markers")
    void testHostCertificateFails(String marker) throws Exception {
        initKeys(KeyUtils.EC_ALGORITHM, 256, KeyUtils.EC_ALGORITHM, 256, "ecdsa-sha2-nistp256", marker);
        assertThrows(SshException.class, () -> {
            try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                    .getSession()) {
                s.addPasswordIdentity(getCurrentTestName());
                s.auth().verify(AUTH_TIMEOUT);
            }
        });
    }

    @Test
    void testHostCertificateSucceeds() throws Exception {
        initKeys(KeyUtils.EC_ALGORITHM, 256, KeyUtils.EC_ALGORITHM, 256, "ecdsa-sha2-nistp256", "cert-authority");
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);
        }
    }

    @Test
    void testHostCertificateWithoutPrincipalsSucceeds() throws Exception {
        initKeys(KeyUtils.EC_ALGORITHM, 256, KeyUtils.EC_ALGORITHM, 256, "ecdsa-sha2-nistp256", "cert-authority",
                new String[0]);
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);
        }
    }
}
