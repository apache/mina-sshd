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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for KEX with host certificates.
 */
class OpenSshHostCertificateTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    private KeyPair hostKey;
    private KeyPair caKey;

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(OpenSshHostCertificateTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(OpenSshHostCertificateTest.class);
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

    private static Stream<Arguments> certificateAlgorithms() {
        return Stream.of( //
                Arguments.of(KeyUtils.RSA_ALGORITHM, 2048, KeyUtils.RSA_ALGORITHM, 2048, "rsa-sha2-512"),
                Arguments.of(KeyUtils.EC_ALGORITHM, 256, KeyUtils.EC_ALGORITHM, 256, "ecdsa-sha2-nistp256"),
                Arguments.of(KeyUtils.RSA_ALGORITHM, 2048, KeyUtils.EC_ALGORITHM, 256, "ecdsa-sha2-nistp256"),
                Arguments.of(KeyUtils.EC_ALGORITHM, 256, KeyUtils.RSA_ALGORITHM, 2048, "rsa-sha2-512"));
    }

    private void initKeys(String keyType, int keySize, String caType, int caSize, String signatureAlgorithm) throws Exception {
        caKey = CommonTestSupportUtils.generateKeyPair(caType, caSize);
        KeyPair hostKeyPair = CommonTestSupportUtils.generateKeyPair(keyType, keySize);
        // Generate a host certificate.
        List<String> principals = new ArrayList<>();
        principals.add("localhost");
        principals.add("127.0.0.1");
        OpenSshCertificate signedCert = OpenSshCertificateBuilder.hostCertificate() //
                .serial(System.currentTimeMillis()) //
                .publicKey(hostKeyPair.getPublic()) //
                .id("test-cert-" + signatureAlgorithm) //
                .validBefore(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)) //
                .principals(principals) //
                .sign(caKey, signatureAlgorithm);
        hostKey = hostKeyPair;
        // new KeyPair(signedCert, hostKeyPair.getPrivate());
        sshd.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
        sshd.setHostKeyCertificateProvider(session -> Collections.singletonList(signedCert));
        client.setServerKeyVerifier((session, address, key) -> {
            return (key instanceof OpenSshCertificate)
                    && KeyUtils.compareKeys(caKey.getPublic(), ((OpenSshCertificate) key).getCaPubKey());
        });
    }

    @ParameterizedTest(name = "test host certificate {0} signed with {2}")
    @MethodSource("certificateAlgorithms")
    void testHostCertificate(String keyType, int keySize, String caType, int caSize, String signatureAlgorithm)
            throws Exception {
        initKeys(keyType, keySize, caType, caSize, signatureAlgorithm);
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);
        }
    }
}
