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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileHostKeyCertificateProvider;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class OpenSSHCertificateTest extends BaseTestSupport {
    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    private FileHostKeyCertificateProvider certificateProvider;
    private FileKeyPairProvider keyPairProvider;
    private List<NamedFactory<Signature>> signatureFactory;

    public void initOpenSSHCertificateTest(String keyPath, String certPath, List<NamedFactory<Signature>> signatureFactory) {
        Path testResourcesFolder = getTestResourcesFolder();
        this.keyPairProvider = new FileKeyPairProvider(testResourcesFolder.resolve(keyPath));
        this.certificateProvider = new FileHostKeyCertificateProvider(testResourcesFolder.resolve(certPath));
        this.signatureFactory = signatureFactory;
        sshd.setKeyPairProvider(keyPairProvider);
        sshd.setHostKeyCertificateProvider(certificateProvider);

        CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE.remove(client);

        client.setSignatureFactories(this.signatureFactory);
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestFullSupportServer(OpenSSHCertificateTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestFullSupportClient(OpenSSHCertificateTest.class);
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

    @SuppressWarnings("deprecation")
    public static List<Object[]> parameters() {
        List<Object[]> list = new ArrayList<>();

        String key = "ssh_host_rsa_key";
        String certificate = "ssh_host_rsa_key_sha1-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
        String certificateSha512 = "ssh_host_rsa_key-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX;

        // default client
        list.add(new Object[] {
                key, certificate,
                Arrays.asList(BuiltinSignatures.rsaSHA512, BuiltinSignatures.rsaSHA256, BuiltinSignatures.rsa) });
        list.add(new Object[] { key, certificate, Arrays.asList(BuiltinSignatures.rsa_cert, BuiltinSignatures.rsa) });
        // client does not support cert
        list.add(new Object[] { key, certificate, Collections.singletonList(BuiltinSignatures.rsa) });
        // rsa variant
        list.add(new Object[] {
                key, certificateSha512, Arrays.asList(BuiltinSignatures.rsaSHA512_cert, BuiltinSignatures.rsaSHA512) });
        list.add(new Object[] {
                key, certificateSha512, Arrays.asList(BuiltinSignatures.rsa_cert, BuiltinSignatures.rsaSHA512) });

        return Collections.unmodifiableList(list);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={2}")
    public void openSshCertificates(String keyPath, String certPath, List<NamedFactory<Signature>> signatureFactory)
            throws Exception {
        initOpenSSHCertificateTest(keyPath, certPath, signatureFactory);
        // default client
        try (ClientSession s = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={2}") // invalid principal, but continue
    public void continueOnInvalidPrincipal(String keyPath, String certPath, List<NamedFactory<Signature>> signatureFactory)
            throws Exception {
        initOpenSSHCertificateTest(keyPath, certPath, signatureFactory);
        CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE.set(client, false);
        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={2}") // invalid principal, abort
    @SuppressWarnings("deprecation")
    public void abortOnInvalidPrincipal(String keyPath, String certPath, List<NamedFactory<Signature>> signatureFactory)
            throws Exception {
        initOpenSSHCertificateTest(keyPath, certPath, signatureFactory);
        CoreModuleProperties.ABORT_ON_INVALID_CERTIFICATE.set(client, true);
        boolean thrown = false;
        try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            s.addPasswordIdentity(getCurrentTestName());
            s.auth().verify(AUTH_TIMEOUT);

            // in case client does not support cert, no exception should be thrown
            assertFalse(client.getSignatureFactories().contains(BuiltinSignatures.rsa_cert));
        } catch (SshException e) {
            assertEquals(SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, e.getDisconnectCode());
            assertTrue(e.getMessage().contains("principal"),
                    "Expected error about invalid principal, got: " + e.getMessage());
            thrown = true;
        }
        boolean containsCert = GenericUtils.containsAny(client.getSignatureFactories(),
                Arrays.asList(BuiltinSignatures.rsaSHA512_cert, BuiltinSignatures.rsaSHA256_cert, BuiltinSignatures.rsa_cert));
        assertEquals(containsCert, thrown);
    }
}
