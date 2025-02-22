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

package org.apache.sshd.certificates;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;

import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("NoIoTestCase") // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class OpenSSHCertificateParserTest extends BaseTestSupport {

    private static final String USER_KEY_PATH = "org/apache/sshd/client/opensshcerts/user/";

    private TestParams params;

    public void initOpenSSHCertificateParserTest(TestParams params) {
        this.params = params;
    }

    public static Iterable<? extends TestParams> privateKeyParams() {
        return Arrays.asList(
                new TestParams("rsa-sha2-256", "user01_rsa_sha2_256_2048"),
                new TestParams("rsa-sha2-512", "user01_rsa_sha2_512_2048"),
                new TestParams("rsa-sha2-256", "user01_rsa_sha2_256_4096"),
                new TestParams("rsa-sha2-512", "user01_rsa_sha2_512_4096"),
                new TestParams("rsa-sha2-512", "user01_ed25519"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_256"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_384"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_521"));
    }

    @SuppressWarnings("synthetic-access")
    private String getCertificateResource() {
        return USER_KEY_PATH + params.privateKey + "-cert" + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
    }

    @MethodSource("privateKeyParams")
    @ParameterizedTest(name = "{0}")
    @SuppressWarnings("synthetic-access")
    public void parseCertificate(TestParams params) throws Exception {

        initOpenSSHCertificateParserTest(params);

        try (InputStream certInputStream
                = Thread.currentThread().getContextClassLoader().getResourceAsStream(getCertificateResource())) {

            byte[] certBytes = IoUtils.toByteArray(certInputStream);
            String certLine = GenericUtils.replaceWhitespaceAndTrim(new String(certBytes, StandardCharsets.UTF_8));

            PublicKeyEntry certPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(certLine);
            PublicKey cert = certPublicKeyEntry.resolvePublicKey(null, null, null);

            assertObjectInstanceOf("Must be OpenSshCertificate instance", OpenSshCertificate.class, cert);

            OpenSshCertificate typedCert = (OpenSshCertificate) cert;

            assertEquals(Collections.singletonList("user01"), typedCert.getPrincipals());
            assertEquals(OpenSshCertificate.Type.USER, typedCert.getType());
            assertNotNull(typedCert.getKeyType());
            assertEquals(0L, typedCert.getSerial());
            assertEquals("user01", typedCert.getId());
            assertEquals(OpenSshCertificate.MIN_EPOCH, typedCert.getValidAfter()); // forever
            assertEquals(OpenSshCertificate.INFINITY, typedCert.getValidBefore()); // forever
            assertTrue(typedCert.getCriticalOptions().isEmpty());
            assertEquals(
                    Arrays.asList(
                            new OpenSshCertificate.CertificateOption("permit-X11-forwarding", ""),
                            new OpenSshCertificate.CertificateOption("permit-agent-forwarding", ""),
                            new OpenSshCertificate.CertificateOption("permit-port-forwarding", ""),
                            new OpenSshCertificate.CertificateOption("permit-pty", ""),
                            new OpenSshCertificate.CertificateOption("permit-user-rc", "")),
                    typedCert.getExtensions());
            assertEquals(params.sigAlgorithm, typedCert.getSignatureAlgorithm());
            verifySignature(typedCert);
            Buffer buffer = new ByteArrayBuffer();
            buffer.putPublicKey(typedCert);
            PublicKey readFromBuffer = buffer.getPublicKey();
            assertTrue(readFromBuffer instanceof OpenSshCertificate,
                    () -> "Expected an OpenSshCertificate but got " + readFromBuffer.getClass().getName());
            OpenSshCertificate readBack = (OpenSshCertificate) readFromBuffer;
            verifySignature(readBack);
        }
    }

    private void verifySignature(OpenSshCertificate cert) throws Exception {
        PublicKey signatureKey = cert.getCaPubKey();
        String keyAlg = KeyUtils.getKeyType(signatureKey);
        String sigAlg = cert.getSignatureAlgorithm();
        assertTrue(KeyUtils.getAllEquivalentKeyTypes(keyAlg).contains(sigAlg),
                "Invalid signature algorithm " + sigAlg + " for key " + keyAlg);
        Signature verif = NamedFactory.create(BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE, sigAlg);
        verif.initVerifier(null, signatureKey);
        verif.update(null, cert.getMessage());
        assertTrue(verif.verify(null, cert.getSignature()), "Signature should validate");
    }

    private static class TestParams {
        private final String sigAlgorithm;
        private final String privateKey;

        TestParams(String sigAlgorithm, String privateKey) {
            this.sigAlgorithm = sigAlgorithm;
            this.privateKey = privateKey;
        }
    }
}
