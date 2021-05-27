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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;

import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class GenerateOpenSshClientCertificateOracleTest extends BaseTestSupport {

    private TestParams params;

    public GenerateOpenSshClientCertificateOracleTest(TestParams params) {
        super();
        this.params = params;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<? extends TestParams> privateKeyParams() {
        return Arrays.asList(
                new TestParams("rsa-sha2-256", "user01_rsa_sha2_256_4096"),
                new TestParams("rsa-sha2-512", "user01_rsa_sha2_512_4096"),
                new TestParams("rsa-sha2-512", "user01_ed25519"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_256"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_384"),
                new TestParams("rsa-sha2-512", "user01_ecdsa_521"));
    }

    protected String getCAPrivateKeyResource() {
        return "org/apache/sshd/client/opensshcerts/ca/ca";
    }

    protected String getClientPrivateKeyResource() {
        return "org/apache/sshd/client/opensshcerts/user/" + params.privateKey;
    }

    protected String getClientPublicKeyResource() {
        return getClientPrivateKeyResource() + ".pub";
    }

    protected String getOracle() {
        return getClientPrivateKeyResource() + "-cert.pub";
    }

    protected PublicKey readPublicKeyFromResource(String resource) throws Exception {
        try (InputStream clientPublicKeyInputStream
                = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)) {
            final byte[] clientPublicKeyBytes = IoUtils.toByteArray(clientPublicKeyInputStream);
            final String clientPublicKeyLine
                    = GenericUtils.replaceWhitespaceAndTrim(new String(clientPublicKeyBytes, StandardCharsets.UTF_8));
            final PublicKeyEntry clientPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(clientPublicKeyLine);
            return clientPublicKeyEntry.resolvePublicKey(null, null, null);
        }
    }

    protected OpenSshCertificate readOpenSshCertificate(String data) throws Exception {

        final String certLine = GenericUtils.replaceWhitespaceAndTrim(data);

        final PublicKeyEntry certPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(certLine);
        final PublicKey certPublicKey = certPublicKeyEntry.resolvePublicKey(null, null, null);

        if (!(certPublicKey instanceof OpenSshCertificate)) {
            fail("Failed to decode a OpenSshCertificate from string data expected to be an OpenSSH Certificate");
        }

        return (OpenSshCertificate) certPublicKey;
    }

    protected OpenSshCertificate readCertificateOracle() throws Exception {
        PublicKey cert = readPublicKeyFromResource(getOracle());
        assertObjectInstanceOf("Must be OpenSshCertificate instance", OpenSshCertificate.class, cert);
        return (OpenSshCertificate) cert;
    }

    @Test
    public void signCertificate() throws Exception {

        final PublicKey clientPublicKey = readPublicKeyFromResource(getClientPublicKeyResource());
        final OpenSshCertificate oracle = readCertificateOracle();

        final String caName = getCAPrivateKeyResource();
        final FileKeyPairProvider keyPairProvider
                = CommonTestSupportUtils.createTestKeyPairProvider(caName);

        final KeyPair caKeypair = keyPairProvider.loadKeys(null).iterator().next();

        final OpenSshCertificate signedCert = OpenSshCertificateBuilder.userCertificate()
                .serial(0L)
                .publicKey(clientPublicKey)
                .id("user01")
                .principals(Collections.singletonList("user01"))
                .nonce(oracle.getNonce())
                .extensions(Arrays.asList(
                        new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-pty"),
                        new OpenSshCertificate.CertificateOption("permit-user-rc")))
                .sign(caKeypair, params.algorithm);

        // Check that they both validate
        verifySignature(signedCert, params.algorithm);
        verifySignature(oracle, params.algorithm);
        assertCertsEqual(oracle, signedCert);
    }

    private void verifySignature(OpenSshCertificate cert, String signatureAlgorithm) throws Exception {
        PublicKey signatureKey = cert.getCaPubKey();
        String keyAlg = KeyUtils.getKeyType(signatureKey);
        String sigAlg = cert.getSignatureAlgorithm();
        assertTrue("Invalid signature algorithm " + sigAlg + " for key " + keyAlg,
                KeyUtils.getAllEquivalentKeyTypes(keyAlg).contains(sigAlg));
        if (signatureAlgorithm != null) {
            assertEquals("Unexpected signature algorithm", signatureAlgorithm, sigAlg);
        }
        Signature verif = NamedFactory.create(BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE, sigAlg);
        verif.initVerifier(null, signatureKey);
        verif.update(null, cert.getMessage());
        assertTrue("Signature should validate", verif.verify(null, cert.getSignature()));
    }

    private static void assertCertsEqual(OpenSshCertificate o1, OpenSshCertificate o2) {
        assertEquals(o1.getSerial(), o2.getSerial());
        assertEquals(o1.getType(), o2.getType());
        assertEquals(o1.getKeyType(), o2.getKeyType());
        assertArrayEquals(o1.getNonce(), o2.getNonce());
        assertEquals(o1.getCertPubKey(), o2.getCertPubKey());
        assertEquals(o1.getId(), o2.getId());
        assertEquals(o1.getPrincipals(), o2.getPrincipals());
        assertEquals(o1.getValidAfter(), o2.getValidAfter());
        assertEquals(o1.getValidBefore(), o2.getValidBefore());
        assertEquals(o1.getCriticalOptions(), o2.getCriticalOptions());
        assertEquals(o1.getExtensions(), o2.getExtensions());
        assertEquals(o1.getReserved(), o2.getReserved());
        assertEquals(o1.getCaPubKey(), o2.getCaPubKey());
        assertEquals(o1.getSignatureAlgorithm(), o2.getSignatureAlgorithm());
        assertArrayEquals(o1.getSignature(), o2.getSignature());
        assertArrayEquals(o1.getMessage(), o2.getMessage());
    }

    private static class TestParams {

        final String privateKey;
        final String algorithm;

        TestParams(String algo, String privateKey) {
            this.algorithm = algo;
            this.privateKey = privateKey;
        }

        @Override
        public String toString() {
            return "TestParams{algo='" + algorithm + "', privateKey='" + privateKey + "'}";
        }
    }
}
