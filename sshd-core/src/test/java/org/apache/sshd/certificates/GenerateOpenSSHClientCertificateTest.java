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

import java.io.ByteArrayOutputStream;
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
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
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
public class GenerateOpenSSHClientCertificateTest extends BaseTestSupport {

    private TestParams params;

    public GenerateOpenSSHClientCertificateTest(TestParams params) {
        super();
        this.params = params;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<? extends TestParams> privateKeyParams() {
        return Arrays.asList(
                new TestParams("ca_rsa2_256", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_rsa2_256", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_rsa2_256", "user01_ed25519"), new TestParams("ca_rsa2_256", "user01_ecdsa_256"),
                new TestParams("ca_rsa2_256", "user01_ecdsa_384"), new TestParams("ca_rsa2_256", "user01_ecdsa_521"),

                new TestParams("ca_rsa2_512", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_rsa2_512", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_rsa2_512", "user01_ed25519"), new TestParams("ca_rsa2_512", "user01_ecdsa_256"),
                new TestParams("ca_rsa2_512", "user01_ecdsa_384"), new TestParams("ca_rsa2_512", "user01_ecdsa_521"),

                new TestParams("ca_ed25519", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_ed25519", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_ed25519", "user01_ed25519"), new TestParams("ca_ed25519", "user01_ecdsa_256"),
                new TestParams("ca_ed25519", "user01_ecdsa_384"), new TestParams("ca_ed25519", "user01_ecdsa_521"),

                new TestParams("ca_ecdsa_256", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_ecdsa_256", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_ecdsa_256", "user01_ed25519"), new TestParams("ca_ecdsa_256", "user01_ecdsa_256"),
                new TestParams("ca_ecdsa_256", "user01_ecdsa_384"), new TestParams("ca_ecdsa_256", "user01_ecdsa_521"),

                new TestParams("ca_ecdsa_384", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_ecdsa_384", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_ecdsa_384", "user01_ed25519"), new TestParams("ca_ecdsa_384", "user01_ecdsa_256"),
                new TestParams("ca_ecdsa_384", "user01_ecdsa_384"), new TestParams("ca_ecdsa_384", "user01_ecdsa_521"),

                new TestParams("ca_ecdsa_521", "user01_rsa_sha2_256_4096"),
                new TestParams("ca_ecdsa_521", "user01_rsa_sha2_512_4096"),
                new TestParams("ca_ecdsa_521", "user01_ed25519"), new TestParams("ca_ecdsa_521", "user01_ecdsa_256"),
                new TestParams("ca_ecdsa_521", "user01_ecdsa_384"), new TestParams("ca_ecdsa_521", "user01_ecdsa_521"));
    }

    protected String getCAPrivateKeyResource() {
        return "org/apache/sshd/client/opensshcerts/ca/" + params.caPrivateKey;
    }

    protected String getCAPublicKeyResource() {
        return getCAPrivateKeyResource() + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
    }

    protected String getClientPrivateKeyResource() {
        return "org/apache/sshd/client/opensshcerts/user/" + params.privateKey;
    }

    protected String getClientPublicKeyResource() {
        return getClientPrivateKeyResource() + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
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

    @Test
    public void signCertificate() throws Exception {

        final PublicKey clientPublicKey = readPublicKeyFromResource(getClientPublicKeyResource());

        final String caName = getCAPrivateKeyResource();
        final FileKeyPairProvider keyPairProvider
                = CommonTestSupportUtils.createTestKeyPairProvider(caName);

        final KeyPair caKeypair = keyPairProvider.loadKeys(null).iterator().next();

        String signatureAlgorithm = null;
        int i = caName.indexOf("rsa2_");
        if (i > 0) {
            signatureAlgorithm = "rsa-sha2-" + caName.substring(i + 5);
        }
        final OpenSshCertificate signedCert = OpenSshCertificateBuilder.userCertificate()
                .serial(0L)
                .publicKey(clientPublicKey)
                .id("user01")
                .principals(Collections.singletonList("user01"))
                .criticalOptions(Arrays.asList(
                        new OpenSshCertificate.CertificateOption("force-command", "/path/to/script.sh"),
                        new OpenSshCertificate.CertificateOption("source-address", "127.0.0.1/32"),
                        new OpenSshCertificate.CertificateOption("verify-required")))
                .extensions(Arrays.asList(
                        new OpenSshCertificate.CertificateOption("no-touch-required"),
                        new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
                        new OpenSshCertificate.CertificateOption("permit-pty"),
                        new OpenSshCertificate.CertificateOption("permit-user-rc")))
                .sign(caKeypair, signatureAlgorithm);

        // encode to ssh public key format
        final OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writer.writePublicKey(signedCert, "user01", baos);
        final String encodedCertData = new String(baos.toByteArray(), StandardCharsets.UTF_8);

        // now, decode and check for equality
        final OpenSshCertificate decodedCert = readOpenSshCertificate(encodedCertData);

        // Check that they both validate
        verifySignature(signedCert, signatureAlgorithm);
        verifySignature(decodedCert, signatureAlgorithm);
        assertCertsEqual(signedCert, decodedCert);
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

        final String caPrivateKey;
        final String privateKey;

        TestParams(String caPrivateKey, String privateKey) {
            this.caPrivateKey = caPrivateKey;
            this.privateKey = privateKey;
        }

        @Override
        public String toString() {
            return "TestParams{" +
                   "caPrivateKey='" + caPrivateKey + '\'' +
                   ", privateKey='" + privateKey + '\'' +
                   '}';
        }
    }
}
