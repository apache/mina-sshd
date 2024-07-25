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
package org.apache.sshd.common.util.security.eddsa;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import net.i2p.crypto.eddsa.EdDSAEngine;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class EDDSAProviderTest extends JUnitTestSupport {
    private static KeyPair keyPair;

    public EDDSAProviderTest() {
        super();
    }

    @BeforeAll
    static void checkProviderSupported() throws GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        KeyPairGenerator g = SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
        assertNotNull(g, "No generator instance");

        keyPair = g.generateKeyPair();
        assertNotNull(keyPair, "No key pair generated");

        PublicKey pubKey = keyPair.getPublic();
        assertNotNull(pubKey, "No public key");
        assertEquals(SecurityUtils.EDDSA, pubKey.getAlgorithm(), "Mismatched public key algorithm");
        assertEquals(KeyPairProvider.SSH_ED25519, KeyUtils.getKeyType(pubKey), "Mismatched public key type");

        PrivateKey prvKey = keyPair.getPrivate();
        assertNotNull(prvKey, "No private key");
        assertEquals(pubKey.getAlgorithm(), prvKey.getAlgorithm(), "Mismatched key-pair algorithm");
        assertEquals(KeyPairProvider.SSH_ED25519, KeyUtils.getKeyType(prvKey), "Mismatched private key type");
    }

    @Test
    void signature() throws GeneralSecurityException {
        Signature s = SecurityUtils.getSignature(EdDSAEngine.SIGNATURE_ALGORITHM);
        assertNotNull(s, "No signature instance");
        s.initSign(keyPair.getPrivate());

        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        s.update(data);
        byte[] signed = s.sign();

        s = SecurityUtils.getSignature(EdDSAEngine.SIGNATURE_ALGORITHM);
        s.initVerify(keyPair.getPublic());
        s.update(data);
        assertTrue(s.verify(signed), "Failed to verify");
    }

    @Test
    void publicKeyEntryDecoder() throws IOException, GeneralSecurityException {
        String comment = getCurrentTestName() + "@" + getClass().getSimpleName();
        String expected = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPKSUTyz1HwHReFVvD5obVsALAgJRNarH4TRpNePnAS " + comment;
        AuthorizedKeyEntry keyEntry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(expected);
        assertNotNull(keyEntry, "No extracted key entry");

        assertEquals(KeyPairProvider.SSH_ED25519, keyEntry.getKeyType(), "Mismatched key type");
        assertEquals(comment, keyEntry.getComment(), "Mismatched comment");

        StringBuilder sb = new StringBuilder(expected.length());
        PublicKey pubKey = keyEntry.appendPublicKey(null, sb, null);
        assertEquals(expected, sb.toString(), "Mismatched encoded result");

        testPublicKeyRecovery(pubKey);
    }

    @Test
    void generatedPublicKeyRecovery() throws IOException, GeneralSecurityException {
        testPublicKeyRecovery(keyPair.getPublic());
    }

    private void testPublicKeyRecovery(PublicKey pubKey) throws IOException, GeneralSecurityException {
        assertNotNull(pubKey, "No public key generated");
        assertEquals(SecurityUtils.EDDSA, pubKey.getAlgorithm(), "Mismatched public key algorithm");

        ByteArrayBuffer buf = new ByteArrayBuffer();
        buf.putRawPublicKey(pubKey);
        PublicKey actual = buf.getRawPublicKey();
        assertEquals(pubKey.getAlgorithm(), actual.getAlgorithm(), "Mismatched key algorithm");
        assertEquals(pubKey, actual, "Mismatched recovered key");
    }
}
