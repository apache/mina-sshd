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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class EDDSAProviderTest extends JUnitTestSupport {
    private static KeyPair keyPair;

    public EDDSAProviderTest() {
        super();
    }

    @BeforeClass
    public static void checkProviderSupported() throws GeneralSecurityException {
        Assume.assumeTrue(SecurityUtils.EDDSA + " not supported", SecurityUtils.isEDDSACurveSupported());
        KeyPairGenerator g = SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
        assertNotNull("No generator instance", g);

        keyPair = g.generateKeyPair();
        assertNotNull("No key pair generated", keyPair);

        PublicKey pubKey = keyPair.getPublic();
        assertNotNull("No public key", pubKey);
        assertEquals("Mismatched public key algorithm", SecurityUtils.EDDSA, pubKey.getAlgorithm());
        assertEquals("Mismatched public key type", KeyPairProvider.SSH_ED25519, KeyUtils.getKeyType(pubKey));

        PrivateKey prvKey = keyPair.getPrivate();
        assertNotNull("No private key", prvKey);
        assertEquals("Mismatched key-pair algorithm", pubKey.getAlgorithm(), prvKey.getAlgorithm());
        assertEquals("Mismatched private key type", KeyPairProvider.SSH_ED25519, KeyUtils.getKeyType(prvKey));
    }

    @Test
    public void testSignature() throws GeneralSecurityException {
        Signature s = SecurityUtils.getSignature(EdDSAEngine.SIGNATURE_ALGORITHM);
        assertNotNull("No signature instance", s);
        s.initSign(keyPair.getPrivate());

        byte[] data = (getClass().getName() + "#" + getCurrentTestName()).getBytes(StandardCharsets.UTF_8);
        s.update(data);
        byte[] signed = s.sign();

        s = SecurityUtils.getSignature(EdDSAEngine.SIGNATURE_ALGORITHM);
        s.initVerify(keyPair.getPublic());
        s.update(data);
        assertTrue("Failed to verify", s.verify(signed));
    }

    @Test
    public void testPublicKeyEntryDecoder() throws IOException, GeneralSecurityException {
        String comment = getCurrentTestName() + "@" + getClass().getSimpleName();
        String expected = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPKSUTyz1HwHReFVvD5obVsALAgJRNarH4TRpNePnAS " + comment;
        AuthorizedKeyEntry keyEntry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(expected);
        assertNotNull("No extracted key entry", keyEntry);

        assertEquals("Mismatched key type", KeyPairProvider.SSH_ED25519, keyEntry.getKeyType());
        assertEquals("Mismatched comment", comment, keyEntry.getComment());

        StringBuilder sb = new StringBuilder(expected.length());
        PublicKey pubKey = keyEntry.appendPublicKey(null, sb, null);
        assertEquals("Mismatched encoded result", expected, sb.toString());

        testPublicKeyRecovery(pubKey);
    }

    @Test
    public void testGeneratedPublicKeyRecovery() throws IOException, GeneralSecurityException {
        testPublicKeyRecovery(keyPair.getPublic());
    }

    private void testPublicKeyRecovery(PublicKey pubKey) throws IOException, GeneralSecurityException {
        assertNotNull("No public key generated", pubKey);
        assertEquals("Mismatched public key algorithm", SecurityUtils.EDDSA, pubKey.getAlgorithm());

        ByteArrayBuffer buf = new ByteArrayBuffer();
        buf.putRawPublicKey(pubKey);
        PublicKey actual = buf.getRawPublicKey();
        assertEquals("Mismatched key algorithm", pubKey.getAlgorithm(), actual.getAlgorithm());
        assertEquals("Mismatched recovered key", pubKey, actual);
    }
}
