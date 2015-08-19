/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.keyprovider;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PEMGeneratorHostKeyProviderTest extends BaseTestSupport {

    @Test
    public void testDSA() {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testPEMGeneratorHostKeyProvider("DSA", KeyPairProvider.SSH_DSS, 512, null);
    }

    @Test
    public void testRSA() {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testPEMGeneratorHostKeyProvider("RSA", KeyPairProvider.SSH_RSA, 512, null);
    }

    @Test
    public void testEC_NISTP256() {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        Assume.assumeTrue("ECC not supported", SecurityUtils.hasEcc());
        testPEMGeneratorHostKeyProvider("EC", KeyPairProvider.ECDSA_SHA2_NISTP256, -1, new ECGenParameterSpec("prime256v1"));
    }

    @Test
    public void testEC_NISTP384() {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        Assume.assumeTrue("ECC not supported", SecurityUtils.hasEcc());
        testPEMGeneratorHostKeyProvider("EC", KeyPairProvider.ECDSA_SHA2_NISTP384, -1, new ECGenParameterSpec("P-384"));
    }

    @Test
    public void testEC_NISTP521() {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        Assume.assumeTrue("ECC not supported", SecurityUtils.hasEcc());
        testPEMGeneratorHostKeyProvider("EC", KeyPairProvider.ECDSA_SHA2_NISTP521, -1, new ECGenParameterSpec("P-521"));
    }

    private File testPEMGeneratorHostKeyProvider(String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec) {
        File path = initKeyFileLocation(algorithm);
        KeyPair kpWrite = invokePEMGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertTrue("Key file not generated: " + path.getAbsolutePath(), path.exists());

        KeyPair kpRead = invokePEMGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        PublicKey pubWrite = kpWrite.getPublic(), pubRead = kpRead.getPublic();
        if (pubWrite instanceof ECPublicKey) {
            // The algorithm is reported as ECDSA instead of EC
            assertECPublicKeyEquals("Mismatched EC public key", ECPublicKey.class.cast(pubWrite), ECPublicKey.class.cast(pubRead));
        } else {
            assertKeyEquals("Mismatched public keys", pubWrite, pubRead);
        }
        return path;
    }

    private static KeyPair invokePEMGeneratorHostKeyProvider(File path, String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec) {
        AbstractGeneratorHostKeyProvider provider = SecurityUtils.createGeneratorHostKeyProvider(path.toPath().toAbsolutePath());
        provider.setAlgorithm(algorithm);
        provider.setOverwriteAllowed(true);
        if (keySize > 0) {
            provider.setKeySize(keySize);
        }
        if (keySpec != null) {
            provider.setKeySpec(keySpec);
        }

        return validateKeyPairProvider(provider, keyType);
    }

    private static KeyPair validateKeyPairProvider(KeyPairProvider provider, String keyType) {
        Iterable<String> types = provider.getKeyTypes();
        KeyPair kp = null;
        for (String type : types) {
            if (keyType.equals(type)) {
                kp = provider.loadKey(keyType);
                assertNotNull("Failed to load key for " + keyType, kp);
                break;
            }
        }

        assertNotNull("Expected key type not found: " + keyType, kp);
        return kp;
    }

    private File initKeyFileLocation(String algorithm) {
        File path = new File(detectTargetFolder(), "keys");
        if (!path.exists()) {
            assertTrue("Failed to crearte hierarchy of " + path.getAbsolutePath(), path.mkdirs());
        }

        path = new File(path, algorithm + "-PEM.key");
        if (path.exists()) {
            assertTrue("Failed to delete test key file: " + path.getAbsolutePath(), path.delete());
        }

        return path;
    }
}
