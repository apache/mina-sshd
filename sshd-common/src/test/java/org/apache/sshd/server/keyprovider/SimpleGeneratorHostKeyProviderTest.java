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
package org.apache.sshd.server.keyprovider;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
@SuppressWarnings("checksyle:MethodCount")
public class SimpleGeneratorHostKeyProviderTest extends JUnitTestSupport {

    @Test
    void dsa() throws IOException, GeneralSecurityException {
        testSimpleGeneratorHostKeyProvider(KeyUtils.DSS_ALGORITHM, KeyPairProvider.SSH_DSS, 512, null);
    }

    @Test
    void rsa() throws IOException, GeneralSecurityException {
        testSimpleGeneratorHostKeyProvider(KeyUtils.RSA_ALGORITHM, KeyPairProvider.SSH_RSA, 512, null);
    }

    @Test
    void eCnistp256() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp256.isSupported(), ECCurves.nistp256 + " N/A");
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP256, -1,
                new ECGenParameterSpec("prime256v1"));
    }

    @Test
    void eCnistp384() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp384.isSupported(), ECCurves.nistp384 + " N/A");
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP384, -1,
                new ECGenParameterSpec("P-384"));
    }

    @Test
    void eCnistp521() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp521.isSupported(), ECCurves.nistp521 + " N/A");
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP521, -1,
                new ECGenParameterSpec("P-521"));
    }

    @Test
    void edDSA() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isEDDSACurveSupported(), "EdDSA not supported");
        testSimpleGeneratorHostKeyProvider(SecurityUtils.EDDSA, KeyPairProvider.SSH_ED25519, -1, null);
    }

    private void testSimpleGeneratorHostKeyProvider(
            String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec)
            throws IOException, GeneralSecurityException {
        Path path = initKeyFileLocation(algorithm);
        KeyPair kpWrite = invokeSimpleGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertTrue(Files.exists(path, IoUtils.EMPTY_LINK_OPTIONS), "Key file not generated: " + path);

        KeyPair kpRead = invokeSimpleGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertKeyPairEquals("Mismatched write/read key pairs", kpWrite, kpRead);

        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            // Try the old way: use Java serialization. net.i2p EdDSA keys cannot be serialized.
            path = initKeyFileLocation(algorithm, "ser");
            try (ObjectOutputStream out = new ObjectOutputStream(Files.newOutputStream(path))) {
                out.writeObject(kpWrite);
            }
            kpRead = invokeSimpleGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
            assertKeyPairEquals("Mismatched serialized/deserialized key pairs", kpWrite, kpRead);
        }
    }

    private static KeyPair invokeSimpleGeneratorHostKeyProvider(
            Path path, String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec)
            throws IOException, GeneralSecurityException {
        SimpleGeneratorHostKeyProvider provider = new SimpleGeneratorHostKeyProvider();
        provider.setAlgorithm(algorithm);
        provider.setOverwriteAllowed(true);
        provider.setPath(path);
        if (keySize > 0) {
            provider.setKeySize(keySize);
        }
        if (keySpec != null) {
            provider.setKeySpec(keySpec);
        }

        return validateKeyPairProvider(provider, keyType);
    }

    private static KeyPair validateKeyPairProvider(
            KeyPairProvider provider, String keyType)
            throws IOException, GeneralSecurityException {
        Iterable<String> types = provider.getKeyTypes(null);
        KeyPair kp = null;
        for (String type : types) {
            if (keyType.equals(type)) {
                kp = provider.loadKey(null, keyType);
                assertNotNull(kp, "Failed to load key for " + keyType);
                break;
            }
        }

        assertNotNull(kp, "Expected key type not found: " + keyType);
        return kp;
    }

    private Path initKeyFileLocation(String algorithm) throws IOException {
        return initKeyFileLocation(algorithm, "key");
    }

    private Path initKeyFileLocation(String algorithm, String extension) throws IOException {
        Path path = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        path = path.resolve(algorithm + "-simple." + extension);
        Files.deleteIfExists(path);
        return path;
    }
}
