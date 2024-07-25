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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
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
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class PEMGeneratorHostKeyProviderTest extends JUnitTestSupport {
    public PEMGeneratorHostKeyProviderTest() {
        super();
    }

    @Test
    void dsa() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        testPEMGeneratorHostKeyProvider(KeyUtils.DSS_ALGORITHM, KeyPairProvider.SSH_DSS, 512, null);
    }

    @Test
    void rsa() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        testPEMGeneratorHostKeyProvider(KeyUtils.RSA_ALGORITHM, KeyPairProvider.SSH_RSA, 512, null);
    }

    @Test
    void eCnistp256() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp256.isSupported(), ECCurves.nistp256 + " N/A");
        testPEMGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP256, -1,
                new ECGenParameterSpec("prime256v1"));
    }

    @Test
    void eCnistp384() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp384.isSupported(), ECCurves.nistp384 + " N/A");
        testPEMGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP384, -1,
                new ECGenParameterSpec("P-384"));
    }

    @Test
    void eCnistp521() throws IOException, GeneralSecurityException {
        Assumptions.assumeTrue(SecurityUtils.isBouncyCastleRegistered(), "BouncyCastle not registered");
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        Assumptions.assumeTrue(ECCurves.nistp521.isSupported(), ECCurves.nistp521 + " N/A");
        testPEMGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP521, -1,
                new ECGenParameterSpec("P-521"));
    }

    private Path testPEMGeneratorHostKeyProvider(
            String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec)
            throws IOException, GeneralSecurityException {
        Path path = initKeyFileLocation(algorithm);
        KeyPair kpWrite = invokePEMGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertTrue(Files.exists(path, IoUtils.EMPTY_LINK_OPTIONS), "Key file not generated: " + path);

        KeyPair kpRead = invokePEMGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        PublicKey pubWrite = kpWrite.getPublic();
        PublicKey pubRead = kpRead.getPublic();
        if (pubWrite instanceof ECPublicKey) {
            // The algorithm is reported as ECDSA instead of EC
            assertECPublicKeyEquals("Mismatched EC public key", ECPublicKey.class.cast(pubWrite),
                    ECPublicKey.class.cast(pubRead));
        } else {
            assertKeyEquals("Mismatched public keys", pubWrite, pubRead);
        }
        return path;
    }

    private static KeyPair invokePEMGeneratorHostKeyProvider(
            Path path, String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec)
            throws IOException, GeneralSecurityException {
        AbstractGeneratorHostKeyProvider provider
                = SecurityUtils.createGeneratorHostKeyProvider(path.toAbsolutePath().normalize());
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

    private static KeyPair validateKeyPairProvider(KeyPairProvider provider, String keyType)
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
        Path path = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        path = path.resolve(algorithm + "-PEM.key");
        Files.deleteIfExists(path);
        return path;
    }
}
