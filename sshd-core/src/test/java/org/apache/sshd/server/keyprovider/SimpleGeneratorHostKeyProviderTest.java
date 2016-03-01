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
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.BaseTestSupport;
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
public class SimpleGeneratorHostKeyProviderTest extends BaseTestSupport {
    public SimpleGeneratorHostKeyProviderTest() {
        super();
    }

    @Test
    public void testDSA() throws IOException {
        testSimpleGeneratorHostKeyProvider(KeyUtils.DSS_ALGORITHM, KeyPairProvider.SSH_DSS, 512, null);
    }

    @Test
    public void testRSA() throws IOException {
        testSimpleGeneratorHostKeyProvider(KeyUtils.RSA_ALGORITHM, KeyPairProvider.SSH_RSA, 512, null);
    }

    @Test
    public void testECnistp256() throws IOException {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP256, -1, new ECGenParameterSpec("prime256v1"));
    }

    @Test
    public void testECnistp384() throws IOException {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP384, -1, new ECGenParameterSpec("P-384"));
    }

    @Test
    public void testECnistp521() throws IOException {
        Assume.assumeTrue("BouncyCastle not registered", SecurityUtils.isBouncyCastleRegistered());
        testSimpleGeneratorHostKeyProvider(KeyUtils.EC_ALGORITHM, KeyPairProvider.ECDSA_SHA2_NISTP521, -1, new ECGenParameterSpec("P-521"));
    }

    private Path testSimpleGeneratorHostKeyProvider(String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec) throws IOException {
        Path path = initKeyFileLocation(algorithm);
        KeyPair kpWrite = invokeSimpleGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertTrue("Key file not generated: " + path, Files.exists(path, IoUtils.EMPTY_LINK_OPTIONS));

        KeyPair kpRead = invokeSimpleGeneratorHostKeyProvider(path, algorithm, keyType, keySize, keySpec);
        assertKeyPairEquals("Mismatched write/read key pairs", kpWrite, kpRead);
        return path;
    }

    private static KeyPair invokeSimpleGeneratorHostKeyProvider(Path path, String algorithm, String keyType, int keySize, AlgorithmParameterSpec keySpec) {
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

    private Path initKeyFileLocation(String algorithm) throws IOException {
        Path path = assertHierarchyTargetFolderExists(getTempTargetRelativeFile(getClass().getSimpleName()));
        path = path.resolve(algorithm + "-simple.key");
        Files.deleteIfExists(path);
        return path;
    }
}
