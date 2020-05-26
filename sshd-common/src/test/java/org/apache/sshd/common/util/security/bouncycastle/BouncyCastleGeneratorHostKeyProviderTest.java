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

package org.apache.sshd.common.util.security.bouncycastle;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class BouncyCastleGeneratorHostKeyProviderTest extends JUnitTestSupport {
    private final String keyType;
    private final int keySize;

    public BouncyCastleGeneratorHostKeyProviderTest(String keyType, int keySize) {
        this.keyType = keyType;
        this.keySize = keySize;
    }

    @Parameters(name = "{0} / {1}")
    public static List<Object[]> parameters() {
        if (!SecurityUtils.isBouncyCastleRegistered()) {
            return Collections.emptyList();
        }

        List<Object[]> params = new ArrayList<>();
        for (Integer ks : RSA_SIZES) {
            params.add(new Object[] { BuiltinIdentities.Constants.RSA, ks });
        }
        for (Integer ks : DSS_SIZES) {
            params.add(new Object[] { BuiltinIdentities.Constants.DSA, ks });
        }

        /*
         * TODO - causes an issue where BC cannot parse its own file if (SecurityUtils.isECCSupported()) { for (ECCurves
         * curve : ECCurves.VALUES) { params.add(new Object[]{BuiltinIdentities.Constants.ECDSA, curve.getKeySize()}); }
         * }
         */
        return params;
    }

    @Test
    public void testKeyReadWrite() throws IOException, GeneralSecurityException {
        KeyPair expected;
        if (BuiltinIdentities.Constants.RSA.equalsIgnoreCase(keyType)) {
            expected = KeyUtils.generateKeyPair(KeyPairProvider.SSH_RSA, keySize);
        } else if (BuiltinIdentities.Constants.DSA.equalsIgnoreCase(keyType)) {
            expected = KeyUtils.generateKeyPair(KeyPairProvider.SSH_DSS, keySize);
        } else if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyType)) {
            ECCurves curve = ECCurves.fromCurveSize(keySize);
            assertNotNull("No curve for key size=" + keySize, curve);
            expected = KeyUtils.generateKeyPair(curve.getKeyType(), curve.getKeySize());
        } else if (BuiltinIdentities.Constants.ED25519.equalsIgnoreCase(keyType)) {
            KeyPairGenerator g = SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
            expected = g.generateKeyPair();
        } else {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        PublicKey key = expected.getPublic();
        String keyAlgorithm = key.getAlgorithm();
        if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyAlgorithm)) {
            keyAlgorithm = KeyUtils.EC_ALGORITHM;
        } else if (BuiltinIdentities.Constants.ED25519.equalsIgnoreCase(keyAlgorithm)) {
            keyAlgorithm = SecurityUtils.EDDSA;
        }

        Path dir = getTempTargetFolder();
        dir = Files.createDirectories(dir.resolve(getClass().getSimpleName()));
        Path file = dir.resolve(keyType + "-" + keySize + ".pem");
        BouncyCastleGeneratorHostKeyProvider.writePEMKeyPair(expected, file);

        AbstractGeneratorHostKeyProvider provider = new BouncyCastleGeneratorHostKeyProvider(file);
        provider.setAlgorithm(keyAlgorithm);

        Iterable<KeyPair> keys = provider.loadKeys(null);
        KeyPair actual = null;
        for (KeyPair k : keys) {
            assertNull("Unexpected multiple keys loaded", actual);
            actual = k;
        }

        assertKeyPairEquals(keyType + "/" + keySize, expected, actual);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + keyType + "/" + keySize + "]";
    }
}
