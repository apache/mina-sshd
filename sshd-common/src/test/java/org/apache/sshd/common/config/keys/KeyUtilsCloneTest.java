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

package org.apache.sshd.common.config.keys;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class KeyUtilsCloneTest extends JUnitTestSupport {
    private String keyType;
    private int keySize;

    public void initKeyUtilsCloneTest(String keyType, int keySize) {
        this.keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified");
        this.keySize = keySize;
    }

    public static List<Object[]> parameters() {
        List<Object[]> list = new ArrayList<>();
        addTests(list, KeyPairProvider.SSH_DSS, DSS_SIZES);
        addTests(list, KeyPairProvider.SSH_RSA, RSA_SIZES);
        if (SecurityUtils.isECCSupported()) {
            for (ECCurves curve : ECCurves.VALUES) {
                if (!curve.isSupported()) {
                    continue;
                }
                addTests(list, curve.getKeyType(), Collections.singletonList(curve.getKeySize()));
            }
        }
        if (SecurityUtils.isEDDSACurveSupported()) {
            addTests(list, KeyPairProvider.SSH_ED25519, ED25519_SIZES);
        }
        return Collections.unmodifiableList(list);
    }

    private static void addTests(List<Object[]> list, String keyType, Collection<Integer> sizes) {
        for (Integer keySize : sizes) {
            list.add(new Object[] { keyType, keySize });
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, size={1}")
    @SuppressWarnings("checkstyle:avoidnestedblocks")
    public void keyPairCloning(String keyType, int keySize) throws GeneralSecurityException {
        initKeyUtilsCloneTest(keyType, keySize);
        outputDebugMessage("generateKeyPair(%s)[%d]", keyType, keySize);
        KeyPair original = KeyUtils.generateKeyPair(keyType, keySize);

        outputDebugMessage("cloneKeyPair(%s)[%d]", keyType, keySize);
        KeyPair cloned = KeyUtils.cloneKeyPair(keyType, original);

        String prefix = keyType + "[" + keySize + "]";
        assertNotSame(original, cloned, prefix + ": Key pair not cloned");
        assertTrue(KeyUtils.compareKeyPairs(original, cloned), prefix + ": Cloned pair not equals");

        {
            PublicKey k1 = original.getPublic();
            PublicKey k2 = cloned.getPublic();
            assertNotSame(k1, k2, prefix + ": Public key not cloned");
            assertTrue(KeyUtils.compareKeys(k1, k2), prefix + ": Cloned public key not equals");

            String f1 = KeyUtils.getFingerPrint(k1);
            String f2 = KeyUtils.getFingerPrint(k2);
            assertEquals(f1, f2, prefix + ": Mismatched fingerprints");
        }

        {
            PrivateKey k1 = original.getPrivate();
            PrivateKey k2 = cloned.getPrivate();
            assertNotSame(k1, k2, prefix + ": Private key not cloned");
            assertTrue(KeyUtils.compareKeys(k1, k2), prefix + ": Cloned private key not equals");
        }
    }
}
