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
public class KeyUtilsCloneTest extends JUnitTestSupport {
    private final String keyType;
    private final int keySize;

    public KeyUtilsCloneTest(String keyType, int keySize) {
        this.keyType = ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified");
        this.keySize = keySize;
    }

    @Parameters(name = "type={0}, size={1}")
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

    @Test
    @SuppressWarnings("checkstyle:avoidnestedblocks")
    public void testKeyPairCloning() throws GeneralSecurityException {
        outputDebugMessage("generateKeyPair(%s)[%d]", keyType, keySize);
        KeyPair original = KeyUtils.generateKeyPair(keyType, keySize);

        outputDebugMessage("cloneKeyPair(%s)[%d]", keyType, keySize);
        KeyPair cloned = KeyUtils.cloneKeyPair(keyType, original);

        String prefix = keyType + "[" + keySize + "]";
        assertNotSame(prefix + ": Key pair not cloned", original, cloned);
        assertTrue(prefix + ": Cloned pair not equals", KeyUtils.compareKeyPairs(original, cloned));

        {
            PublicKey k1 = original.getPublic();
            PublicKey k2 = cloned.getPublic();
            assertNotSame(prefix + ": Public key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned public key not equals", KeyUtils.compareKeys(k1, k2));

            String f1 = KeyUtils.getFingerPrint(k1);
            String f2 = KeyUtils.getFingerPrint(k2);
            assertEquals(prefix + ": Mismatched fingerprints", f1, f2);
        }

        {
            PrivateKey k1 = original.getPrivate();
            PrivateKey k2 = cloned.getPrivate();
            assertNotSame(prefix + ": Private key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned private key not equals", KeyUtils.compareKeys(k1, k2));
        }
    }
}
