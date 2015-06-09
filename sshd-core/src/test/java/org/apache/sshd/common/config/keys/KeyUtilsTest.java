/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.config.keys;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyUtilsTest extends BaseTestSupport {
    private static int[] DSS_SIZES = { 512, 768, 1024 };
    private static int[] RSA_SIZES = { 1024, 2048, 3072, 4096 };

    public KeyUtilsTest() {
        super();
    }

    @Test
    public void testGenerateRSAKeyPairs() throws GeneralSecurityException {
        GeneralSecurityException err = null;
        for (int keySize : RSA_SIZES) {
            try {
                KeyPair kp = generateKeyPair(KeyPairProvider.SSH_RSA, keySize);
                testKeyPairCloning(KeyPairProvider.SSH_RSA, keySize, kp);
            } catch(GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }
        
        if (err != null) {
            throw err;
        }
    }

    @Test
    public void testGenerateDSSKeyPairs() throws GeneralSecurityException {
        GeneralSecurityException err = null;
        for (int keySize : DSS_SIZES) {
            try {
                KeyPair kp = generateKeyPair(KeyPairProvider.SSH_DSS, keySize);
                testKeyPairCloning(KeyPairProvider.SSH_DSS, keySize, kp);
            } catch(GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }
        
        if (err != null) {
            throw err;
        }
    }

    @Test
    public void testGenerateECDSAKeyPairs() throws GeneralSecurityException {
        Assume.assumeTrue("No ECC support", SecurityUtils.hasEcc());

        GeneralSecurityException err = null;
        for (String curveName : ECCurves.NAMES) {
            Integer keySize = ECCurves.getCurveSize(curveName);
            try {
                String keyType = ECCurves.ECDSA_SHA2_PREFIX + curveName;
                KeyPair kp = generateKeyPair(keyType, keySize.intValue());
                testKeyPairCloning(keyType, keySize.intValue(), kp);
            } catch(GeneralSecurityException e) {
                err = GenericUtils.accumulateException(err, e);
            }
        }
        
        if (err != null) {
            throw err;
        }
    }

    private static KeyPair generateKeyPair(String keyType, int keySize) throws GeneralSecurityException {
        try {
            System.out.println("generateKeyPair(" + keyType + ")[" + keySize + "]");
            return KeyUtils.generateKeyPair(keyType, keySize);
        } catch(GeneralSecurityException e) {
            System.err.println("Failed (" + e.getClass().getSimpleName() + ") to generate key-pair for " + keyType + "/" + keySize + ": " + e.getMessage());
            throw e;
        }
    }
    
    private static void testKeyPairCloning(String keyType, int keySize, KeyPair kp) throws GeneralSecurityException {
        String prefix = keyType + "[" + keySize + "]";
        System.out.println("testKeyPairCloning(" + prefix + ")");

        KeyPair cloned = KeyUtils.cloneKeyPair(keyType, kp);
        assertNotSame(prefix + ": Key pair not cloned", kp, cloned);
        assertTrue(prefix + ": Cloned pair not equals", KeyUtils.compareKeyPairs(kp, cloned));
        
        {
            PublicKey k1 = kp.getPublic(), k2 = cloned.getPublic();
            assertNotSame(prefix + ": Public key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned public key not equals", KeyUtils.compareKeys(k1, k2));
            
            String f1 = KeyUtils.getFingerPrint(k1), f2 = KeyUtils.getFingerPrint(k2);
            assertEquals(prefix + ": Mismatched fingerprints", f1, f2);
        }
        
        {
            PrivateKey k1 = kp.getPrivate(), k2 = cloned.getPrivate();
            assertNotSame(prefix + ": Private key not cloned", k1, k2);
            assertTrue(prefix + ": Cloned private key not equals", KeyUtils.compareKeys(k1, k2));
        }
    }

}
