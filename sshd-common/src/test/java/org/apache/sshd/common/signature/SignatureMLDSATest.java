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
package org.apache.sshd.common.signature;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@Tag("NoIoTestCase")
class SignatureMLDSATest extends JUnitTestSupport {
    private static final byte[] DATA = "ML-DSA signature test".getBytes(StandardCharsets.UTF_8);

    SignatureMLDSATest() {
        super();
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void signAndVerify(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        byte[] signature = sign(factory, pair, DATA);
        assertEquals(params.getSignatureSize(), signature.length);
        assertTrue(verify(factory, pair.getPublic(), DATA, signature));
        assertTrue(verify(factory, pair.getPublic(), DATA, encode(params.getSshName(), signature)));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void rejectsTamperedSignatureAndData(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        byte[] signature = sign(factory, pair, DATA);
        for (int pos : new int[] { 0, signature.length / 2, signature.length - 1 }) {
            byte[] tampered = signature.clone();
            tampered[pos] ^= 1;
            assertFalse(verify(factory, pair.getPublic(), DATA, tampered), "Tampered at " + pos);
        }
        byte[] otherData = DATA.clone();
        otherData[0] ^= 1;
        assertFalse(verify(factory, pair.getPublic(), otherData, signature));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void rejectsWrongLengthSignature(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        byte[] signature = sign(factory, pair, DATA);
        assertFalse(verify(factory, pair.getPublic(), DATA, Arrays.copyOf(signature, signature.length - 1)));
        assertFalse(verify(factory, pair.getPublic(), DATA, Arrays.copyOf(signature, signature.length + 1)));
        assertFalse(verify(factory, pair.getPublic(), DATA, new byte[0]));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void rejectsOtherKey(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        byte[] signature = sign(factory, generateKeyPair(params), DATA);
        assertFalse(verify(factory, generateKeyPair(params).getPublic(), DATA, signature));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void rejectsMismatchedKeyType(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        byte[] signature = sign(factory, pair, DATA);
        MLDSAParameterSets other
                = params == MLDSAParameterSets.ML_DSA_44 ? MLDSAParameterSets.ML_DSA_65 : MLDSAParameterSets.ML_DSA_44;
        assertFalse(verify(factory, pair.getPublic(), DATA, encode(other.getSshName(), signature)));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void signatureVerifiesWithEveryProvider(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        byte[] signature = sign(factory, pair, DATA);
        int checked = 0;
        for (String name : new String[] { "SUN", SecurityUtils.BOUNCY_CASTLE }) {
            Provider provider = Security.getProvider(name);
            if (provider == null || provider.getService("Signature", params.getJceName()) == null) {
                continue;
            }
            PublicKey key = KeyFactory.getInstance(params.getJceName(), provider)
                    .generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
            java.security.Signature verifier = java.security.Signature.getInstance(params.getJceName(), provider);
            verifier.initVerify(key);
            verifier.update(DATA);
            assertTrue(verifier.verify(signature), "Not verified by " + name);
            checked++;
        }
        assertTrue(checked > 0, "No provider to check");
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void factoryMatchesPublicKey(MLDSAParameterSets params) throws Exception {
        SignatureFactory factory = factory(params);
        KeyPair pair = generateKeyPair(params);
        assertSame(factory, SignatureFactory.resolveSignatureFactoryByPublicKey(pair.getPublic(), null));
        assertSame(factory, SignatureFactory.resolveSignatureFactoryByPublicKey(pair.getPublic(), params.getSshName()));
    }

    private static SignatureFactory factory(MLDSAParameterSets params) {
        SignatureFactory factory = BuiltinSignatures.fromFactoryName(params.getSshName());
        assertNotNull(factory, "No factory for " + params.getSshName());
        Assumptions.assumeTrue(factory.isSupported(), "Unsupported factory: " + factory);
        return factory;
    }

    private static KeyPair generateKeyPair(MLDSAParameterSets params) throws Exception {
        return SecurityUtils.getKeyPairGenerator(params.getJceName()).generateKeyPair();
    }

    private static byte[] sign(SignatureFactory factory, KeyPair pair, byte[] data) throws Exception {
        Signature signer = factory.create();
        signer.initSigner(null, pair.getPrivate());
        signer.update(null, data);
        return signer.sign(null);
    }

    private static boolean verify(SignatureFactory factory, PublicKey key, byte[] data, byte[] signature)
            throws Exception {
        Signature verifier = factory.create();
        verifier.initVerifier(null, key);
        verifier.update(null, data);
        return verifier.verify(null, signature);
    }

    private static byte[] encode(String keyType, byte[] signature) {
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putString(keyType);
        buffer.putBytes(signature);
        return buffer.getCompactData();
    }
}
