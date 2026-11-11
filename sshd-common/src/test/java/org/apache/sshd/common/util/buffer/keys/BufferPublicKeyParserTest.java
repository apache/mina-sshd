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
package org.apache.sshd.common.util.buffer.keys;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.BufferException;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.mldsa.MLDSAUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@Tag("NoIoTestCase")
class BufferPublicKeyParserTest extends JUnitTestSupport {
    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void defaultParserSupportMatchesProvider(MLDSAParameterSets params) {
        boolean supported = SecurityUtils.isMLDSASupported(params.getJceName());
        assertEquals(supported, MLDSABufferPublicKeyParser.INSTANCE.isKeyTypeSupported(params.getSshName()));
        assertEquals(supported, BufferPublicKeyParser.DEFAULT.isKeyTypeSupported(params.getSshName()));
    }

    @Test
    void unknownTypesAndEmptyParser() {
        for (String type : new String[] { "", "ssh-mldsa-99", "ML-DSA-44", "ssh-unknown" }) {
            assertFalse(MLDSABufferPublicKeyParser.INSTANCE.isKeyTypeSupported(type));
            assertFalse(BufferPublicKeyParser.DEFAULT.isKeyTypeSupported(type));
            assertFalse(BufferPublicKeyParser.EMPTY.isKeyTypeSupported(type));
            assertThrows(NoSuchAlgorithmException.class,
                    () -> BufferPublicKeyParser.DEFAULT.getRawPublicKey(type, new ByteArrayBuffer()));
            assertThrows(InvalidKeySpecException.class,
                    () -> MLDSABufferPublicKeyParser.INSTANCE.getRawPublicKey(type, new ByteArrayBuffer()));
        }
        assertSame(BufferPublicKeyParser.EMPTY, BufferPublicKeyParser.aggregate(Collections.emptyList()));
        assertFalse(MLDSABufferPublicKeyParser.INSTANCE.isKeyTypeSupported(null));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void rawPublicKeyRoundTripAndWireFormat(MLDSAParameterSets params) throws Exception {
        PublicKey key = generatePublicKey(params);
        byte[] expected = MLDSAUtils.getRawBytes(key);
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(key);
        byte[] wire = buffer.getCompactData();

        assertEquals(params.getSshName(), buffer.getString());
        assertArrayEquals(expected, buffer.getBytes());
        assertEquals(0, buffer.available());

        ByteArrayBuffer input = new ByteArrayBuffer(wire);
        PublicKey decoded = input.getRawPublicKey();
        assertArrayEquals(expected, MLDSAUtils.getRawBytes(decoded));
        assertEquals(0, input.available());

        ByteArrayBuffer explicit = new ByteArrayBuffer(wire);
        assertArrayEquals(expected, MLDSAUtils.getRawBytes(
                explicit.getRawPublicKey(MLDSABufferPublicKeyParser.INSTANCE)));
        assertEquals(0, explicit.available());
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void lengthPrefixedPublicKeyRoundTrip(MLDSAParameterSets params) throws Exception {
        PublicKey key = generatePublicKey(params);
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putPublicKey(key);
        buffer.putInt(0x12345678);
        PublicKey decoded = buffer.getPublicKey();
        assertArrayEquals(MLDSAUtils.getRawBytes(key), MLDSAUtils.getRawBytes(decoded));
        assertEquals(0x12345678, buffer.getInt(), "Parser must leave the next field intact");
        assertEquals(0, buffer.available());
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void malformedRawKeys(MLDSAParameterSets params) {
        Assumptions.assumeTrue(SecurityUtils.isMLDSASupported(params.getJceName()), "ML-DSA provider unavailable");
        for (int size : new int[] { 0, params.getPublicKeySize() - 1, params.getPublicKeySize() + 1 }) {
            ByteArrayBuffer buffer = new ByteArrayBuffer();
            buffer.putString(params.getSshName());
            buffer.putBytes(new byte[size]);
            assertThrows(SshException.class, buffer::getRawPublicKey, "Invalid public key size " + size);
        }

        ByteArrayBuffer truncated = new ByteArrayBuffer();
        truncated.putString(params.getSshName());
        truncated.putInt(params.getPublicKeySize());
        truncated.putRawBytes(new byte[params.getPublicKeySize() - 1]);
        assertThrows(SshException.class, truncated::getRawPublicKey);
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSets.class)
    void mismatchedVariantAndTruncatedOuterString(MLDSAParameterSets params) throws Exception {
        PublicKey key = generatePublicKey(params);
        MLDSAParameterSets other
                = params == MLDSAParameterSets.ML_DSA_44 ? MLDSAParameterSets.ML_DSA_65 : MLDSAParameterSets.ML_DSA_44;
        Assumptions.assumeTrue(SecurityUtils.isMLDSASupported(other.getJceName()), "Other variant unavailable");
        ByteArrayBuffer mismatched = new ByteArrayBuffer();
        mismatched.putString(other.getSshName());
        mismatched.putBytes(MLDSAUtils.getRawBytes(key));
        assertThrows(SshException.class, mismatched::getRawPublicKey);

        ByteArrayBuffer encoded = new ByteArrayBuffer();
        encoded.putPublicKey(key);
        byte[] bytes = encoded.getCompactData();
        ByteArrayBuffer truncated = new ByteArrayBuffer(Arrays.copyOf(bytes, bytes.length - 1));
        assertThrows(BufferException.class, truncated::getPublicKey);
    }

    @Test
    void unknownRawType() {
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putString("ssh-mldsa-99");
        buffer.putBytes(new byte[32]);
        assertThrows(SshException.class, buffer::getRawPublicKey);
    }

    private static PublicKey generatePublicKey(MLDSAParameterSets params) throws Exception {
        Assumptions.assumeTrue(SecurityUtils.isMLDSASupported(params.getJceName()), "ML-DSA provider unavailable");
        return SecurityUtils.getKeyPairGenerator(params.getJceName()).generateKeyPair().getPublic();
    }
}
