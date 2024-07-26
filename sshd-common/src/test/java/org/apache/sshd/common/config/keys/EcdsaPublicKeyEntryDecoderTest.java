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

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase") // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class EcdsaPublicKeyEntryDecoderTest extends JUnitTestSupport {
    public static final int TESTS_COUNT
            = Integer.parseInt(System.getProperty(EcdsaPublicKeyEntryDecoderTest.class.getName(), "500"));

    private ECCurves curve;

    public void initEcdsaPublicKeyEntryDecoderTest(ECCurves curve) {
        this.curve = curve;
    }

    public static List<Object[]> parameters() {
        return parameterize(ECCurves.VALUES);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}") // see SSHD-934
    public void encodeDecodePublicKey(ECCurves curve) throws Exception {
        initEcdsaPublicKeyEntryDecoderTest(curve);
        Assumptions.assumeTrue(SecurityUtils.isECCSupported(), "ECC not supported");
        int keySize = curve.getKeySize();
        String keyType = curve.getKeyType();
        for (int index = 1; index <= TESTS_COUNT; index++) {
            if (OUTPUT_DEBUG_MESSAGES && ((index % 50) == 0)) {
                System.out.println(getCurrentTestName() + ": generated " + index + "/" + TESTS_COUNT + " test cases");
            }

            KeyPair keyPair = KeyUtils.generateKeyPair(keyType, keySize);
            PublicKey expected = keyPair.getPublic();
            @SuppressWarnings("unchecked")
            PublicKeyEntryDecoder<PublicKey, ?> decoder
                    = (PublicKeyEntryDecoder<PublicKey, ?>) KeyUtils.getPublicKeyEntryDecoder(expected);
            byte[] encodedPublicKey;
            try (ByteArrayOutputStream ostrm = new ByteArrayOutputStream()) {
                decoder.encodePublicKey(ostrm, expected);
                encodedPublicKey = ostrm.toByteArray();
            }

            PublicKey actual;
            try {
                actual = decoder.decodePublicKey(
                        null, keyType, encodedPublicKey, 0, encodedPublicKey.length, Collections.emptyMap());
            } catch (Exception e) {
                String encData = PublicKeyEntry.toString(expected);
                System.err.append("===> ").println(encData);
                System.err.println("Failed (" + e.getClass().getSimpleName() + ")"
                                   + " to decode at attempt #" + index + ": " + e.getMessage());
                e.printStackTrace(System.err);
                if (OUTPUT_DEBUG_MESSAGES) {
                    continue;
                }
                throw e;
            }

            if (KeyUtils.compareKeys(expected, actual)) {
                continue;
            }

            assertObjectInstanceOf("Mismatched expected key type", ECPublicKey.class, expected);
            ECPublicKey expKey = (ECPublicKey) expected;
            assertObjectInstanceOf("Mismatched actual key type", ECPublicKey.class, actual);
            ECPublicKey actKey = (ECPublicKey) actual;

            assertECPublicKeyEquals("[" + index + "]", expKey, actKey);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + curve + "]";
    }
}
