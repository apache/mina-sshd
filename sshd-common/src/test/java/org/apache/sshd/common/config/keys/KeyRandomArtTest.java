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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class KeyRandomArtTest extends JUnitTestSupport {
    private static final Collection<KeyPair> KEYS = new LinkedList<>();

    static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        for (int keySize : RSA_SIZES) {
            params.add(new Object[] { KeyUtils.RSA_ALGORITHM, keySize });
        }

        for (int keySize : DSS_SIZES) {
            params.add(new Object[] { KeyUtils.DSS_ALGORITHM, keySize });
        }

        for (ECCurves curve : ECCurves.VALUES) {
            params.add(new Object[] { KeyUtils.EC_ALGORITHM, curve.getKeySize() });
        }

        if (SecurityUtils.isEDDSACurveSupported()) {
            for (int keySize : ED25519_SIZES) {
                params.add(new Object[] { SecurityUtils.EDDSA, keySize });
            }
        }
        return params;
    }

    @AfterAll
    static void dumpAllArts() throws Exception {
        KeyRandomArt.combine(null, System.out, ' ', session -> KEYS);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "algorithm={0}, key-size={1}")
    void randomArtString(String algorithm, int keySize) throws Exception {
        KeyPair keyPair = CommonTestSupportUtils.generateKeyPair(algorithm, keySize);
        KEYS.add(keyPair);
        KeyRandomArt art = new KeyRandomArt(keyPair.getPublic());
        assertEquals(algorithm, art.getAlgorithm(), "Mismatched algorithm");
        assertEquals(keySize, art.getKeySize(), "Mismatched key size");

        String s = art.toString();
        String[] lines = GenericUtils.split(s, '\n');
        assertEquals(KeyRandomArt.FLDSIZE_Y + 2, lines.length, "Mismatched lines count");

        for (int index = 0; index < lines.length; index++) {
            String l = lines[index];
            if ((l.length() > 0) && (l.charAt(l.length() - 1) == '\r')) {
                l = l.substring(0, l.length() - 1);
                lines[index] = l;
            }
            System.out.append('\t').println(l);

            assertTrue(l.length() >= (KeyRandomArt.FLDSIZE_X + 2),
                    "Mismatched line length #" + (index + 1) + ": " + l.length());
        }
    }
}
