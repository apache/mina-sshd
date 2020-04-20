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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.AfterClass;
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
public class KeyRandomArtTest extends JUnitTestSupport {
    private static final Collection<KeyPair> KEYS = new LinkedList<>();

    private final String algorithm;
    private final int keySize;
    private final KeyPair keyPair;

    public KeyRandomArtTest(String algorithm, int keySize) throws Exception {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.keyPair = CommonTestSupportUtils.generateKeyPair(algorithm, keySize);
        KEYS.add(this.keyPair);
    }

    @Parameters(name = "algorithm={0}, key-size={1}")
    public static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        for (int keySize : RSA_SIZES) {
            params.add(new Object[] { KeyUtils.RSA_ALGORITHM, keySize });
        }

        for (int keySize : DSS_SIZES) {
            params.add(new Object[] { KeyUtils.DSS_ALGORITHM, keySize });
        }

        if (SecurityUtils.isECCSupported()) {
            for (ECCurves curve : ECCurves.VALUES) {
                params.add(new Object[] { KeyUtils.EC_ALGORITHM, curve.getKeySize() });
            }
        }

        if (SecurityUtils.isEDDSACurveSupported()) {
            for (int keySize : ED25519_SIZES) {
                params.add(new Object[] { SecurityUtils.EDDSA, keySize });
            }
        }
        return params;
    }

    @AfterClass
    public static void dumpAllArts() throws Exception {
        KeyRandomArt.combine(null, System.out, ' ', session -> KEYS);
    }

    @Test
    public void testRandomArtString() throws Exception {
        KeyRandomArt art = new KeyRandomArt(keyPair.getPublic());
        assertEquals("Mismatched algorithm", algorithm, art.getAlgorithm());
        assertEquals("Mismatched key size", keySize, art.getKeySize());

        String s = art.toString();
        String[] lines = GenericUtils.split(s, '\n');
        assertEquals("Mismatched lines count", KeyRandomArt.FLDSIZE_Y + 2, lines.length);

        for (int index = 0; index < lines.length; index++) {
            String l = lines[index];
            if ((l.length() > 0) && (l.charAt(l.length() - 1) == '\r')) {
                l = l.substring(0, l.length() - 1);
                lines[index] = l;
            }
            System.out.append('\t').println(l);

            assertTrue("Mismatched line length #" + (index + 1) + ": " + l.length(),
                    l.length() >= (KeyRandomArt.FLDSIZE_X + 2));
        }
    }
}
