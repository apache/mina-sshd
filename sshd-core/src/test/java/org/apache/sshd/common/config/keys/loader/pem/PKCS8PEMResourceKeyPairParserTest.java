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
package org.apache.sshd.common.config.keys.loader.pem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.commons.ssl.PEMItem;
import org.apache.commons.ssl.PEMUtil;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
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
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PKCS8PEMResourceKeyPairParserTest extends BaseTestSupport {
    private final String algorithm;
    private final int keySize;

    public PKCS8PEMResourceKeyPairParserTest(String algorithm, int keySize) {
        this.algorithm = algorithm;
        this.keySize = keySize;
    }

    @Parameters(name = "{0} / {1}")
    public static List<Object[]> parameters() {
        return Collections.unmodifiableList(new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCases(KeyUtils.RSA_ALGORITHM, RSA_SIZES);
                addTestCases(KeyUtils.DSS_ALGORITHM, DSS_SIZES);
                // TODO add test cases for ECDSA
            }

            private void addTestCases(String algorithm, Collection<Integer> keySizes) {
                for (Integer ks : keySizes) {
                    add(new Object[]{algorithm, ks});
                }
            }
        });
    }

    @Test   // see SSHD-760
    public void testPkcs8() throws IOException, GeneralSecurityException {
        KeyPairGenerator generator = SecurityUtils.getKeyPairGenerator(algorithm);
        if (keySize > 0) {
            generator.initialize(keySize);
        }
        KeyPair kp = generator.generateKeyPair();

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            Collection<Object> items = new ArrayList<>();
            PrivateKey prv1 = kp.getPrivate();
            items.add(new PEMItem(prv1.getEncoded(), "PRIVATE KEY"));
            byte[] bytes = PEMUtil.encode(items);
            os.write(bytes);
            os.close();

            try (ByteArrayInputStream bais = new ByteArrayInputStream(os.toByteArray())) {
                KeyPair kp2 = SecurityUtils.loadKeyPairIdentity(getCurrentTestName(), bais, null);

                assertEquals("Mismatched public key", kp.getPublic(), kp2.getPublic());
                assertEquals("Mismatched private key", prv1, kp2.getPrivate());
            }
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + algorithm + "/" + keySize + "]";
    }
}
