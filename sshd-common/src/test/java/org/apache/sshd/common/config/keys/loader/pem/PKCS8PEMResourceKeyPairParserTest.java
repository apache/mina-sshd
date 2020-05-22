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
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.ssl.PEMItem;
import org.apache.commons.ssl.PEMUtil;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
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
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PKCS8PEMResourceKeyPairParserTest extends JUnitTestSupport {
    private final String algorithm;
    private final int keySize;

    public PKCS8PEMResourceKeyPairParserTest(String algorithm, int keySize) {
        this.algorithm = algorithm;
        this.keySize = keySize;
    }

    @Parameters(name = "{0}-{1}")
    public static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        for (Integer ks : RSA_SIZES) {
            params.add(new Object[] { KeyUtils.RSA_ALGORITHM, ks });
        }
        for (Integer ks : DSS_SIZES) {
            params.add(new Object[] { KeyUtils.DSS_ALGORITHM, ks });
        }
        if (SecurityUtils.isECCSupported()) {
            for (ECCurves curve : ECCurves.VALUES) {
                if (!curve.isSupported()) {
                    outputDebugMessage("Skip unsupported curve=%s", curve);
                    continue;
                }

                params.add(new Object[] { KeyUtils.EC_ALGORITHM, curve.getKeySize() });
            }
        }
        if (SecurityUtils.isEDDSACurveSupported()) {
            params.add(new Object[] { SecurityUtils.EDDSA, 0 });
        }
        return params;
    }

    @Test // see SSHD-760
    public void testLocallyGeneratedPkcs8() throws IOException, GeneralSecurityException {
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
                Iterable<KeyPair> ids = SecurityUtils.loadKeyPairIdentities(
                        null, NamedResource.ofName(getCurrentTestName()), bais, null);
                KeyPair kp2 = GenericUtils.head(ids);
                assertNotNull("No identity loaded", kp2);
                assertKeyEquals("Mismatched public key", kp.getPublic(), kp2.getPublic());
                assertKeyEquals("Mismatched private key", prv1, kp2.getPrivate());
            }
        }
    }

    /*
     * See https://gist.github.com/briansmith/2ee42439923d8e65a266994d0f70180b
     *
     * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out pkcs8-rsa-1024.pem
     * openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out pkcs8-ecdsa-256.pem
     *
     * openssl ecparam -genkey -name prime256v1 -noout -out pkcs8-ec-256.key
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8-ec-256.key -out pkcs8-ec-256.pem
     *
     * openssl genpkey -algorithm ed25519 -out pkcs8-ed25519.pem
     * openssl asn1parse -inform PEM -in ...file... -dump
     */
    @Test // see SSHD-989
    public void testPKCS8FileParsing() throws Exception {
        String baseName = "pkcs8-" + algorithm.toLowerCase();
        String resourceKey = baseName + ((keySize > 0) ? "-" + keySize : "") + ".pem";
        URL url = getClass().getResource(resourceKey);
        Assume.assumeTrue("No test file=" + resourceKey, url != null);

        Collection<KeyPair> pairs = PKCS8PEMResourceKeyPairParser.INSTANCE.loadKeyPairs(null, url, null);
        assertEquals("Mismatched extract keys count", 1, GenericUtils.size(pairs));
        validateKeyPairSignable(algorithm + "/" + keySize, GenericUtils.head(pairs));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + algorithm + "/" + keySize + "]";
    }
}
