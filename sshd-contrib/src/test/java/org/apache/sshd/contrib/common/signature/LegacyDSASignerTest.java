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

package org.apache.sshd.contrib.common.signature;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.pem.DSSPEMResourceKeyPairParser;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class LegacyDSASignerTest extends JUnitTestSupport {
    private int keySize;
    private KeyPair kp;

    public void initLegacyDSASignerTest(int keySize)
            throws IOException, GeneralSecurityException {
        this.keySize = keySize;

        String resourceName = KeyPairProvider.SSH_DSS + "-" + keySize;
        URL url = getClass().getResource(resourceName);
        assertNotNull(url, "Missing test key file " + resourceName);

        Collection<KeyPair> keys = DSSPEMResourceKeyPairParser.INSTANCE.loadKeyPairs(null, url, null);
        ValidateUtils.checkNotNullAndNotEmpty(keys, "No keys loaded from %s", resourceName);
        kp = GenericUtils.head(keys);

        int l = KeyUtils.getKeySize(kp.getPublic());
        assertEquals(keySize, l, "Mismatched read public key size");

        l = KeyUtils.getKeySize(kp.getPrivate());
        assertEquals(keySize, l, "mismatched read private key size");
    }

    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList(1024, 2048));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "key-size={0}")
    public void reflexiveSigning(int keySize) throws Exception {
        initLegacyDSASignerTest(keySize);
        java.security.Signature signer = new LegacyDSASigner(JceRandomFactory.INSTANCE);
        signer.initSign(kp.getPrivate());

        byte[] data = (getClass().getName() + "#" + getCurrentTestName())
                .getBytes(StandardCharsets.UTF_8);
        signer.update(data);
        byte[] signature = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(data, 0, data.length);
        assertTrue(signer.verify(signature));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "key-size={0}")
    public void builtinVerifier(int keySize) throws Exception {
        initLegacyDSASignerTest(keySize);
        Assumptions.assumeTrue(keySize <= 1024, "Skip SHA-1 with too large a key");

        java.security.Signature signer = new LegacyDSASigner(JceRandomFactory.INSTANCE);
        signer.initSign(kp.getPrivate());

        byte[] data = (getClass().getName() + "#" + getCurrentTestName())
                .getBytes(StandardCharsets.UTF_8);
        signer.update(data);
        byte[] signature = signer.sign();

        java.security.Signature verifier = SecurityUtils.getSignature(SignatureDSA.DEFAULT_ALGORITHM);
        verifier.initVerify(kp.getPublic());
        verifier.update(data);
        assertTrue(verifier.verify(signature));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "key-size={0}")
    public void builtinSigner(int keySize) throws Exception {
        initLegacyDSASignerTest(keySize);
        Assumptions.assumeTrue(keySize <= 1024, "Skip SHA-1 with too large a key");

        java.security.Signature signer = SecurityUtils.getSignature(SignatureDSA.DEFAULT_ALGORITHM);
        signer.initSign(kp.getPrivate());

        byte[] data = (getClass().getName() + "#" + getCurrentTestName())
                .getBytes(StandardCharsets.UTF_8);
        signer.update(data);
        byte[] signature = signer.sign();

        java.security.Signature verifier = new LegacyDSASigner(JceRandomFactory.INSTANCE);
        verifier.initVerify(kp.getPublic());
        verifier.update(data);
        assertTrue(verifier.verify(signature));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[keySize=" + keySize + "]";
    }
}
