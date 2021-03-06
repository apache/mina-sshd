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
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class LegacyDSASignerTest extends JUnitTestSupport {
    private final int keySize;
    private final KeyPair kp;

    public LegacyDSASignerTest(int keySize)
                                            throws IOException, GeneralSecurityException {
        this.keySize = keySize;

        String resourceName = KeyPairProvider.SSH_DSS + "-" + keySize;
        URL url = getClass().getResource(resourceName);
        assertNotNull("Missing test key file " + resourceName, url);

        Collection<KeyPair> keys = DSSPEMResourceKeyPairParser.INSTANCE.loadKeyPairs(null, url, null);
        ValidateUtils.checkNotNullAndNotEmpty(keys, "No keys loaded from %s", resourceName);
        kp = GenericUtils.head(keys);

        int l = KeyUtils.getKeySize(kp.getPublic());
        assertEquals("Mismatched read public key size", keySize, l);

        l = KeyUtils.getKeySize(kp.getPrivate());
        assertEquals("mismatched read private key size", keySize, l);
    }

    @Parameters(name = "key-size={0}")
    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList(1024, 2048));
    }

    @Test
    public void testReflexiveSigning() throws GeneralSecurityException {
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

    @Test
    public void testBuiltinVerifier() throws GeneralSecurityException {
        Assume.assumeTrue("Skip SHA-1 with too large a key", keySize <= 1024);

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

    @Test
    public void testBuiltinSigner() throws GeneralSecurityException {
        Assume.assumeTrue("Skip SHA-1 with too large a key", keySize <= 1024);

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
