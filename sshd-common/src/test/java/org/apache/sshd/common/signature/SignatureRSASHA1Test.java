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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SignatureRSASHA1Test extends JUnitTestSupport {
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();
    @SuppressWarnings("checkstyle:linelength")
    private static final byte[] TEST_MSG = B64_DECODER.decode(
            "AAAAFPHgK1MeV9zNnok3pwNJhCd8SONqMgAAAAlidWlsZHVzZXIAAAAOc3NoLWNvbm5lY3Rpb24AAAAJcHVibGlja2V5AQAAAAdzc2gtcnNhAAABFQAAAAdzc2gtcnNhAAAAASMAAAEBAMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=");
    @SuppressWarnings("checkstyle:linelength")
    private static final byte[] TEST_SIGNATURE = B64_DECODER.decode(
            "AAAAB3NzaC1yc2EAAAD/+Ntnf4qfr2J1voDS6I+u3VRjtMn+LdWJsAZfkLDxRkK1rQxP7QAjLdNqpT4CkWHp8dtoTGFlBFt6NieNJCMTA2KSOxJMZKsX7e/lHkh7C+vhQvJ9eLTKWjCxSFUrcM0NvFhmwbRCffwXSHvAKak4wbmofxQMpd+G4jZkNMz5kGpmeICBcNjRLPb7oXzuGr/g4x/3ge5Qaawqrg/gcZr/sKN6SdE8SszgKYO0SB320N4gcUoShVdLYr9uwdJ+kJoobfkUK6Or171JCctP/cu2nM79lDqVnJw/2jOG8OnTc8zRDXAh0RKoR5rOU8cOHm0Ls2MATsFdnyRU5FGUxqZ+");
    private static PublicKey testKey;

    public SignatureRSASHA1Test() {
        super();
    }

    @BeforeClass
    public static void initializeTestKey() throws GeneralSecurityException {
        byte[] exp = B64_DECODER.decode("Iw==");
        @SuppressWarnings("checkstyle:linelength")
        byte[] mod = B64_DECODER.decode(
                "AMs9HO/NH/Now+6fSnESebaG4wzaYQWA1b/q1TGV1wHNtCg9fGFGVSKs0VxKF4cfVyrSLtgLjnlXQTn+Lm7xiYKGbBbsTQWOqEDaBVBsRbAkxIkpuvr6/EBxwrtDbKmSQYTJZVJSD2bZRYjGsR9gpZXPorOOKFd5EPCMHXsqnhp2hidTGH7cK6RuLk7MNnPISsY0Nbx8/ZvikiPROGcoTZ8bzUv4IaLr3veW6epSeQem8tJqhnrpTHhbLU99zf045M0Gsnk/azjjlBM+qrHZ5FNdC1kowJnLtf2Oy/rUQNpkGJtcBPT8xvreV0wLsn9t3hSxzsc0+VkDNTQRlfU+o3M=");
        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.RSA_ALGORITHM);
        testKey = kf.generatePublic(new RSAPublicKeySpec(new BigInteger(mod), new BigInteger(exp)));
    }

    @Test // see SSHD-642
    public void testLeadingZeroesBC() throws Throwable {
        testLeadingZeroes(new Factory<SignatureRSA>() {
            @Override
            public SignatureRSA create() {
                return new SignatureRSASHA1() {
                    @Override
                    protected java.security.Signature doInitSignature(
                            SessionContext session, String algo, Key key, boolean forSigning)
                            throws GeneralSecurityException {
                        assertFalse("Signature not initialized for verification", forSigning);
                        java.security.Signature signature = super.doInitSignature(session, algo, key, forSigning);
                        if (SecurityUtils.isBouncyCastleRegistered()) {
                            Provider provider = signature.getProvider();
                            String name = provider.getName();
                            assertEquals("Mismatched BC provider name", SecurityUtils.BOUNCY_CASTLE, name);
                        }
                        return signature;
                    }
                };
            }
        });
    }

    @Test // see SSHD-642
    public void testLeadingZeroesJCE() throws Throwable {
        testLeadingZeroes(() -> new SignatureRSASHA1() {
            @Override
            protected java.security.Signature doInitSignature(
                    SessionContext session, String algo, Key key, boolean forSigning)
                    throws GeneralSecurityException {
                assertFalse("Signature not initialized for verification", forSigning);
                java.security.Signature signature = java.security.Signature.getInstance(algo);
                Provider provider = signature.getProvider();
                String name = provider.getName();
                assertNotEquals("BC provider used although not required", SecurityUtils.BOUNCY_CASTLE, name);
                return signature;
            }
        });
    }

    private void testLeadingZeroes(Factory<? extends SignatureRSA> factory) throws Exception {
        SignatureRSA rsa = factory.create();
        rsa.initVerifier(null, testKey);

        int vSize = rsa.getVerifierSignatureSize();
        assertTrue("Verifier signature size not initialized", vSize > 0);

        // make sure padding is required
        Map.Entry<String, byte[]> encoding = rsa.extractEncodedSignature(
                TEST_SIGNATURE, SignatureRSA.SUPPORTED_KEY_TYPES);
        assertNotNull("Signature is not encoded", encoding);
        byte[] data = encoding.getValue();
        assertTrue("Signature data size (" + data.length + ") not below verifier size (" + vSize + ")", data.length < vSize);

        rsa.update(null, TEST_MSG);
        assertTrue("Failed to verify", rsa.verify(null, TEST_SIGNATURE));
    }
}
