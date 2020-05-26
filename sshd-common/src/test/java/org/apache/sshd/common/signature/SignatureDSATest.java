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
import java.security.spec.DSAPublicKeySpec;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class SignatureDSATest extends JUnitTestSupport {
    public SignatureDSATest() {
        super();
    }

    @Test
    public void testTooShortSignature() throws Exception {
        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.DSS_ALGORITHM);
        SignatureDSA signatureDSA = new SignatureDSA(KeyUtils.DSS_ALGORITHM) {
            @Override
            protected java.security.Signature doInitSignature(
                    SessionContext session, String algo, Key key, boolean forSigning)
                    throws GeneralSecurityException {
                return java.security.Signature.getInstance(algo);

            }
        };

        byte[] y = new byte[] {
                0, -92, 59, 5, 72, 124, 101, 124, -18, 114, 7, 100, 98, -61, 73, -104,
                120, -98, 54, 118, 17, -62, 91, -110, 29, 98, 50, -101, -41, 99, -116,
                101, 107, -123, 124, -97, 62, 119, 88, -109, -110, -1, 109, 119, -51,
                69, -98, -105, 2, -69, -121, -82, -118, 23, -6, 96, -61, -65, 102, -58,
                -74, 32, -104, 116, -6, -35, -83, -10, -88, -68, 106, -112, 72, -2, 35,
                38, 15, -11, -22, 30, -114, -46, -47, -18, -17, -71, 24, -25, 28, 13, 29,
                -40, 101, 18, 81, 45, -120, -67, -53, -41, 11, 50, -89, -33, 50, 54, -14,
                -91, -35, 12, -42, 13, -84, -19, 100, -3, -85, -18, 74, 99, -49, 64, -49,
                51, -83, -82, -127, 116, 64 };
        byte[] p = new byte[] {
                0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28,
                -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38,
                105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70,
                48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102,
                96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79,
                -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4,
                -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117,
                -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57 };
        byte[] q = new byte[] {
                0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21,
                -124, 11, -16, 88, 28, -11 };
        byte[] g = new byte[] {
                0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87,
                -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126,
                103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76,
                73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31,
                60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117,
                -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52,
                -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6,
                -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42 };

        BigInteger bigY = new BigInteger(y);
        BigInteger bigP = new BigInteger(p);
        BigInteger bigQ = new BigInteger(q);
        BigInteger bigG = new BigInteger(g);

        DSAPublicKeySpec dsaPublicKey = new DSAPublicKeySpec(bigY, bigP, bigQ, bigG);
        signatureDSA.initVerifier(null, kf.generatePublic(dsaPublicKey));
        byte[] h = new byte[] {
                -4, 111, -103, 111, 72, -106, 105, -19, 81, -123, 84, -13, -40, -53, -3,
                -97, -8, 43, -22, -2, -23, -15, 28, 116, -63, 96, -79, -127, -84, 63, -6, -94 };
        signatureDSA.update(null, h);

        byte[] sig_of_h = new byte[] {
                0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, 0, 79,
                84, 118, -50, 11, -117, -112, 52, -25, -78, -50, -20, 6, -69, -26,
                7, 90, -34, -124, 80, 76, -32, -23, -8, 43, 38, -48, -89, -17, -60,
                -1, -78, 112, -88, 14, -39, -78, -98, -80 };
        boolean verified = signatureDSA.verify(null, sig_of_h);

        assertTrue(verified);
    }
}
