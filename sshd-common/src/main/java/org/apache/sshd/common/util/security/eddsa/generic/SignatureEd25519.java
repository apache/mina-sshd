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
package org.apache.sshd.common.util.security.eddsa.generic;

import java.security.SignatureException;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.AbstractSignature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * An ed25519 signature.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureEd25519 extends AbstractSignature {

    // See https://www.rfc-editor.org/rfc/rfc7748.html#section-4.1
    // 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed; little-endian
    private static final int[] ED25519_ORDER = { //
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, //
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 //
    };

    public SignatureEd25519() {
        super(SecurityUtils.ED25519, KeyPairProvider.SSH_ED25519);
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        byte[] data = sig;
        Map.Entry<String, byte[]> encoding = extractEncodedSignature(data, KeyPairProvider.SSH_ED25519::equalsIgnoreCase);
        if (encoding != null) {
            String keyType = encoding.getKey();
            ValidateUtils.checkTrue(KeyPairProvider.SSH_ED25519.equals(keyType), "Mismatched key type: %s", keyType);
            data = encoding.getValue();
        }

        return doVerify(data);
    }

    @Override
    protected boolean doVerify(byte[] data) throws SignatureException {
        java.security.Signature verifier = Objects.requireNonNull(getSignature(), "Signature not initialized");
        if (SecurityUtils.EDDSA.equals(verifier.getProvider().getName())) {
            // Fix CVE 2020-36843 in net.i2p.crypto.eddsa 0.3.0: check that s is in the range [0 .. L), where
            // L is the order.
            //
            // Note: Wikipedia says 0 < S < L. https://en.wikipedia.org/w/index.php?title=EdDSA&oldid=1304068429
            // RFC 8032 says 0 <= S < L. https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7
            //
            // We stick to RFC 8032 here.
            if (data.length != 64 || !isValidFactor(data)) {
                return false;
            }
        }
        return verifier.verify(data);
    }

    private static boolean isValidFactor(byte[] sig) {
        // Must be strictly smaller than the field order (little-endian).
        for (int i = 31; i >= 0; i--) {
            int y = (sig[i + 32] & 0xFF) - ED25519_ORDER[i];
            if (y != 0) {
                return y < 0;
            }
        }
        return false;
    }

}
