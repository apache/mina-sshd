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
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Map;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * RSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-6.6">RFC4253 section 6.6</A>
 */
public abstract class SignatureRSA extends AbstractSignature {
    private int verifierSignatureSize = -1;

    protected SignatureRSA(String algorithm) {
        super(algorithm);
    }

    /**
     * @return The expected number of bytes in the signature - non-positive
     * if not initialized or not intended to be used for verification
     */
    protected int getVerifierSignatureSize() {
        return verifierSignatureSize;
    }

    @Override
    public void initVerifier(SessionContext session, PublicKey key) throws Exception {
        super.initVerifier(session, key);
        RSAKey rsaKey = ValidateUtils.checkInstanceOf(key, RSAKey.class, "Not an RSA key");
        verifierSignatureSize = getVerifierSignatureSize(rsaKey);
    }

    public static int getVerifierSignatureSize(RSAKey key) {
        BigInteger modulus = key.getModulus();
        return (modulus.bitLength() + Byte.SIZE - 1) / Byte.SIZE;
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        byte[] data = sig;
        Map.Entry<String, byte[]> encoding = extractEncodedSignature(data);
        if (encoding != null) {
            String keyType = encoding.getKey();
            /*
             * According to https://tools.ietf.org/html/rfc8332#section-3.2:
             *
             *      OpenSSH 7.2 (but not 7.2p2) incorrectly encodes the algorithm in the
             *      signature as "ssh-rsa" when the algorithm in SSH_MSG_USERAUTH_REQUEST
             *      is "rsa-sha2-256" or "rsa-sha2-512".  In this case, the signature
             *      does actually use either SHA-256 or SHA-512.  A server MAY, but is
             *      not required to, accept this variant or another variant that
             *      corresponds to a good-faith implementation and is considered safe to accept.
             */
            String canonicalName = KeyUtils.getCanonicalKeyType(keyType);
            ValidateUtils.checkTrue(KeyPairProvider.SSH_RSA.equals(canonicalName), "Mismatched key type: %s", keyType);
            data = encoding.getValue();
        }

        int expectedSize = getVerifierSignatureSize();
        ValidateUtils.checkTrue(expectedSize > 0, "Signature verification size has not been initialized");
        // Pad with zero if value is trimmed
        if (data.length < expectedSize) {
            byte[] pad = new byte[expectedSize];
            System.arraycopy(data, 0, pad, pad.length - data.length, data.length);
            data = pad;
        }

        return doVerify(data);
    }
}
