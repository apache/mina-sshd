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

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * RSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-6.6">RFC4253 section 6.6</A>
 */
public class SignatureRSA extends AbstractSignature {
    public static final String DEFAULT_ALGORITHM = "SHA1withRSA";

    private int verifierSignatureSize = -1;

    public SignatureRSA() {
        super(DEFAULT_ALGORITHM);
    }

    protected SignatureRSA(String algorithm) {
        super(algorithm);
    }

    @Override
    public byte[] sign() throws Exception {
        java.security.Signature signature = ValidateUtils.checkNotNull(getSignature(), "Signature not initialized");
        return signature.sign();
    }

    /**
     * @return The expected number of bytes in the signature - non-positive
     * if not initialized or not intended to be used for verification
     */
    protected int getVerifierSignatureSize() {
        return verifierSignatureSize;
    }

    @Override
    public void initVerifier(PublicKey key) throws Exception {
        super.initVerifier(key);
        ValidateUtils.checkTrue(key instanceof RSAKey, "Not an RSA key");
        verifierSignatureSize = getVerifierSignatureSize((RSAKey) key);
    }

    public static int getVerifierSignatureSize(RSAKey key) {
        BigInteger modulus = key.getModulus();
        return (modulus.bitLength() + Byte.SIZE - 1) / Byte.SIZE;
    }

    @Override
    public boolean verify(byte[] sig) throws Exception {
        byte[] data = sig;
        Pair<String, byte[]> encoding = extractEncodedSignature(data);
        if (encoding != null) {
            String keyType = encoding.getFirst();
            ValidateUtils.checkTrue(KeyPairProvider.SSH_RSA.equals(keyType), "Mismatched key type: %s", keyType);
            data = encoding.getSecond();
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
