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

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;

import java.security.PublicKey;
import java.security.interfaces.RSAKey;

/**
 * RSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://tools.ietf.org/html/rfc4253#section-6.6">RFC4253 section 6.6</A>
 */
public class SignatureRSA extends AbstractSignature {
    public static final String DEFAULT_ALGORITHM = "SHA1withRSA";

    private int verifierSingatureSize = -1;

    public SignatureRSA() {
        super(DEFAULT_ALGORITHM);
    }

    protected SignatureRSA(String algorithm) {
        super(algorithm);
    }

    @Override
    public byte[] sign() throws Exception {
        return signature.sign();
    }

    @Override
    public void initVerifier(PublicKey key) throws Exception {
        super.initVerifier(key);
        verifierSingatureSize = (((RSAKey)key).getModulus().bitLength() + Byte.SIZE - 1) / Byte.SIZE;
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

        ValidateUtils.checkTrue(verifierSingatureSize > 0, "Signature size should be initialized");
        if (data.length < verifierSingatureSize) {
            byte[] pad = new byte[verifierSingatureSize];
            System.arraycopy(data, 0, pad, pad.length - data.length, data.length);
            data = pad;
        }

        return doVerify(data);
    }

}
