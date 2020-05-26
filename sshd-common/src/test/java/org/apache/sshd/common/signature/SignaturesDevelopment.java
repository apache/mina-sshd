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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.Ignore;

/**
 * A &quot;scratch-pad&quot; class for testing signatures related code during development
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Ignore("Used only for development")
public class SignaturesDevelopment extends JUnitTestSupport {
    public SignaturesDevelopment() {
        super();
    }

    public static void testSignatureFactory(
            SignatureFactory factory, KeyPair kp, byte[] data, boolean generateSignature, byte[] signature)
            throws Exception {
        Signature signer = factory.create();
        if (generateSignature) {
            signer.initSigner(null, kp.getPrivate());
            signer.update(null, data);
            signature = signer.sign(null);
            System.out.append('\t').append("Signature: ").println(BufferUtils.toHex(':', signature));
        } else {
            signer.initVerifier(null, kp.getPublic());
            signer.update(null, data);
            if (signer.verify(null, signature)) {
                System.out.append('\t').println("Valid signature");
            } else {
                System.err.append('\t').println("Invalid signature");
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////

    // args[0]=signatureName, args[1]=publicKey, args[2]=privateKey, args[3]=sign/verify, args[4]=data,
    // args[5]=signature(if verify required)
    public static void main(String[] args) throws Exception {
        SignatureFactory factory = BuiltinSignatures.resolveFactory(args[0]);
        // TODO recover public/private keys according to factory name
        byte[] publicKey = BufferUtils.decodeHex(':', args[1]);
        PublicKey pubKey = EdDSASecurityProviderUtils.generateEDDSAPublicKey(publicKey);
        byte[] privateKey = BufferUtils.decodeHex(':', args[2]);
        PrivateKey prvKey = EdDSASecurityProviderUtils.generateEDDSAPrivateKey(privateKey);
        String op = args[3];
        byte[] data = BufferUtils.decodeHex(':', args[4]);
        byte[] signature = GenericUtils.EMPTY_BYTE_ARRAY;
        if ("verify".equalsIgnoreCase(op)) {
            signature = BufferUtils.decodeHex(':', args[5]);
        }

        testSignatureFactory(factory, new KeyPair(pubKey, prvKey), data, "sign".equalsIgnoreCase(op), signature);
    }
}
