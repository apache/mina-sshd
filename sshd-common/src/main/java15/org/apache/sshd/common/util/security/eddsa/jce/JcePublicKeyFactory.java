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
package org.apache.sshd.common.util.security.eddsa.jce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.EdECKey;
import java.security.spec.NamedParameterSpec;

import org.apache.sshd.common.util.security.PublicKeyFactory;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSAUtils;
import org.bouncycastle.util.Arrays;

public class JcePublicKeyFactory implements PublicKeyFactory {

    public JcePublicKeyFactory() {
        super();
    }

    @Override
    public PublicKey getPublicKey(PrivateKey key) {
        if (SecurityUtils.EDDSA.equals(key.getAlgorithm()) && (key instanceof EdECKey)) {
            NamedParameterSpec params = ((EdECKey) key).getParams();
            return recoverEd25519PublicKey(key, params);
        }
        return null;
    }

    private static PublicKey recoverEd25519PublicKey(PrivateKey key, NamedParameterSpec params) {
        byte[] rawPrivateKey = EdDSAUtils.getBytes(key);
        // An EdDSA private key is just cryptographically secure random data, which the JDK implementation obtains from
        // the given SecureRandom. By making that random generator return not new random bytes but the bytes of the
        // existing private key, the library will then compute the public key for this private key.
        //
        // This relies on the library using the returned "random" value as-is for the private key. Theoretically a
        // library would be free to process these random bytes in any way it wants before setting it as private key.
        // Since any such post-processing of the random value runs the risk of introducing weaknesses through
        // inadvertently loosing some randomness properties of the originally cryptographically secure random data, it
        // is unlikely that an EdDSA implementation would do so, and in any case the JDK implementation doesn't.
        //
        // All this is just a hack to work around sun.security.ec.ed.EdDSAOperations.computePublic() not being
        // accessible.
        //
        // Note that NamedParameterSpec was introduced in Java 11, and the ED25519 constant in Java 15.
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(params.getName());
            gen.initialize(params, new SecureRandom() {

                private static final long serialVersionUID = 1L;

                @Override
                public void nextBytes(byte[] bytes) {
                    if (bytes.length != rawPrivateKey.length) {
                        throw new IllegalStateException(
                                "Wrong array length requested; expected " + rawPrivateKey.length + " but got " + bytes.length);
                    }
                    System.arraycopy(rawPrivateKey, 0, bytes, 0, rawPrivateKey.length);
                }
            });
            return gen.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            return null;
        } finally {
            Arrays.fill(rawPrivateKey, (byte) 0);
        }

    }
}
