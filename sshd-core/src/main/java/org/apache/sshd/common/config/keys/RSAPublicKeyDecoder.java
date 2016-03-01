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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RSAPublicKeyDecoder extends AbstractPublicKeyEntryDecoder<RSAPublicKey, RSAPrivateKey> {
    public static final RSAPublicKeyDecoder INSTANCE = new RSAPublicKeyDecoder();

    public RSAPublicKeyDecoder() {
        super(RSAPublicKey.class, RSAPrivateKey.class, Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_RSA)));
    }

    @Override
    public RSAPublicKey decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_RSA.equals(keyType)) { // just in case we were invoked directly
            throw new InvalidKeySpecException("Unepected key type: " + keyType);
        }

        BigInteger e = decodeBigInt(keyData);
        BigInteger n = decodeBigInt(keyData);

        return generatePublicKey(new RSAPublicKeySpec(n, e));
    }

    @Override
    public String encodePublicKey(OutputStream s, RSAPublicKey key) throws IOException {
        ValidateUtils.checkNotNull(key, "No public key provided");
        encodeString(s, KeyPairProvider.SSH_RSA);
        encodeBigInt(s, key.getPublicExponent());
        encodeBigInt(s, key.getModulus());

        return KeyPairProvider.SSH_RSA;
    }

    @Override
    public RSAPublicKey clonePublicKey(RSAPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePublicKey(new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent()));
        }
    }

    @Override
    public RSAPrivateKey clonePrivateKey(RSAPrivateKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        }

        if (!(key instanceof RSAPrivateCrtKey)) {
            throw new InvalidKeyException("Cannot clone a non-RSAPrivateCrtKey: " + key.getClass().getSimpleName());
        }

        RSAPrivateCrtKey rsaPrv = (RSAPrivateCrtKey) key;
        return generatePrivateKey(
                new RSAPrivateCrtKeySpec(
                        rsaPrv.getModulus(),
                        rsaPrv.getPublicExponent(),
                        rsaPrv.getPrivateExponent(),
                        rsaPrv.getPrimeP(),
                        rsaPrv.getPrimeQ(),
                        rsaPrv.getPrimeExponentP(),
                        rsaPrv.getPrimeExponentQ(),
                        rsaPrv.getCrtCoefficient()));
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(KeyUtils.RSA_ALGORITHM);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyUtils.RSA_ALGORITHM);
    }
}
