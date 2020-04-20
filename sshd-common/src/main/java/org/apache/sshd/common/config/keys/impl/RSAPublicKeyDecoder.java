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

package org.apache.sshd.common.config.keys.impl;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RSAPublicKeyDecoder extends AbstractPublicKeyEntryDecoder<RSAPublicKey, RSAPrivateKey> {
    public static final RSAPublicKeyDecoder INSTANCE = new RSAPublicKeyDecoder();

    public RSAPublicKeyDecoder() {
        super(RSAPublicKey.class, RSAPrivateKey.class,
              Collections.unmodifiableList(
                      Arrays.asList(KeyPairProvider.SSH_RSA,
                              // Not really required, but allow it
                              KeyUtils.RSA_SHA256_KEY_TYPE_ALIAS,
                              KeyUtils.RSA_SHA512_KEY_TYPE_ALIAS)));
    }

    @Override
    public RSAPublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        // Not really required, but allow it
        String canonicalName = KeyUtils.getCanonicalKeyType(keyType);
        if (!KeyPairProvider.SSH_RSA.equals(canonicalName)) { // just in case we were invoked directly
            throw new InvalidKeySpecException("Unexpected key type: " + keyType);
        }

        BigInteger e = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger n = KeyEntryResolver.decodeBigInt(keyData);

        return generatePublicKey(new RSAPublicKeySpec(n, e));
    }

    @Override
    public String encodePublicKey(OutputStream s, RSAPublicKey key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");
        KeyEntryResolver.encodeString(s, KeyPairProvider.SSH_RSA);
        KeyEntryResolver.encodeBigInt(s, key.getPublicExponent());
        KeyEntryResolver.encodeBigInt(s, key.getModulus());

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
