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

package org.apache.sshd.common.config.keys.loader.openssh;

import java.io.IOException;
import java.io.InputStream;
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
import java.util.Objects;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.impl.AbstractPrivateKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.SecureByteArrayOutputStream;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHRSAPrivateKeyDecoder extends AbstractPrivateKeyEntryDecoder<RSAPublicKey, RSAPrivateKey> {
    public static final BigInteger DEFAULT_PUBLIC_EXPONENT = new BigInteger("65537");
    public static final OpenSSHRSAPrivateKeyDecoder INSTANCE = new OpenSSHRSAPrivateKeyDecoder();

    public OpenSSHRSAPrivateKeyDecoder() {
        super(RSAPublicKey.class, RSAPrivateKey.class,
              Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_RSA)));
    }

    @Override
    public RSAPrivateKey decodePrivateKey(
            SessionContext session, String keyType, FilePasswordProvider passwordProvider, InputStream keyData)
            throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_RSA.equals(keyType)) { // just in case we were invoked directly
            throw new InvalidKeySpecException("Unexpected key type: " + keyType);
        }

        BigInteger n = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger e = KeyEntryResolver.decodeBigInt(keyData);
        if (!Objects.equals(e, DEFAULT_PUBLIC_EXPONENT)) {
            log.warn("decodePrivateKey({}) non-standard RSA exponent found: {}", keyType, e);
        }

        BigInteger d = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger inverseQmodP = KeyEntryResolver.decodeBigInt(keyData);
        Objects.requireNonNull(inverseQmodP, "Missing iqmodp"); // TODO run some validation on it
        BigInteger p = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger q = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger modulus = p.multiply(q);
        if (!Objects.equals(n, modulus)) {
            log.warn("decodePrivateKey({}) mismatched modulus values: encoded={}, calculated={}", keyType, n, modulus);
        }
        try {
            return generatePrivateKey(new RSAPrivateCrtKeySpec(
                    n, e, d, p, q, d.mod(p.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)), inverseQmodP));
        } finally {
            // get rid of sensitive data a.s.a.p
            d = null;
            inverseQmodP = null;
            p = null;
            q = null;
        }
    }

    @Override
    public String encodePrivateKey(SecureByteArrayOutputStream s, RSAPrivateKey key, RSAPublicKey pubKey) throws IOException {
        Objects.requireNonNull(key, "No private key provided");
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey a = (RSAPrivateCrtKey) key;
            KeyEntryResolver.encodeBigInt(s, a.getModulus()); // n
            KeyEntryResolver.encodeBigInt(s, a.getPublicExponent()); // e
            KeyEntryResolver.encodeBigInt(s, a.getPrivateExponent()); // d
            // CRT coefficient q^-1 mod p
            KeyEntryResolver.encodeBigInt(s, a.getCrtCoefficient());
            KeyEntryResolver.encodeBigInt(s, a.getPrimeP()); // p
            KeyEntryResolver.encodeBigInt(s, a.getPrimeQ()); // q
            return KeyPairProvider.SSH_RSA;
        }
        return null;
    }

    @Override
    public boolean isPublicKeyRecoverySupported() {
        return true;
    }

    @Override
    public RSAPublicKey recoverPublicKey(RSAPrivateKey privateKey) throws GeneralSecurityException {
        return KeyUtils.recoverRSAPublicKey(privateKey);
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
