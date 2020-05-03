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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
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
public class OpenSSHDSSPrivateKeyEntryDecoder extends AbstractPrivateKeyEntryDecoder<DSAPublicKey, DSAPrivateKey> {
    public static final OpenSSHDSSPrivateKeyEntryDecoder INSTANCE = new OpenSSHDSSPrivateKeyEntryDecoder();

    public OpenSSHDSSPrivateKeyEntryDecoder() {
        super(DSAPublicKey.class, DSAPrivateKey.class,
              Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_DSS)));
    }

    @Override
    public DSAPrivateKey decodePrivateKey(
            SessionContext session, String keyType, FilePasswordProvider passwordProvider, InputStream keyData)
            throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_DSS.equals(keyType)) { // just in case we were invoked directly
            throw new InvalidKeySpecException("Unexpected key type: " + keyType);
        }

        BigInteger p = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger q = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger g = KeyEntryResolver.decodeBigInt(keyData);
        BigInteger y = KeyEntryResolver.decodeBigInt(keyData);
        Objects.requireNonNull(y, "No public key data"); // TODO run some validation on it
        BigInteger x = KeyEntryResolver.decodeBigInt(keyData);

        try {
            return generatePrivateKey(new DSAPrivateKeySpec(x, p, q, g));
        } finally {
            // get rid of sensitive data a.s.a.p
            p = null;
            q = null;
            g = null;
            y = null;
            x = null;
        }
    }

    @Override
    public String encodePrivateKey(SecureByteArrayOutputStream s, DSAPrivateKey key, DSAPublicKey pubKey) throws IOException {
        Objects.requireNonNull(key, "No private key provided");

        DSAParams keyParams = Objects.requireNonNull(key.getParams(), "No DSA params available");
        BigInteger p = keyParams.getP();
        KeyEntryResolver.encodeBigInt(s, p);
        KeyEntryResolver.encodeBigInt(s, keyParams.getQ());

        BigInteger g = keyParams.getG();
        KeyEntryResolver.encodeBigInt(s, g);

        BigInteger x = key.getX();
        BigInteger y = pubKey != null ? pubKey.getY() : g.modPow(x, p);
        KeyEntryResolver.encodeBigInt(s, y);
        KeyEntryResolver.encodeBigInt(s, x);
        return KeyPairProvider.SSH_DSS;
    }

    @Override
    public boolean isPublicKeyRecoverySupported() {
        return true;
    }

    @Override
    public DSAPublicKey recoverPublicKey(DSAPrivateKey privateKey) throws GeneralSecurityException {
        return KeyUtils.recoverDSAPublicKey(privateKey);
    }

    @Override
    public DSAPublicKey clonePublicKey(DSAPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        }

        DSAParams params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePublicKey(new DSAPublicKeySpec(key.getY(), params.getP(), params.getQ(), params.getG()));
    }

    @Override
    public DSAPrivateKey clonePrivateKey(DSAPrivateKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        }

        DSAParams params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePrivateKey(new DSAPrivateKeySpec(key.getX(), params.getP(), params.getQ(), params.getG()));
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(KeyUtils.DSS_ALGORITHM);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyUtils.DSS_ALGORITHM);
    }
}
