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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.u2f.SkEcdsaPublicKey;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SkECDSAPublicKeyEntryDecoder extends AbstractPublicKeyEntryDecoder<SkEcdsaPublicKey, PrivateKey> {
    public static final String KEY_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com";
    public static final int MAX_APP_NAME_LENGTH = 1024;

    public static final SkECDSAPublicKeyEntryDecoder INSTANCE = new SkECDSAPublicKeyEntryDecoder();

    private static final String NO_TOUCH_REQUIRED_HEADER = "no-touch-required";

    public SkECDSAPublicKeyEntryDecoder() {
        super(SkEcdsaPublicKey.class, PrivateKey.class, Collections.singleton(KEY_TYPE));
    }

    @Override
    public SkEcdsaPublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (!KEY_TYPE.equals(keyType)) {
            throw new InvalidKeySpecException("Invalid keyType: " + keyType);
        }

        boolean noTouchRequired = parseBooleanHeader(headers, NO_TOUCH_REQUIRED_HEADER, false);
        ECPublicKey ecPublicKey = ECDSAPublicKeyEntryDecoder.INSTANCE.decodePublicKey(ECCurves.nistp256, keyData);
        String appName = KeyEntryResolver.decodeString(keyData, MAX_APP_NAME_LENGTH);
        return new SkEcdsaPublicKey(appName, noTouchRequired, ecPublicKey);
    }

    @Override
    public SkEcdsaPublicKey clonePublicKey(SkEcdsaPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        }

        return new SkEcdsaPublicKey(
                key.getAppName(), key.isNoTouchRequired(),
                ECDSAPublicKeyEntryDecoder.INSTANCE.clonePublicKey(key.getDelegatePublicKey()));
    }

    @Override
    public String encodePublicKey(OutputStream s, SkEcdsaPublicKey key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");
        ECDSAPublicKeyEntryDecoder.encodePublicKey(s, KEY_TYPE, ECCurves.nistp256, key.getDelegatePublicKey().getW());
        KeyEntryResolver.encodeString(s, key.getAppName());
        return KEY_TYPE;
    }

    @Override
    public PrivateKey clonePrivateKey(PrivateKey key) {
        throw new UnsupportedOperationException("Private key operations are not supported for security keys.");
    }

    @Override
    public KeyFactory getKeyFactoryInstance() {
        throw new UnsupportedOperationException("Private key operations are not supported for security keys.");
    }

    @Override
    public KeyPair generateKeyPair(int keySize) {
        throw new UnsupportedOperationException("Private key operations are not supported for security keys.");
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() {
        throw new UnsupportedOperationException("Private key operations are not supported for security keys.");
    }
}
