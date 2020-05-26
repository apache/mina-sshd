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
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.u2f.SkED25519PublicKey;
import org.apache.sshd.common.util.security.eddsa.Ed25519PublicKeyDecoder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SkED25519PublicKeyEntryDecoder extends AbstractPublicKeyEntryDecoder<SkED25519PublicKey, PrivateKey> {
    public static final String KEY_TYPE = "sk-ssh-ed25519@openssh.com";
    public static final int MAX_APP_NAME_LENGTH = 1024;

    public static final SkED25519PublicKeyEntryDecoder INSTANCE = new SkED25519PublicKeyEntryDecoder();

    private static final String NO_TOUCH_REQUIRED_HEADER = "no-touch-required";

    public SkED25519PublicKeyEntryDecoder() {
        super(SkED25519PublicKey.class, PrivateKey.class, Collections.singleton(KEY_TYPE));
    }

    @Override
    public SkED25519PublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (!KEY_TYPE.equals(keyType)) {
            throw new InvalidKeySpecException("Invalid keyType: " + keyType);
        }

        boolean noTouchRequired = parseBooleanHeader(headers, NO_TOUCH_REQUIRED_HEADER, false);
        EdDSAPublicKey edDSAPublicKey
                = Ed25519PublicKeyDecoder.INSTANCE.decodePublicKey(session, KeyPairProvider.SSH_ED25519, keyData, headers);
        String appName = KeyEntryResolver.decodeString(keyData, MAX_APP_NAME_LENGTH);
        return new SkED25519PublicKey(appName, noTouchRequired, edDSAPublicKey);
    }

    @Override
    public SkED25519PublicKey clonePublicKey(SkED25519PublicKey key) {
        if (key == null) {
            return null;
        }

        return new SkED25519PublicKey(key.getAppName(), key.isNoTouchRequired(), key.getDelegatePublicKey());
    }

    @Override
    public String encodePublicKey(OutputStream s, SkED25519PublicKey key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");
        KeyEntryResolver.encodeString(s, KEY_TYPE);
        byte[] seed = Ed25519PublicKeyDecoder.getSeedValue(key.getDelegatePublicKey());
        KeyEntryResolver.writeRLEBytes(s, seed);
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
