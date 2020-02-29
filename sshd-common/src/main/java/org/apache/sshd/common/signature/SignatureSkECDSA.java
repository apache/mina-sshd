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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class SignatureSkECDSA implements Signature {

    private static final int FLAG_USER_PRESENCE = 0x01;

    private SkEcdsaPublicKey publicKey;
    private MessageDigest challengeDigest;

    public SignatureSkECDSA() {
        // Intentionally empty
    }

    @Override
    public String getAlgorithm() {
        return "SK-ECDSA";
    }

    @Override
    public void initVerifier(SessionContext session, PublicKey key) throws Exception {
        if (!(key instanceof SkEcdsaPublicKey)) {
            throw new IllegalArgumentException("Only instances of SkEcdsaPublicKey can be used");
        }
        this.publicKey = (SkEcdsaPublicKey) key;
        this.challengeDigest = MessageDigest.getInstance("SHA-256");
    }

    @Override
    public void update(SessionContext session, byte[] hash, int off, int len) {
        if (challengeDigest == null) {
            throw new IllegalStateException("initVerifier must be called before update");
        }
        challengeDigest.update(hash, off, len);
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        if (challengeDigest == null) {
            throw new IllegalStateException("initVerifier must be called before verify");
        }

        ByteArrayBuffer data = new ByteArrayBuffer(sig);
        String keyType = data.getString();
        if (!SkECDSAPublicKeyEntryDecoder.KEY_TYPE.equals(keyType)) {
            return false;
        }
        byte[] ecSig = data.getBytes();
        byte flags = data.getByte();
        long counter = data.getUInt();

        // Return false if we don't understand the flags
        if ((flags & ~FLAG_USER_PRESENCE) != 0) {
            return false;
        }
        // Check user-presence flag is present if required by the public key
        if ((flags & FLAG_USER_PRESENCE) != FLAG_USER_PRESENCE && !publicKey.isNoTouchRequired()) {
            return false;
        }

        // Re-encode EC signature in a format to match the delegate
        ByteArrayBuffer encoded = new ByteArrayBuffer();
        encoded.putString(ECCurves.nistp256.getKeyType());
        encoded.putBytes(ecSig);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] appNameDigest = md.digest(publicKey.getAppName().getBytes(StandardCharsets.UTF_8));
        byte[] challengeDigest = this.challengeDigest.digest();
        ByteArrayBuffer counterData = new ByteArrayBuffer(Integer.BYTES, false);
        counterData.putInt(counter);

        Signature delegate = new SignatureECDSA.SignatureECDSA256();
        delegate.initVerifier(session, publicKey.getEcPublicKey());
        delegate.update(session, appNameDigest);
        delegate.update(session, new byte[]{flags});
        delegate.update(session, counterData.getCompactData());
        delegate.update(session, challengeDigest);
        return delegate.verify(session, encoded.getCompactData());
    }

    @Override
    public void initSigner(SessionContext session, PrivateKey key) {
        throw new UnsupportedOperationException("Security key private key signatures are unsupported.");
    }

    @Override
    public byte[] sign(SessionContext session) {
        throw new UnsupportedOperationException("Security key private key signatures are unsupported.");
    }
}
