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
package org.apache.sshd.common.util.security.eddsa;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.Ed25519PublicKeyDecoder;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSAUtils;
import org.apache.sshd.common.util.security.eddsa.generic.SignatureEd25519;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EdDSASecurityProviderUtils {
    // See EdDSANamedCurveTable
    public static final int KEY_SIZE = EdDSAUtils.ED25519_LENGTH * Byte.SIZE;

    private EdDSASecurityProviderUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static boolean isEDDSAKey(Key key) {
        return getEDDSAKeySize(key) == KEY_SIZE;
    }

    public static int getEDDSAKeySize(Key key) {
        return (SecurityUtils.isEDDSACurveSupported() && (key instanceof EdDSAKey)) ? KEY_SIZE : -1;
    }

    public static boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            return false;
        }

        if ((k1 instanceof EdDSAPublicKey) && (k2 instanceof EdDSAPublicKey)) {
            if (k1.equals(k2)) {
                return true;
            }

            EdDSAPublicKey ed1 = (EdDSAPublicKey) k1;
            EdDSAPublicKey ed2 = (EdDSAPublicKey) k2;
            return Arrays.equals(ed1.getAbyte(), ed2.getAbyte())
                    && compareEDDSAKeyParams(ed1.getParams(), ed2.getParams());
        }

        return false;
    }

    public static boolean isEDDSASignatureAlgorithm(String algorithm) {
        return EdDSAEngine.SIGNATURE_ALGORITHM.equalsIgnoreCase(algorithm);
    }

    public static EdDSAPublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        ValidateUtils.checkTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        if (!(key instanceof EdDSAPrivateKey)) {
            throw new InvalidKeyException("Private key is not " + SecurityUtils.EDDSA);
        }

        EdDSAPrivateKey prvKey = (EdDSAPrivateKey) key;
        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(prvKey.getAbyte(), prvKey.getParams());
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.ED25519);
        return EdDSAPublicKey.class.cast(factory.generatePublic(keySpec));
    }

    public static org.apache.sshd.common.signature.Signature getEDDSASignature() {
        ValidateUtils.checkTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        return new SignatureEd25519();
    }

    public static PublicKeyEntryDecoder getEDDSAPublicKeyEntryDecoder() {
        ValidateUtils.checkTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        return Ed25519PublicKeyDecoder.INSTANCE;
    }

    public static boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            return false;
        }

        if ((k1 instanceof EdDSAPrivateKey) && (k2 instanceof EdDSAPrivateKey)) {
            if (k1.equals(k2)) {
                return true;
            }

            EdDSAPrivateKey ed1 = (EdDSAPrivateKey) k1;
            EdDSAPrivateKey ed2 = (EdDSAPrivateKey) k2;
            return Arrays.equals(ed1.getSeed(), ed2.getSeed())
                    && compareEDDSAKeyParams(ed1.getParams(), ed2.getParams());
        }

        return false;
    }

    public static boolean compareEDDSAKeyParams(EdDSAParameterSpec s1, EdDSAParameterSpec s2) {
        if (Objects.equals(s1, s2)) {
            return true;
        } else if (s1 == null || s2 == null) {
            return false; // both null is covered by Objects#equals
        } else {
            return Objects.equals(s1.getHashAlgorithm(), s2.getHashAlgorithm())
                    && Objects.equals(s1.getCurve(), s2.getCurve())
                    && Objects.equals(s1.getB(), s2.getB());
        }
    }

    public static PublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " not supported");
        }

        return EdDSAUtils.getPublicKey(seed);
    }

    public static PrivateKey generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " not supported");
        }

        return EdDSAUtils.getPrivateKey(seed);
    }
}
