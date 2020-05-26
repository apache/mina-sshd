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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.IdentityResourceLoader;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECDSAPublicKeyEntryDecoder extends AbstractPublicKeyEntryDecoder<ECPublicKey, ECPrivateKey> {
    public static final int MAX_ALLOWED_POINT_SIZE = IdentityResourceLoader.MAX_BIGINT_OCTETS_COUNT;
    public static final int MAX_CURVE_NAME_LENGTH = 1024;

    public static final ECDSAPublicKeyEntryDecoder INSTANCE = new ECDSAPublicKeyEntryDecoder();

    // see rfc5480 section 2.2
    public static final byte ECPOINT_UNCOMPRESSED_FORM_INDICATOR = 0x04;
    public static final byte ECPOINT_COMPRESSED_VARIANT_2 = 0x02;
    public static final byte ECPOINT_COMPRESSED_VARIANT_3 = 0x02;

    public ECDSAPublicKeyEntryDecoder() {
        super(ECPublicKey.class, ECPrivateKey.class, ECCurves.KEY_TYPES);
    }

    @Override
    public ECPublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        ECCurves curve = ECCurves.fromKeyType(keyType);
        if (curve == null) {
            throw new InvalidKeySpecException("Not an EC curve name: " + keyType);
        }

        return decodePublicKey(curve, keyData);
    }

    ECPublicKey decodePublicKey(ECCurves curve, InputStream keyData) throws IOException, GeneralSecurityException {
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        String keyCurveName = curve.getName();
        // see rfc5656 section 3.1
        String encCurveName = KeyEntryResolver.decodeString(keyData, MAX_CURVE_NAME_LENGTH);
        if (!keyCurveName.equals(encCurveName)) {
            throw new InvalidKeySpecException(
                    "Mismatched key curve name (" + keyCurveName + ") vs. encoded one (" + encCurveName + ")");
        }

        byte[] octets = KeyEntryResolver.readRLEBytes(keyData, MAX_ALLOWED_POINT_SIZE);
        ECPoint w;
        try {
            w = ECCurves.octetStringToEcPoint(octets);
            if (w == null) {
                throw new InvalidKeySpecException(
                        "No ECPoint generated for curve=" + keyCurveName + " from octets=" + BufferUtils.toHex(':', octets));
            }
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException(
                    "Failed (" + e.getClass().getSimpleName() + ")" + " to generate ECPoint for curve=" + keyCurveName
                                              + " from octets=" + BufferUtils.toHex(':', octets) + ": " + e.getMessage());
        }

        ECParameterSpec paramSpec = curve.getParameters();
        return generatePublicKey(new ECPublicKeySpec(w, paramSpec));
    }

    @Override
    public ECPublicKey clonePublicKey(ECPublicKey key) throws GeneralSecurityException {
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        if (key == null) {
            return null;
        }

        ECParameterSpec params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePublicKey(new ECPublicKeySpec(key.getW(), params));
    }

    @Override
    public ECPrivateKey clonePrivateKey(ECPrivateKey key) throws GeneralSecurityException {
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        if (key == null) {
            return null;
        }

        ECParameterSpec params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePrivateKey(new ECPrivateKeySpec(key.getS(), params));
    }

    @Override
    public String encodePublicKey(OutputStream s, ECPublicKey key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");

        ECParameterSpec params = Objects.requireNonNull(key.getParams(), "No EC parameters available");
        ECCurves curve = Objects.requireNonNull(ECCurves.fromCurveParameters(params), "Cannot determine curve");
        String keyType = curve.getKeyType();
        encodePublicKey(s, keyType, curve, key.getW());
        return keyType;
    }

    static void encodePublicKey(OutputStream s, String keyType, ECCurves curve, ECPoint w) throws IOException {
        String curveName = curve.getName();
        KeyEntryResolver.encodeString(s, keyType);
        // see rfc5656 section 3.1
        KeyEntryResolver.encodeString(s, curveName);
        ECCurves.ECPointCompression.UNCOMPRESSED.writeECPoint(s, curveName, w);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        if (SecurityUtils.isECCSupported()) {
            return SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        } else {
            throw new NoSuchProviderException("ECC not supported");
        }
    }

    @Override
    public KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        ECCurves curve = ECCurves.fromCurveSize(keySize);
        if (curve == null) {
            throw new InvalidKeySpecException("Unknown curve for key size=" + keySize);
        }

        KeyPairGenerator gen = getKeyPairGenerator();
        gen.initialize(curve.getParameters());
        return gen.generateKeyPair();
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        if (SecurityUtils.isECCSupported()) {
            return SecurityUtils.getKeyPairGenerator(KeyUtils.EC_ALGORITHM);
        } else {
            throw new NoSuchProviderException("ECC not supported");
        }
    }
}
