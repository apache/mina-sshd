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

package org.apache.sshd.openpgp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.c02e.jpgpj.Subkey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PGPPublicKeyExtractor {
    default PublicKey extractPublicKey(NamedResource resourceKey, Subkey sk)
            throws IOException, GeneralSecurityException {
        if (sk == null) {
            return null;
        }

        PGPPublicKey pgpKey = Objects.requireNonNull(sk.getPublicKey(), "Missing sub-key public key");
        PublicKeyPacket pgpPacket = Objects.requireNonNull(pgpKey.getPublicKeyPacket(), "Missing public key packet");
        BCPGKey bcKey = Objects.requireNonNull(pgpPacket.getKey(), "Missing BC key");
        if (bcKey instanceof RSAPublicBCPGKey) {
            return extractRSAPublicKey(resourceKey, (RSAPublicBCPGKey) bcKey);
        } else if (bcKey instanceof ECPublicBCPGKey) {
            return extractECPublicKey(resourceKey, (ECPublicBCPGKey) bcKey);
        } else if (bcKey instanceof DSAPublicBCPGKey) {
            return extractDSSPublicKey(resourceKey, (DSAPublicBCPGKey) bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported BC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    default RSAPublicKey extractRSAPublicKey(NamedResource resourceKey, RSAPublicBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        BigInteger e = bcKey.getPublicExponent();
        BigInteger n = bcKey.getModulus();
        return generatePublicKey(KeyUtils.RSA_ALGORITHM, RSAPublicKey.class, new RSAPublicKeySpec(n, e));
    }

    default PublicKey extractECPublicKey(NamedResource resourceKey, ECPublicBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        } else if (bcKey instanceof EdDSAPublicBCPGKey) {
            return extractEdDSAPublicKey(resourceKey, (EdDSAPublicBCPGKey) bcKey);
        } else if ((bcKey instanceof ECDSAPublicBCPGKey) || (bcKey instanceof ECDHPublicBCPGKey)) {
            return extractECDSAPublicKey(resourceKey, bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported EC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    default ECPublicKey extractECDSAPublicKey(NamedResource resourceKey, ECPublicBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        ASN1ObjectIdentifier asnId = bcKey.getCurveOID();
        String oid = asnId.getId();
        ECCurves curve = ECCurves.fromOID(oid);
        if (curve == null) {
            throw new InvalidKeySpecException("Not an EC curve OID: " + oid);
        }

        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        BigInteger encPoint = bcKey.getEncodedPoint();
        byte[] octets = encPoint.toByteArray();
        ECPoint w;
        try {
            w = ECCurves.octetStringToEcPoint(octets);
            if (w == null) {
                throw new InvalidKeySpecException(
                        "No ECPoint generated for curve=" + curve.getName()
                                                  + " from octets=" + BufferUtils.toHex(':', octets));
            }
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException(
                    "Failed (" + e.getClass().getSimpleName() + ")"
                                              + " to generate ECPoint for curve=" + curve.getName()
                                              + " from octets=" + BufferUtils.toHex(':', octets)
                                              + ": " + e.getMessage());
        }

        ECParameterSpec paramSpec = curve.getParameters();
        return generatePublicKey(KeyUtils.EC_ALGORITHM, ECPublicKey.class, new ECPublicKeySpec(w, paramSpec));
    }

    default PublicKey extractEdDSAPublicKey(NamedResource resourceKey, EdDSAPublicBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchProviderException("EdDSA not supported");
        }

        throw new NoSuchAlgorithmException("Unsupported EdDSA public key type: " + bcKey.getClass().getSimpleName());
    }

    default DSAPublicKey extractDSSPublicKey(NamedResource resourceKey, DSAPublicBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        BigInteger p = bcKey.getP();
        BigInteger q = bcKey.getQ();
        BigInteger g = bcKey.getG();
        BigInteger y = bcKey.getY();
        return generatePublicKey(KeyUtils.DSS_ALGORITHM, DSAPublicKey.class, new DSAPublicKeySpec(y, p, q, g));
    }

    <K extends PublicKey> K generatePublicKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException;
}
