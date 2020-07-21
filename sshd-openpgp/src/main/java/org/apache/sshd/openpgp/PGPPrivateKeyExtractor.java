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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.c02e.jpgpj.Subkey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface PGPPrivateKeyExtractor {
    default PrivateKey extractPrivateKey(
            NamedResource resourceKey, Subkey sk, PublicKey pubKey)
            throws IOException, GeneralSecurityException, PGPException {
        if (sk == null) {
            return null;
        }

        PGPPrivateKey pgpKey = Objects.requireNonNull(sk.getPrivateKey(), "Missing sub-key private key");
        BCPGKey bcKey = Objects.requireNonNull(pgpKey.getPrivateKeyDataPacket(), "Missing BC key");
        if (bcKey instanceof RSASecretBCPGKey) {
            return extractRSAPrivateKey(resourceKey, (RSAPublicKey) pubKey, (RSASecretBCPGKey) bcKey);
        } else if (bcKey instanceof ECSecretBCPGKey) {
            return extractECDSAPrivateKey(resourceKey, (ECPublicKey) pubKey, (ECSecretBCPGKey) bcKey);
        } else if (bcKey instanceof EdSecretBCPGKey) {
            return extractEdDSAPrivateKey(resourceKey, pubKey, (EdSecretBCPGKey) bcKey);
        } else if (bcKey instanceof DSASecretBCPGKey) {
            return extractDSSPrivateKey(resourceKey, (DSAPublicKey) pubKey, (DSASecretBCPGKey) bcKey);
        } else {
            throw new NoSuchAlgorithmException("Unsupported BC public key type: " + bcKey.getClass().getSimpleName());
        }
    }

    default ECPrivateKey extractECDSAPrivateKey(
            NamedResource resourceKey, ECPublicKey pubKey, ECSecretBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        ECParameterSpec params = pubKey.getParams();
        BigInteger x = bcKey.getX();
        return generatePrivateKey(KeyUtils.EC_ALGORITHM, ECPrivateKey.class, new ECPrivateKeySpec(x, params));
    }

    default PrivateKey extractEdDSAPrivateKey(
            NamedResource resourceKey, PublicKey pubKey, EdSecretBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchProviderException("EdDSA not supported");
        }

        throw new NoSuchAlgorithmException("Unsupported EdDSA private key type: " + bcKey.getClass().getSimpleName());
    }

    default RSAPrivateKey extractRSAPrivateKey(
            NamedResource resourceKey, RSAPublicKey pubKey, RSASecretBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        return generatePrivateKey(KeyUtils.RSA_ALGORITHM, RSAPrivateKey.class,
                new RSAPrivateCrtKeySpec(
                        bcKey.getModulus(),
                        pubKey.getPublicExponent(),
                        bcKey.getPrivateExponent(),
                        bcKey.getPrimeP(),
                        bcKey.getPrimeQ(),
                        bcKey.getPrimeExponentP(),
                        bcKey.getPrimeExponentQ(),
                        bcKey.getCrtCoefficient()));
    }

    default DSAPrivateKey extractDSSPrivateKey(
            NamedResource resourceKey, DSAPublicKey pubKey, DSASecretBCPGKey bcKey)
            throws IOException, GeneralSecurityException {
        if (bcKey == null) {
            return null;
        }

        DSAParams params = pubKey.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in public key");
        }

        return generatePrivateKey(KeyUtils.DSS_ALGORITHM, DSAPrivateKey.class,
                new DSAPrivateKeySpec(bcKey.getX(), params.getP(), params.getQ(), params.getG()));
    }

    <K extends PrivateKey> K generatePrivateKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException;
}
