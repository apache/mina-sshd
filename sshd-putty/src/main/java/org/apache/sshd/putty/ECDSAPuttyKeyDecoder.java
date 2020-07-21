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
package org.apache.sshd.putty;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECDSAPuttyKeyDecoder extends AbstractPuttyKeyDecoder<ECPublicKey, ECPrivateKey> {
    public static final ECDSAPuttyKeyDecoder INSTANCE = new ECDSAPuttyKeyDecoder();

    public ECDSAPuttyKeyDecoder() {
        super(ECPublicKey.class, ECPrivateKey.class, ECCurves.KEY_TYPES);
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, PuttyKeyReader pubReader, PuttyKeyReader prvReader, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (!SecurityUtils.isECCSupported()) {
            throw new NoSuchAlgorithmException("ECC not supported for " + resourceKey);
        }

        String keyType = pubReader.readString();
        ECCurves curve = ECCurves.fromKeyType(keyType);
        if (curve == null) {
            throw new InvalidKeySpecException("Not an EC curve name: " + keyType);
        }

        String encCurveName = pubReader.readString();
        String keyCurveName = curve.getName();
        if (!keyCurveName.equals(encCurveName)) {
            throw new InvalidKeySpecException(
                    "Mismatched key curve name (" + keyCurveName + ") vs. encoded one (" + encCurveName + ")");
        }

        byte[] octets = pubReader.read(Short.MAX_VALUE); // reasonable max. allowed size
        ECPoint w;
        try {
            w = ECCurves.octetStringToEcPoint(octets);
            if (w == null) {
                throw new InvalidKeySpecException(
                        "No public ECPoint generated for curve=" + keyCurveName
                                                  + " from octets=" + BufferUtils.toHex(':', octets));
            }
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException(
                    "Failed (" + e.getClass().getSimpleName() + ")"
                                              + " to generate public ECPoint for curve=" + keyCurveName
                                              + " from octets=" + BufferUtils.toHex(':', octets)
                                              + ": " + e.getMessage());
        }

        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        ECParameterSpec paramSpec = curve.getParameters();
        PublicKey pubKey = kf.generatePublic(new ECPublicKeySpec(w, paramSpec));

        BigInteger s = prvReader.readInt();
        PrivateKey prvKey = kf.generatePrivate(new ECPrivateKeySpec(s, paramSpec));
        return Collections.singletonList(new KeyPair(pubKey, prvKey));
    }
}
