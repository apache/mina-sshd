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

package org.apache.sshd.common.util.buffer.keys;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECBufferPublicKeyParser extends AbstractBufferPublicKeyParser<ECPublicKey> {
    public static final ECBufferPublicKeyParser INSTANCE = new ECBufferPublicKeyParser();

    public ECBufferPublicKeyParser() {
        super(ECPublicKey.class, ECCurves.KEY_TYPES);
    }

    @Override
    public ECPublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
        ValidateUtils.checkTrue(isKeyTypeSupported(keyType), "Unsupported key type: %s", keyType);
        ECCurves curve = ECCurves.fromKeyType(keyType);
        if (curve == null) {
            throw new NoSuchAlgorithmException("Unsupported raw public algorithm: " + keyType);
        }

        String curveName = curve.getName();
        ECParameterSpec params = curve.getParameters();
        return getRawECKey(curveName, params, buffer);
    }

    protected ECPublicKey getRawECKey(String expectedCurve, ECParameterSpec spec, Buffer buffer)
            throws GeneralSecurityException {
        String curveName = buffer.getString();
        if (!expectedCurve.equals(curveName)) {
            throw new InvalidKeySpecException(
                    "getRawECKey(" + expectedCurve + ") curve name does not match expected: " + curveName);
        }

        if (spec == null) {
            throw new InvalidKeySpecException("getRawECKey(" + expectedCurve + ") missing curve parameters");
        }

        byte[] octets = buffer.getBytes();
        ECPoint w;
        try {
            w = ECCurves.octetStringToEcPoint(octets);
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException(
                    "getRawECKey(" + expectedCurve + ")"
                                              + " cannot (" + e.getClass().getSimpleName() + ")"
                                              + " retrieve W value: " + e.getMessage(),
                    e);
        }

        return generatePublicKey(KeyUtils.EC_ALGORITHM, new ECPublicKeySpec(w, spec));
    }
}
