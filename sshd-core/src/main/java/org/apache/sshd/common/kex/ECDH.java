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
package org.apache.sshd.common.kex;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Elliptic Curve Diffie-Hellman key agreement.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECDH extends AbstractDH {
    public static final String KEX_TYPE = "ECDH";

    private ECCurves curve;
    private ECParameterSpec params;
    private ECPoint f;

    public ECDH() throws Exception {
        this((ECParameterSpec) null);
    }

    public ECDH(String curveName) throws Exception {
        this(ValidateUtils.checkNotNull(ECCurves.fromCurveName(curveName), "Unknown curve name: %s", curveName));
    }

    public ECDH(ECCurves curve) throws Exception {
        this(Objects.requireNonNull(curve, "No known curve instance provided").getParameters());
        this.curve = curve;
    }

    public ECDH(ECParameterSpec paramSpec) throws Exception {
        myKeyAgree = SecurityUtils.getKeyAgreement(KEX_TYPE);
        params = paramSpec; // do not check for null-ity since in some cases it can be
    }

    @Override
    protected byte[] calculateE() throws Exception {
        Objects.requireNonNull(params, "No ECParameterSpec(s)");
        KeyPairGenerator myKpairGen = SecurityUtils.getKeyPairGenerator(KeyUtils.EC_ALGORITHM);
        myKpairGen.initialize(params);

        KeyPair myKpair = myKpairGen.generateKeyPair();
        myKeyAgree.init(myKpair.getPrivate());

        ECPublicKey pubKey = (ECPublicKey) myKpair.getPublic();
        ECPoint e = pubKey.getW();
        return ECCurves.encodeECPoint(e, params);
    }

    @Override
    protected byte[] calculateK() throws Exception {
        Objects.requireNonNull(params, "No ECParameterSpec(s)");
        Objects.requireNonNull(f, "Missing 'f' value");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(f, params);
        KeyFactory myKeyFac = SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        PublicKey yourPubKey = myKeyFac.generatePublic(keySpec);
        myKeyAgree.doPhase(yourPubKey, true);
        return stripLeadingZeroes(myKeyAgree.generateSecret());
    }

    public void setCurveParameters(ECParameterSpec paramSpec) {
        params = paramSpec;
    }

    @Override
    public void setF(byte[] f) {
        Objects.requireNonNull(params, "No ECParameterSpec(s)");
        Objects.requireNonNull(f, "No 'f' value specified");
        this.f = ECCurves.octetStringToEcPoint(f);
    }

    @Override
    public Digest getHash() throws Exception {
        if (curve == null) {
            Objects.requireNonNull(params, "No ECParameterSpec(s)");
            curve = Objects.requireNonNull(ECCurves.fromCurveParameters(params), "Unknown curve parameters");
        }

        return curve.getDigestForParams();
    }

    @Override
    public String toString() {
        return super.toString()
               + "[curve=" + curve
               + ", f=" + f
               + "]";
    }
}
