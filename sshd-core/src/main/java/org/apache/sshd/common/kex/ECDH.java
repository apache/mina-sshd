/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
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

import javax.crypto.KeyAgreement;

import org.apache.sshd.common.Digest;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * Elliptic Curve Diffie-Hellman key agreement.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECDH extends AbstractDH {

    private ECParameterSpec params;
    private ECPoint e;
    private byte[] e_array;
    private ECPoint f;
    private KeyPairGenerator myKpairGen;
    private KeyAgreement myKeyAgree;

    public ECDH() throws Exception {
        myKpairGen = SecurityUtils.getKeyPairGenerator("EC");
        myKeyAgree = SecurityUtils.getKeyAgreement("ECDH");
    }

    @Override
    public byte[] getE() throws Exception {
        if (e == null) {
            myKpairGen.initialize(params);
            KeyPair myKpair = myKpairGen.generateKeyPair();
            myKeyAgree.init(myKpair.getPrivate());
            e = ((ECPublicKey) myKpair.getPublic()).getW();
            e_array = ECCurves.encodeECPoint(e, params.getCurve());
        }
        return e_array;
    }

    @Override
    protected byte[] calculateK() throws Exception {
        KeyFactory myKeyFac = SecurityUtils.getKeyFactory("EC");
        ECPublicKeySpec keySpec = new ECPublicKeySpec(f, params);
        PublicKey yourPubKey = myKeyFac.generatePublic(keySpec);
        myKeyAgree.doPhase(yourPubKey, true);
        return stripLeadingZeroes(myKeyAgree.generateSecret());
    }

    public void setCurveParameters(ECParameterSpec params) {
        this.params = params;
    }

    @Override
    public void setF(byte[] f) {
        this.f = ECCurves.decodeECPoint(f, params.getCurve());
    }

    @Override
    public Digest getHash() throws Exception {
        return ECCurves.getDigestForParams(params);
    }
}
