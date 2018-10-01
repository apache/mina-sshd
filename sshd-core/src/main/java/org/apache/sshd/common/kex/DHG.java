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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Diffie-Hellman key generator.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DHG extends AbstractDH {

    private BigInteger p;
    private BigInteger g;
    private BigInteger e;  // my public key
    private byte[] e_array;
    private BigInteger f;  // your public key
    private KeyPairGenerator myKpairGen;
    private KeyAgreement myKeyAgree;
    private Factory<? extends Digest> factory;

    public DHG(Factory<? extends Digest> digestFactory) throws Exception {
        this(digestFactory, null, null);
    }

    public DHG(Factory<? extends Digest> digestFactory, BigInteger pValue, BigInteger gValue) throws Exception {
        myKpairGen = SecurityUtils.getKeyPairGenerator("DH");
        myKeyAgree = SecurityUtils.getKeyAgreement("DH");
        factory = digestFactory;
        p = pValue;
        g = gValue;
    }

    @Override
    public byte[] getE() throws Exception {
        if (e == null) {
            DHParameterSpec dhSkipParamSpec = new DHParameterSpec(p, g);
            myKpairGen.initialize(dhSkipParamSpec);
            KeyPair myKpair = myKpairGen.generateKeyPair();
            myKeyAgree.init(myKpair.getPrivate());
            e = ((javax.crypto.interfaces.DHPublicKey) (myKpair.getPublic())).getY();
            e_array = e.toByteArray();

            // At this point we will not need the KeyPairGenerator, allow it to be garbage-collected
            myKpairGen = null;
        }
        return e_array;
    }

    @Override
    protected byte[] calculateK() throws Exception {
        KeyFactory myKeyFac = SecurityUtils.getKeyFactory("DH");
        DHPublicKeySpec keySpec = new DHPublicKeySpec(f, p, g);
        PublicKey yourPubKey = myKeyFac.generatePublic(keySpec);
        myKeyAgree.doPhase(yourPubKey, true);
        return stripLeadingZeroes(myKeyAgree.generateSecret());
    }

    public void setP(byte[] p) {
        setP(new BigInteger(p));
    }

    public void setG(byte[] g) {
        setG(new BigInteger(g));
    }

    @Override
    public void setF(byte[] f) {
        setF(new BigInteger(f));
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public void setF(BigInteger f) {
        this.f = f;
    }

    @Override
    public Digest getHash() throws Exception {
        return factory.create();
    }
}
