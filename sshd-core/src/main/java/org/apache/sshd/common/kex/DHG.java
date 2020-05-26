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
import java.util.Objects;

import javax.crypto.interfaces.DHPublicKey;
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
    public static final String KEX_TYPE = "DH";

    private BigInteger p;
    private BigInteger g;
    private BigInteger f; // your public key
    private Factory<? extends Digest> factory;

    public DHG(Factory<? extends Digest> digestFactory) throws Exception {
        this(digestFactory, null, null);
    }

    public DHG(Factory<? extends Digest> digestFactory, BigInteger pValue, BigInteger gValue) throws Exception {
        myKeyAgree = SecurityUtils.getKeyAgreement(KEX_TYPE);
        factory = digestFactory;
        p = pValue; // do not check for null-ity since in some cases it can be
        g = gValue; // do not check for null-ity since in some cases it can be
    }

    @Override
    protected byte[] calculateE() throws Exception {
        DHParameterSpec dhSkipParamSpec = new DHParameterSpec(p, g);
        KeyPairGenerator myKpairGen = SecurityUtils.getKeyPairGenerator("DH");
        myKpairGen.initialize(dhSkipParamSpec);

        KeyPair myKpair = myKpairGen.generateKeyPair();
        myKeyAgree.init(myKpair.getPrivate());

        DHPublicKey pubKey = (DHPublicKey) myKpair.getPublic();
        BigInteger e = pubKey.getY();
        return e.toByteArray();
    }

    @Override
    protected byte[] calculateK() throws Exception {
        Objects.requireNonNull(f, "Missing 'f' value");
        DHPublicKeySpec keySpec = new DHPublicKeySpec(f, p, g);
        KeyFactory myKeyFac = SecurityUtils.getKeyFactory("DH");
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
        this.f = Objects.requireNonNull(f, "No 'f' value specified");
    }

    @Override
    public Digest getHash() throws Exception {
        return factory.create();
    }

    @Override
    public String toString() {
        return super.toString()
               + "[p=" + p
               + ", g=" + g
               + ", f=" + f
               + ", digest=" + factory
               + "]";
    }
}
