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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.apache.sshd.common.util.SecurityUtils;

/**
 * Diffie-Hellman key generator.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DH {

    private BigInteger p;
    private BigInteger g;
    private BigInteger e;  // my public key
    private byte[] e_array;
    private BigInteger f;  // your public key
    private BigInteger K;  // shared secret key
    private byte[] K_array;
    private KeyPairGenerator myKpairGen;
    private KeyAgreement myKeyAgree;

    public DH() throws Exception {
        myKpairGen = SecurityUtils.getKeyPairGenerator("DH");
        myKeyAgree = SecurityUtils.getKeyAgreement("DH");
    }

    public byte[] getE() throws Exception {
        if (e == null) {
            DHParameterSpec dhSkipParamSpec = new DHParameterSpec(p, g);
            myKpairGen.initialize(dhSkipParamSpec);
            KeyPair myKpair = myKpairGen.generateKeyPair();
            myKeyAgree.init(myKpair.getPrivate());
            e = ((javax.crypto.interfaces.DHPublicKey) (myKpair.getPublic())).getY();
            e_array = e.toByteArray();
        }
        return e_array;
    }

    public byte[] getK() throws Exception {
        if (K == null) {
            KeyFactory myKeyFac = SecurityUtils.getKeyFactory("DH");
            DHPublicKeySpec keySpec = new DHPublicKeySpec(f, p, g);
            PublicKey yourPubKey = myKeyFac.generatePublic(keySpec);
            myKeyAgree.doPhase(yourPubKey, true);
            byte[] mySharedSecret = stripLeadingZeroes(myKeyAgree.generateSecret());
            K = new BigInteger(mySharedSecret);
            K_array = mySharedSecret;
        }
        return K_array;
    }

    public void setP(byte[] p) {
        setP(new BigInteger(p));
    }

    public void setG(byte[] g) {
        setG(new BigInteger(g));
    }

    public void setF(byte[] f) {
        setF(new BigInteger(f));
    }

    void setP(BigInteger p) {
        this.p = p;
    }

    void setG(BigInteger g) {
        this.g = g;
    }

    void setF(BigInteger f) {
        this.f = f;
    }

    // The shared secret returned by KeyAgreement.generateSecret() is
    // a byte array, which can (by chance, roughly 1 out of 256 times)
    // begin with zero byte (some JCE providers might strip this, though).
    // In SSH, the shared secret is an integer, so we need to strip
    // the leading zero(es).
    private static byte[] stripLeadingZeroes(byte[] x) {
        int i = 0;
        while ((i < x.length - 1) && (x[i] == 0)) {
            i++;
        }
        byte[] ret = new byte[x.length - i];
        System.arraycopy(x, i, ret, 0, ret.length);
        return ret;
    }
}
