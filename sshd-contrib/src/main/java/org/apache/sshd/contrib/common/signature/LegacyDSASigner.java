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

package org.apache.sshd.contrib.common.signature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.io.der.DERWriter;

/**
 * A special signer for DSA that uses SHA-1 regardless of the key size
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://issues.apache.org/jira/browse/SSHD-945">SSHD-945 issue</a>
 */
public class LegacyDSASigner extends java.security.Signature {
    public static final String LEGACY_SIGNATURE = "LegacySHA1withDSA";

    protected final MessageDigest md;
    protected final Factory<Random> randomFactory;
    protected BigInteger x;
    protected BigInteger y;
    protected DSAParams params;

    public LegacyDSASigner(Factory<Random> randomFactory) throws GeneralSecurityException {
        super(LEGACY_SIGNATURE);

        this.randomFactory = randomFactory;
        md = MessageDigest.getInstance("SHA-1");
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String key, Object param) {
        throw new InvalidParameterException("No parameter accepted");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String key) {
        return null;
    }

    protected void initDSAParameters(DSAKey key) throws InvalidKeyException {
        params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing DSA parameters in key");
        }

        md.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
        if (!(key instanceof DSAPrivateKey)) {
            throw new InvalidKeyException("Not a DSA private key");
        }

        DSAPrivateKey prvKey = (DSAPrivateKey) key;
        initDSAParameters(prvKey);
        x = prvKey.getX();
        y = null;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            ValidateUtils.checkState(params != null, "Missing DSA parameters");

            BigInteger q = params.getQ();
            BigInteger k = generateK(q);

            BigInteger r = generateR(params.getP(), q, params.getG(), k);
            byte[] rEncoding;
            try (DERWriter w = new DERWriter(SignatureDSA.MAX_SIGNATURE_VALUE_LENGTH + 4)) { // in case length > 0x7F
                w.writeBigInteger(r);
                rEncoding = w.toByteArray();
            }

            BigInteger s = generateS(x, q, r, k);
            byte[] sEncoding;
            try (DERWriter w = new DERWriter(SignatureDSA.MAX_SIGNATURE_VALUE_LENGTH + 4)) { // in case length > 0x7F
                w.writeBigInteger(s);
                sEncoding = w.toByteArray();
            }

            int length = rEncoding.length + sEncoding.length;
            try (DERWriter w = new DERWriter(1 + length + 4)) { // in case length > 0x7F
                w.write(0x30); // SEQUENCE
                w.writeLength(length);
                w.write(rEncoding);
                w.write(sEncoding);
                return w.toByteArray();
            }
        } catch (RuntimeException | IOException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    protected BigInteger generateK(BigInteger q) {
        Random random;
        if (appRandom == null) {
            ValidateUtils.checkState(randomFactory != null, "No signing random factory provided");
            random = randomFactory.create();
        } else {
            random = null;
        }

        byte[] kValue = new byte[q.bitLength() / Byte.SIZE];

        while (true) {
            if (random == null) {
                appRandom.nextBytes(kValue);
            } else {
                random.fill(kValue);
            }

            BigInteger posK = new BigInteger(1, kValue);
            BigInteger k = posK.mod(q);
            if ((k.signum() > 0) && (k.compareTo(q) < 0)) {
                return k;
            }
        }
    }

    protected BigInteger generateR(
            BigInteger p, BigInteger q, BigInteger g, BigInteger k) {
        BigInteger temp = g.modPow(k, p);
        return temp.mod(q);
    }

    protected BigInteger generateS(
            BigInteger x, BigInteger q, BigInteger r, BigInteger k) {
        byte[] s2 = md.digest();

        int nBytes = q.bitLength() / Byte.SIZE;
        if (nBytes < s2.length) {
            s2 = Arrays.copyOfRange(s2, 0, nBytes);
        }

        BigInteger z = new BigInteger(1, s2);
        BigInteger k1 = k.modInverse(q);
        BigInteger mul1 = x.multiply(r);
        BigInteger withZ = mul1.add(z);
        BigInteger mul2 = withZ.multiply(k1);
        return mul2.mod(q);
    }

    @Override
    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
        if (!(key instanceof DSAPublicKey)) {
            throw new InvalidKeyException("Not a DSA public key");
        }

        DSAPublicKey pubKey = (DSAPublicKey) key;
        initDSAParameters(pubKey);
        x = null;
        y = pubKey.getY();
    }

    @Override
    protected boolean engineVerify(byte[] signature)
            throws SignatureException {
        return engineVerify(signature, 0, signature.length);
    }

    @Override
    protected boolean engineVerify(byte[] signature, int offset, int length)
            throws SignatureException {
        ValidateUtils.checkState(params != null, "Missing DSA parameters");

        try {
            BigInteger r;
            BigInteger s;
            try (DERParser parser = new DERParser(signature, offset, length)) {
                int type = parser.read();
                if (type != 0x30) {
                    throw new SignatureException(
                            "Invalid signature format - not a DER SEQUENCE: 0x" + Integer.toHexString(type));
                }

                // length of remaining encoding of the 2 integers
                int remainLen = parser.readLength();
                /*
                 * There are supposed to be 2 INTEGERs, each encoded with:
                 *
                 * - one byte representing the fact that it is an INTEGER - one byte of the integer encoding length - at
                 * least one byte of integer data (zero length is not an option)
                 */
                if (remainLen < (2 * 3)) {
                    throw new SignatureException(
                            "Invalid signature format - not enough encoded data length: " + remainLen);
                }

                r = parser.readBigInteger();
                s = parser.readBigInteger();
            } catch (IOException e) {
                throw new SignatureException("Failed to parse DSA DER data", e);
            }

            /*
             * Some implementations do not correctly encode values in the ASN.1 2's complement format - we need positive
             * values for validation
             */
            if (r.signum() < 0) {
                r = new BigInteger(1, r.toByteArray());
            }
            if (s.signum() < 0) {
                s = new BigInteger(1, s.toByteArray());
            }

            BigInteger q = params.getQ();
            if ((r.compareTo(q) != -1) || (s.compareTo(q) != -1)) {
                throw new IndexOutOfBoundsException("Out of range values in signature");
            }

            BigInteger p = params.getP();
            BigInteger g = params.getG();
            BigInteger w = generateW(p, q, g, s);
            BigInteger v = generateV(y, p, q, g, w, r);
            return v.equals(r);
        } catch (RuntimeException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    protected BigInteger generateW(
            BigInteger p, BigInteger q, BigInteger g, BigInteger s) {
        return s.modInverse(q);
    }

    protected BigInteger generateV(
            BigInteger y, BigInteger p, BigInteger q, BigInteger g, BigInteger w, BigInteger r) {
        byte[] s2 = md.digest();
        int nBytes = q.bitLength() / Byte.SIZE;
        if (nBytes < s2.length) {
            s2 = Arrays.copyOfRange(s2, 0, nBytes);
        }

        BigInteger z = new BigInteger(1, s2);
        BigInteger u1 = z.multiply(w).mod(q);
        BigInteger mul = r.multiply(w);
        BigInteger u2 = mul.mod(q);
        BigInteger t1 = g.modPow(u1, p);
        BigInteger t2 = y.modPow(u2, p);
        BigInteger t3 = t1.multiply(t2);
        BigInteger t5 = t3.mod(p);
        return t5.mod(q);
    }

    @Override
    protected void engineUpdate(byte b) {
        md.update(b);
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) {
        md.update(data, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer b) {
        md.update(b);
    }
}
