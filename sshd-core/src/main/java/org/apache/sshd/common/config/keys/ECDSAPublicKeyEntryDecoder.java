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

package org.apache.sshd.common.config.keys;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECDSAPublicKeyEntryDecoder extends AbstractPublicKeyEntryDecoder<ECPublicKey, ECPrivateKey> {

    public static final ECDSAPublicKeyEntryDecoder INSTANCE = new ECDSAPublicKeyEntryDecoder();

    // see rfc5480 section 2.2
    public static final byte ECPOINT_UNCOMPRESSED_FORM_INDICATOR = 0x04;
    public static final byte ECPOINT_COMPRESSED_VARIANT_2 = 0x02;
    public static final byte ECPOINT_COMPRESSED_VARIANT_3 = 0x02;


    public ECDSAPublicKeyEntryDecoder() {
        super(ECPublicKey.class, ECPrivateKey.class, ECCurves.KEY_TYPES);
    }

    @Override
    public ECPublicKey decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException {
        ECCurves curve = ECCurves.fromKeyType(keyType);
        if (curve == null) {
            throw new InvalidKeySpecException("Not an EC curve name: " + keyType);
        }

        if (!SecurityUtils.hasEcc()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        String keyCurveName = curve.getName();
        ECParameterSpec paramSpec = curve.getParameters();
        // see rfc5656 section 3.1
        String encCurveName = decodeString(keyData);
        if (!keyCurveName.equals(encCurveName)) {
            throw new InvalidKeySpecException("Mismatched key curve name (" + keyCurveName + ") vs. encoded one (" + encCurveName + ")");
        }

        byte[] octets = readRLEBytes(keyData);
        final ECPoint w;
        try {
            w = octetStringToEcPoint(octets);
            if (w == null) {
                throw new InvalidKeySpecException("No ECPoint generated for curve=" + keyCurveName + " from octets=" + BufferUtils.toHex(':', octets));
            }
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("Failed (" + e.getClass().getSimpleName() + ")"
                    + " to generate ECPoint for curve=" + keyCurveName
                    + " from octets=" + BufferUtils.toHex(':', octets)
                    + ": " + e.getMessage());
        }

        return generatePublicKey(new ECPublicKeySpec(w, paramSpec));
    }

    @Override
    public ECPublicKey clonePublicKey(ECPublicKey key) throws GeneralSecurityException {
        if (!SecurityUtils.hasEcc()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        if (key == null) {
            return null;
        }

        ECParameterSpec params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePublicKey(new ECPublicKeySpec(key.getW(), params));
    }

    @Override
    public ECPrivateKey clonePrivateKey(ECPrivateKey key) throws GeneralSecurityException {
        if (!SecurityUtils.hasEcc()) {
            throw new NoSuchProviderException("ECC not supported");
        }

        if (key == null) {
            return null;
        }

        ECParameterSpec params = key.getParams();
        if (params == null) {
            throw new InvalidKeyException("Missing parameters in key");
        }

        return generatePrivateKey(new ECPrivateKeySpec(key.getS(), params));
    }

    @Override
    public String encodePublicKey(OutputStream s, ECPublicKey key) throws IOException {
        ValidateUtils.checkNotNull(key, "No public key provided");

        ECParameterSpec params = ValidateUtils.checkNotNull(key.getParams(), "No EC parameters available");
        ECCurves curve = ValidateUtils.checkNotNull(ECCurves.fromCurveParameters(params), "Cannot determine curve");
        String keyType = curve.getKeyType();
        String curveName = curve.getName();
        encodeString(s, keyType);
        // see rfc5656 section 3.1
        encodeString(s, curveName);
        ECPointCompression.UNCOMPRESSED.writeECPoint(s, curveName, key.getW());
        return keyType;
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        if (SecurityUtils.hasEcc()) {
            return SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        } else {
            throw new NoSuchProviderException("ECC not supported");
        }
    }

    @Override
    public KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        ECCurves curve = ECCurves.fromCurveSize(keySize);
        if (curve == null) {
            throw new InvalidKeySpecException("Unknown curve for key size=" + keySize);
        }

        KeyPairGenerator gen = getKeyPairGenerator();
        gen.initialize(curve.getParameters());
        return gen.generateKeyPair();
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        if (SecurityUtils.hasEcc()) {
            return SecurityUtils.getKeyPairGenerator(KeyUtils.EC_ALGORITHM);
        } else {
            throw new NoSuchProviderException("ECC not supported");
        }
    }

    public static ECPoint octetStringToEcPoint(byte... octets) {
        if (NumberUtils.isEmpty(octets)) {
            return null;
        }

        int startIndex = findFirstNonZeroIndex(octets);
        if (startIndex < 0) {
            throw new IllegalArgumentException("All zeroes ECPoint N/A");
        }

        byte indicator = octets[startIndex];
        ECPointCompression compression = ECPointCompression.fromIndicatorValue(indicator);
        if (compression == null) {
            throw new UnsupportedOperationException("Unknown compression indicator value: 0x" + Integer.toHexString(indicator & 0xFF));
        }

        // The coordinates actually start after the compression indicator
        return compression.octetStringToEcPoint(octets, startIndex + 1, octets.length - startIndex - 1);
    }

    private static int findFirstNonZeroIndex(byte... octets) {
        if (NumberUtils.isEmpty(octets)) {
            return -1;
        }

        for (int index = 0; index < octets.length; index++) {
            if (octets[index] != 0) {
                return index;
            }
        }

        return -1;    // all zeroes
    }

    /**
     * The various {@link ECPoint} representation compression indicators
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     * @see <A HREF="https://www.ietf.org/rfc/rfc5480.txt">RFC-5480 - section 2.2</A>
     */
    public enum ECPointCompression {
        // see http://tools.ietf.org/html/draft-jivsov-ecc-compact-00
        // see http://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
        VARIANT2((byte) 0x02) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                byte[] xp = new byte[len];
                System.arraycopy(octets, startIndex, xp, 0, len);
                BigInteger x = octetStringToInteger(xp);

                // TODO derive even Y...
                throw new UnsupportedOperationException("octetStringToEcPoint(" + name() + ")(X=" + x + ") compression support N/A");
            }
        },
        VARIANT3((byte) 0x03) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                byte[] xp = new byte[len];
                System.arraycopy(octets, startIndex, xp, 0, len);
                BigInteger x = octetStringToInteger(xp);

                // TODO derive odd Y...
                throw new UnsupportedOperationException("octetStringToEcPoint(" + name() + ")(X=" + x + ") compression support N/A");
            }
        },
        UNCOMPRESSED((byte) 0x04) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                int numElements = len / 2;    /* x, y */
                if (len != (numElements * 2)) {    // make sure length is not odd
                    throw new IllegalArgumentException("octetStringToEcPoint(" + name() + ") "
                            + " invalid remainder octets representation: "
                            + " expected=" + (2 * numElements) + ", actual=" + len);
                }

                byte[] xp = new byte[numElements];
                byte[] yp = new byte[numElements];
                System.arraycopy(octets, startIndex, xp, 0, numElements);
                System.arraycopy(octets, startIndex + numElements, yp, 0, numElements);

                BigInteger x = octetStringToInteger(xp);
                BigInteger y = octetStringToInteger(yp);
                return new ECPoint(x, y);
            }

            @Override
            public void writeECPoint(OutputStream s, String curveName, ECPoint p) throws IOException {
                ECCurves curve = ECCurves.fromCurveName(curveName);
                if (curve == null) {
                    throw new StreamCorruptedException("writeECPoint(" + name() + ")[" + curveName + "] cannot determine octets count");
                }

                int numElements = curve.getNumPointOctets();
                AbstractPublicKeyEntryDecoder.encodeInt(s, 1 /* the indicator */ + 2 * numElements);
                s.write(getIndicatorValue());
                writeCoordinate(s, "X", p.getAffineX(), numElements);
                writeCoordinate(s, "Y", p.getAffineY(), numElements);
            }

        };

        public static final Set<ECPointCompression> VALUES =
                Collections.unmodifiableSet(EnumSet.allOf(ECPointCompression.class));

        private final byte indicatorValue;

        ECPointCompression(byte indicator) {
            indicatorValue = indicator;
        }

        public final byte getIndicatorValue() {
            return indicatorValue;
        }

        public abstract ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len);

        public byte[] ecPointToOctetString(String curveName, ECPoint p) {
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream((2 * 66) + Long.SIZE)) {
                writeECPoint(baos, curveName, p);
                return baos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException("ecPointToOctetString(" + curveName + ")"
                        + " failed (" + e.getClass().getSimpleName() + ")"
                        + " to write data: " + e.getMessage(),
                        e);
            }
        }

        public void writeECPoint(OutputStream s, String curveName, ECPoint p) throws IOException {
            if (s == null) {
                throw new EOFException("No output stream");
            }

            throw new StreamCorruptedException("writeECPoint(" + name() + ")[" + p + "] N/A");
        }

        protected void writeCoordinate(OutputStream s, String n, BigInteger v, int numElements) throws IOException {
            byte[] vp = v.toByteArray();
            int startIndex = 0;
            int vLen = vp.length;
            if (vLen > numElements) {
                if (vp[0] == 0) {   // skip artificial positive sign
                    startIndex++;
                    vLen--;
                }
            }

            if (vLen > numElements) {
                throw new StreamCorruptedException("writeCoordinate(" + name() + ")[" + n + "]"
                        + " value length (" + vLen + ") exceeds max. (" + numElements + ")"
                        + " for " + v);
            }

            if (vLen < numElements) {
                byte[] tmp = new byte[numElements];
                System.arraycopy(vp, startIndex, tmp, numElements - vLen, vLen);
                vp = tmp;
            }

            s.write(vp, startIndex, vLen);
        }

        public static ECPointCompression fromIndicatorValue(int value) {
            if ((value < 0) || (value > 0xFF)) {
                return null;    // must be a byte value
            }

            for (ECPointCompression c : VALUES) {
                if (value == c.getIndicatorValue()) {
                    return c;
                }
            }

            return null;
        }

        /**
         * Converts the given octet string (defined by ASN.1 specifications) to a {@link BigInteger}
         * As octet strings always represent positive integers, a zero-byte is prepended to
         * the given array if necessary (if is MSB equal to 1), then this is converted to BigInteger
         * The conversion is defined in the Section 2.3.8
         *
         * @param octets - octet string bytes to be converted
         * @return The {@link BigInteger} representation of the octet string
         */
        public static BigInteger octetStringToInteger(byte... octets) {
            if (octets == null) {
                return null;
            } else if (octets.length == 0) {
                return BigInteger.ZERO;
            } else {
                return new BigInteger(1, octets);
            }
        }
    }
}
