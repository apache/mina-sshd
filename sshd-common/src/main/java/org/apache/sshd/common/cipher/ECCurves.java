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
package org.apache.sshd.common.cipher;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECKey;
import java.security.spec.ECField;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Utilities for working with elliptic curves.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum ECCurves implements KeyTypeIndicator, KeySizeIndicator, NamedResource, OptionalFeature {

    // See RFC 5656: https://datatracker.ietf.org/doc/html/rfc5656#section-10.1
    nistp256(Constants.NISTP256, "secp256r1", new int[] { 1, 2, 840, 10045, 3, 1, 7 }, 32, BuiltinDigests.sha256),
    nistp384(Constants.NISTP384, "secp384r1", new int[] { 1, 3, 132, 0, 34 }, 48, BuiltinDigests.sha384),
    nistp521(Constants.NISTP521, "secp521r1", new int[] { 1, 3, 132, 0, 35 }, 66, BuiltinDigests.sha512);

    /**
     * A {@link Set} of all the known curves
     */
    public static final Set<ECCurves> VALUES = Collections.unmodifiableSet(EnumSet.allOf(ECCurves.class));

    /**
     * A {@link Set} of all the known curves names
     */
    public static final NavigableSet<String> NAMES = Collections.unmodifiableNavigableSet(
            GenericUtils.mapSort(VALUES, ECCurves::getName, String.CASE_INSENSITIVE_ORDER));

    /**
     * A {@link Set} of all the known curves key types
     */
    public static final NavigableSet<String> KEY_TYPES = Collections.unmodifiableNavigableSet(
            GenericUtils.mapSort(VALUES, ECCurves::getKeyType, String.CASE_INSENSITIVE_ORDER));

    public static final Comparator<ECCurves> BY_KEY_SIZE = (o1, o2) -> {
        int k1 = (o1 == null) ? Integer.MAX_VALUE : o1.getKeySize();
        int k2 = (o2 == null) ? Integer.MAX_VALUE : o2.getKeySize();
        return Integer.compare(k1, k2);
    };

    public static final List<ECCurves> SORTED_KEY_SIZE = Collections.unmodifiableList(VALUES.stream()
            .sorted(BY_KEY_SIZE)
            .collect(Collectors.toList()));

    private final String name;
    private final String secName;
    private final String keyType;
    private final String oidString;
    private final List<Integer> oidValue;
    private final int numOctets;
    private final DigestFactory digestFactory;

    private ECParameterSpec params;
    private volatile int keySize = -1;

    ECCurves(String name, String secName, int[] oid, int numOctets, DigestFactory digestFactory) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No curve name");
        this.secName = ValidateUtils.checkNotNullAndNotEmpty(secName, "No SEC curve name");
        this.oidString = NumberUtils.join('.', ValidateUtils.checkNotNullAndNotEmpty(oid, "No OID"));
        this.oidValue = Collections.unmodifiableList(NumberUtils.asList(oid));
        this.keyType = Constants.ECDSA_SHA2_PREFIX + name;
        this.numOctets = numOctets;
        this.digestFactory = Objects.requireNonNull(digestFactory, "No digestFactory");
    }

    private ECParameterSpec getParams(String secName) {
        try {
            AlgorithmParameters paramsFactory = SecurityUtils.getAlgorithmParameters(KeyUtils.EC_ALGORITHM);
            // Although ECGenParameterSpec exists since Java 1.5 the parameter names were documented only in Java 14
            // with JDK-8210755. But the names were available all the time and are also supported in Bouncy Castle.
            //
            // Note that the names must not be the NIST names but the SEC names.
            //
            // See also https://www.secg.org/sec2-v2.pdf for the name definitions and the exact numerical parameters.
            paramsFactory.init(new ECGenParameterSpec(secName));
            return paramsFactory.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    @Override // The curve's standard name
    public final String getName() {
        return name;
    }

    public final String getOID() {
        return oidString;
    }

    public final List<Integer> getOIDValue() {
        return oidValue;
    }

    @Override
    public final String getKeyType() {
        return keyType;
    }

    @Override
    public final boolean isSupported() {
        return digestFactory.isSupported();
    }

    public final ECParameterSpec getParameters() {
        synchronized (this) {
            if (params == null) {
                params = ValidateUtils.checkNotNull(getParams(secName), "No EC params for %s", name);
            }
            return params;
        }
    }

    @Override
    public final int getKeySize() {
        int sz = keySize;
        if (sz < 0) {
            sz = getCurveSize(getParameters());
            keySize = sz;
        }
        return sz;
    }

    /**
     * @return The number of octets used to represent the point(s) for the curve
     */
    public final int getNumPointOctets() {
        return numOctets;
    }

    /**
     * @return The {@link Digest} to use when hashing the curve's parameters
     */
    public final Digest getDigestForParams() {
        return digestFactory.create();
    }

    /**
     * @param  type The key type value - ignored if {@code null}/empty
     * @return      The matching {@link ECCurves} constant - {@code null} if no match found case <U>insensitive</U>
     */
    public static ECCurves fromKeyType(String type) {
        if (GenericUtils.isEmpty(type)) {
            return null;
        }

        for (ECCurves c : VALUES) {
            if (type.equalsIgnoreCase(c.getKeyType())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param  name The curve name (case <U>insensitive</U> - ignored if {@code null}/empty
     * @return      The matching {@link ECCurves} instance - {@code null} if no match found
     */
    public static ECCurves fromCurveName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  key The {@link ECKey} - ignored if {@code null}
     * @return     The matching {@link ECCurves} instance - {@code null} if no match found
     */
    public static ECCurves fromECKey(ECKey key) {
        return fromCurveParameters((key == null) ? null : key.getParams());
    }

    /**
     * @param  params The curve's {@link ECParameterSpec} - ignored if {@code null}
     * @return        The matching {@link ECCurves} value - {@code null} if no match found
     * @see           #getCurveSize(ECParameterSpec)
     * @see           #fromCurveSize(int)
     */
    public static ECCurves fromCurveParameters(ECParameterSpec params) {
        if (params == null) {
            return null;
        } else {
            return fromCurveSize(getCurveSize(params));
        }
    }

    /**
     * @param  keySize The key size (in bits)
     * @return         The matching {@link ECCurves} value - {@code null} if no match found
     */
    public static ECCurves fromCurveSize(int keySize) {
        if (keySize <= 0) {
            return null;
        }

        for (ECCurves c : VALUES) {
            if (keySize == c.getKeySize()) {
                return c;
            }
        }

        return null;
    }

    public static ECCurves fromOIDValue(List<? extends Number> oid) {
        if (GenericUtils.isEmpty(oid)) {
            return null;
        }

        for (ECCurves c : VALUES) {
            List<? extends Number> v = c.getOIDValue();
            if (oid.size() != v.size()) {
                continue;
            }

            boolean matches = true;
            for (int index = 0; index < v.size(); index++) {
                Number exp = v.get(index);
                Number act = oid.get(index);
                if (exp.intValue() != act.intValue()) {
                    matches = false;
                    break;
                }
            }

            if (matches) {
                return c;
            }
        }

        return null;
    }

    public static ECCurves fromOID(String oid) {
        if (GenericUtils.isEmpty(oid)) {
            return null;
        }

        for (ECCurves c : VALUES) {
            if (oid.equalsIgnoreCase(c.getOID())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param  params                   The curve's {@link ECParameterSpec}
     * @return                          The curve's key size in bits
     * @throws IllegalArgumentException if invalid parameters provided
     */
    public static int getCurveSize(ECParameterSpec params) {
        EllipticCurve curve = Objects.requireNonNull(params, "No EC params").getCurve();
        ECField field = Objects.requireNonNull(curve, "No EC curve").getField();
        return Objects.requireNonNull(field, "No EC field").getFieldSize();
    }

    public static byte[] encodeECPoint(ECPoint group, ECParameterSpec params) {
        return encodeECPoint(group, params.getCurve());
    }

    public static byte[] encodeECPoint(ECPoint group, EllipticCurve curve) {
        // M has len 2 ceil(log_2(q)/8) + 1 ?
        int elementSize = (curve.getField().getFieldSize() + 7) / 8;
        byte[] m = new byte[2 * elementSize + 1];

        // Uncompressed format
        m[0] = 0x04;

        byte[] affineX = removeLeadingZeroes(group.getAffineX().toByteArray());
        System.arraycopy(affineX, 0, m, 1 + elementSize - affineX.length, affineX.length);

        byte[] affineY = removeLeadingZeroes(group.getAffineY().toByteArray());
        System.arraycopy(affineY, 0, m, 1 + elementSize + elementSize - affineY.length, affineY.length);

        return m;
    }

    private static byte[] removeLeadingZeroes(byte[] input) {
        if (input[0] != 0x00) {
            return input;
        }

        int pos = 1;
        while (pos < input.length - 1 && input[pos] == 0x00) {
            pos++;
        }

        byte[] output = new byte[input.length - pos];
        System.arraycopy(input, pos, output, 0, output.length);
        return output;
    }

    /**
     * Converts the given octet string (defined by ASN.1 specifications) to a {@link BigInteger} As octet strings always
     * represent positive integers, a zero-byte is prepended to the given array if necessary (if is MSB equal to 1),
     * then this is converted to BigInteger The conversion is defined in the Section 2.3.8
     *
     * @param  octets - octet string bytes to be converted
     * @return        The {@link BigInteger} representation of the octet string
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

    public static ECPoint octetStringToEcPoint(byte... octets) {
        if (NumberUtils.isEmpty(octets)) {
            return null;
        }

        int startIndex = findFirstNonZeroIndex(octets);
        if (startIndex < 0) {
            throw new IllegalArgumentException("All zeroes ECPoint N/A");
        }

        byte indicator = octets[startIndex];
        ECCurves.ECPointCompression compression = ECCurves.ECPointCompression.fromIndicatorValue(indicator);
        if (compression == null) {
            throw new UnsupportedOperationException(
                    "Unknown compression indicator value: 0x" + Integer.toHexString(indicator & 0xFF));
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

        return -1; // all zeroes
    }

    public static final class Constants {
        /**
         * Standard prefix of NISTP key types when encoded
         */
        public static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

        public static final String NISTP256 = "nistp256";
        public static final String NISTP384 = "nistp384";
        public static final String NISTP521 = "nistp521";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * The various {@link ECPoint} representation compression indicators
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     * @see    <A HREF="https://tools.ietf.org/html/rfc5480#section-2.2">RFC-5480 - section 2.2</A>
     */
    public enum ECPointCompression {
        // see http://tools.ietf.org/html/draft-jivsov-ecc-compact-00
        // see
        // http://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
        VARIANT2((byte) 0x02) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                byte[] xp = new byte[len];
                System.arraycopy(octets, startIndex, xp, 0, len);
                BigInteger x = octetStringToInteger(xp);

                // TODO derive even Y...
                throw new UnsupportedOperationException(
                        "octetStringToEcPoint(" + name() + ")(X=" + x + ") compression support N/A");
            }
        },
        VARIANT3((byte) 0x03) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                byte[] xp = new byte[len];
                System.arraycopy(octets, startIndex, xp, 0, len);
                BigInteger x = octetStringToInteger(xp);

                // TODO derive odd Y...
                throw new UnsupportedOperationException(
                        "octetStringToEcPoint(" + name() + ")(X=" + x + ") compression support N/A");
            }
        },
        UNCOMPRESSED((byte) 0x04) {
            @Override
            public ECPoint octetStringToEcPoint(byte[] octets, int startIndex, int len) {
                int numElements = len / 2; /* x, y */
                if (len != (numElements * 2)) { // make sure length is not odd
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
                ECCurves curve = fromCurveName(curveName);
                if (curve == null) {
                    throw new StreamCorruptedException(
                            "writeECPoint(" + name() + ")[" + curveName + "] cannot determine octets count");
                }

                int numElements = curve.getNumPointOctets();
                KeyEntryResolver.encodeInt(s, 1 /* the indicator */ + 2 * numElements);
                s.write(getIndicatorValue());
                writeCoordinate(s, "X", p.getAffineX(), numElements);
                writeCoordinate(s, "Y", p.getAffineY(), numElements);
            }
        };

        public static final Set<ECPointCompression> VALUES
                = Collections.unmodifiableSet(EnumSet.allOf(ECPointCompression.class));

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
                throw new UncheckedIOException("ecPointToOctetString(" + curveName + ")"
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
                if (vp[0] == 0) { // skip artificial positive sign
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
                startIndex = 0;
                vLen = vp.length;
            }

            s.write(vp, startIndex, vLen);
        }

        public static ECPointCompression fromIndicatorValue(int value) {
            if ((value < 0) || (value > 0xFF)) {
                return null; // must be a byte value
            }

            for (ECPointCompression c : VALUES) {
                if (value == c.getIndicatorValue()) {
                    return c;
                }
            }

            return null;
        }
    }
}
