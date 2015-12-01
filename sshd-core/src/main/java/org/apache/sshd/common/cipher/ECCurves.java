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

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Utilities for working with elliptic curves.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum ECCurves implements NamedResource, OptionalFeature {
    nistp256(Constants.NISTP256,
            new ECParameterSpec(
                    new EllipticCurve(
                            new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                            new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                            new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)),
                    new ECPoint(
                            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)),
                    new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
                    1),
            32,
            BuiltinDigests.sha256),
    nistp384(Constants.NISTP384,
            new ECParameterSpec(
                    new EllipticCurve(
                            new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)),
                            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
                            new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)),
                    new ECPoint(
                            new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
                            new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)),
                    new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
                    1),
            48,
            BuiltinDigests.sha384),
    nistp521(Constants.NISTP521,
            new ECParameterSpec(
                    new EllipticCurve(
                            new ECFieldFp(new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                                          + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                            new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                                + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                            new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951"
                                            + "EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)),
                    new ECPoint(
                            new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77"
                                            + "EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
                            new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE7299"
                                            + "5EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)),
                    new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B"
                                    + "7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
                    1),
            66,
            BuiltinDigests.sha512);

    /**
     * A {@link Set} of all the known curves
     */
    public static final Set<ECCurves> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(ECCurves.class));

    /**
     * A {@link Set} of all the known curves names
     */
    public static final Set<String> NAMES =
            Collections.unmodifiableSet(new TreeSet<String>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    for (ECCurves c : VALUES) {
                        add(c.getName());
                    }
                }
            });

    /**
     * A {@link Set} of all the known curves key types
     */
    public static final Set<String> KEY_TYPES =
            Collections.unmodifiableSet(new TreeSet<String>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    for (ECCurves c : VALUES) {
                        add(c.getKeyType());
                    }
                }
            });

    private final String name;
    private final String keyType;
    private final ECParameterSpec params;
    private final int keySize;
    private final int numOctets;
    private final DigestFactory digestFactory;

    ECCurves(String name, ECParameterSpec params, int numOctets, DigestFactory digestFactory) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No curve name");
        this.keyType = Constants.ECDSA_SHA2_PREFIX + name;
        this.params = ValidateUtils.checkNotNull(params, "No EC params for %s", name);
        this.keySize = getCurveSize(params);
        this.numOctets = numOctets;
        this.digestFactory = ValidateUtils.checkNotNull(digestFactory, "No digestFactory");
    }

    @Override   // The curve name
    public final String getName() {
        return name;
    }

    /**
     * @return The standard key type used to represent this curve
     */
    public final String getKeyType() {
        return keyType;
    }

    @Override
    public final boolean isSupported() {
        return SecurityUtils.hasEcc() && digestFactory.isSupported();
    }

    public final ECParameterSpec getParameters() {
        return params;
    }

    /**
     * @return The size (in bits) of the key
     */
    public final int getKeySize() {
        return keySize;
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
     * @param type The key type value - ignored if {@code null}/empty
     * @return The matching {@link ECCurves} constant - {@code null} if
     * no match found case <U>insensitive</U>
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
     * @param name The curve name (case <U>insensitive</U> - ignored if
     *             {@code null}/empty
     * @return The matching {@link ECCurves} instance - {@code null} if no
     * match found
     */
    public static ECCurves fromCurveName(String name) {
        return NamedResource.Utils.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param params The curve's {@link ECParameterSpec} - ignored if {@code null}
     * @return The matching {@link ECCurves} value - {@code null} if no match found
     * @see #getCurveSize(ECParameterSpec)
     * @see #fromCurveSize(int)
     */
    public static ECCurves fromCurveParameters(ECParameterSpec params) {
        if (params == null) {
            return null;
        } else {
            return fromCurveSize(getCurveSize(params));
        }
    }

    /**
     * @param keySize The key size (in bits)
     * @return The matching {@link ECCurves} value - {@code null} if no
     * match found
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

    /**
     * @param params The curve's {@link ECParameterSpec}
     * @return The curve's key size in bits
     * @throws IllegalArgumentException if invalid parameters provided
     */
    public static int getCurveSize(ECParameterSpec params) {
        EllipticCurve curve = ValidateUtils.checkNotNull(params, "No EC params").getCurve();
        ECField field = ValidateUtils.checkNotNull(curve, "No EC curve").getField();
        return ValidateUtils.checkNotNull(field, "No EC field").getFieldSize();
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

    public static final class Constants {
        /**
         * Standard prefix of NISTP key types when encoded
         */
        public static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

        public static final String NISTP256 = "nistp256";
        public static final String NISTP384 = "nistp384";
        public static final String NISTP521 = "nistp521";
    }
}
