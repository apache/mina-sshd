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
package org.apache.sshd.common.cipher;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Utilities for working with elliptic curves.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ECCurves {
    public static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

    public static final String NISTP256 = "nistp256";

    public static final String NISTP384 = "nistp384";

    public static final String NISTP521 = "nistp521";


    public static String getCurveName(ECParameterSpec params) {
        int fieldSize = getCurveSize(params);
        final String curveName = getCurveName(fieldSize);
        if (GenericUtils.isEmpty(curveName)) {
            throw new RuntimeException("invalid curve size " + fieldSize);
        }
        return curveName;
    }

    /**
     * Key=curve name, value=num. of bits
     */
    private static final Map<String,Integer> CURVENAME2SIZE =
            Collections.unmodifiableMap(new TreeMap<String,Integer>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it
                
                {
                    put(NISTP256, Integer.valueOf(256));
                    put(NISTP384, Integer.valueOf(384));
                    put(NISTP521, Integer.valueOf(521));
                }
        
            });

    /**
     * An un-modifiable {@link List} of all the known curve names
     */
    @SuppressWarnings("synthetic-access")
    public static final List<String> NAMES =
            Collections.unmodifiableList(new ArrayList<String>(CURVENAME2SIZE.size()) {
                private static final long serialVersionUID = 1L;    // we're not serializing it
                
                {
                    addAll(CURVENAME2SIZE.keySet());
                    Collections.sort(this); // as a courtesy
                }
            });

    /**
     * An un-modifiable {@link List} of all the known curve types according to {@code OpenSSH}
     */
    public static final List<String> TYPES =
            Collections.unmodifiableList(new ArrayList<String>(CURVENAME2SIZE.size()) {
                private static final long serialVersionUID = 1L;    // we're not serializing it
                
                {
                    for (String n : NAMES) {
                        add(ECDSA_SHA2_PREFIX + n);
                    }

                    Collections.sort(this); // as a courtesy
                }
            });
    /**
     * An un-modifiable {@link List} of all the known curve sizes
     */
    @SuppressWarnings("synthetic-access")
    public static final List<Integer> SIZES =
            Collections.unmodifiableList(new ArrayList<Integer>(CURVENAME2SIZE.size()) {
                    private static final long serialVersionUID = 1L;    // we're not serializing it
                
                    {
                        addAll(CURVENAME2SIZE.values());
                        Collections.sort(this); // as a courtesy
                    }
            });
    
    /**
     * @param name The curve name - ignored if {@code null}/empty
     * @return The curve size - {@code null} if unknown curve
     */
    public static Integer getCurveSize(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        } else {
            return CURVENAME2SIZE.get(name);
        }
    }

    /**
     * Key=num. of bits, value=curve name
     */
    @SuppressWarnings("synthetic-access")
    private static final Map<Integer, String> SIZE2CURVENAME = 
            Collections.unmodifiableMap(new TreeMap<Integer, String>() {
                private static final long serialVersionUID = 1L;    // we're not serializing it
        
                {
                    for (Map.Entry<String,Integer> e : CURVENAME2SIZE.entrySet()) {
                        String name = e.getKey();
                        Integer size = e.getValue();
                        put(size, name);
                    }
                }
            });

    /**
     * @param fieldSize The key size in bits
     * @return The name of the curve - {@code null/empty} if no match found
     */
    public static String getCurveName(int fieldSize) {
        return SIZE2CURVENAME.get(Integer.valueOf(fieldSize));
    }

    private static final Map<String, Integer> CURVENAME2OCTECTCOUNT = 
            Collections.unmodifiableMap(new TreeMap<String, Integer>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it
        
                {
                    put(NISTP256, Integer.valueOf(32));
                    put(NISTP384, Integer.valueOf(48));
                    put(NISTP521, Integer.valueOf(66));
                }
            });

    /**
     * @param curveName Curve name - case <U>insensitive</U> - ignored
     * if {@code null}/empty
     * @return The number of octets used to represent the point(s) for
     * the curve - {@code null} if no match found
     */
    public static Integer getNumPointOctets(String curveName) {
        if (GenericUtils.isEmpty(curveName)) {
            return null;
        } else {
            return CURVENAME2OCTECTCOUNT.get(curveName);
        }
    }

    public static int getCurveSize(ECParameterSpec params) {
        EllipticCurve   curve = ValidateUtils.checkNotNull(params, "No EC params", GenericUtils.EMPTY_OBJECT_ARRAY).getCurve();
        ECField field = ValidateUtils.checkNotNull(curve, "No EC curve", GenericUtils.EMPTY_OBJECT_ARRAY).getField();
        return ValidateUtils.checkNotNull(field, "No EC field", GenericUtils.EMPTY_OBJECT_ARRAY).getFieldSize();
    }

    public static Digest getDigestForParams(ECParameterSpec params) {
        int size = getCurveSize(params);
        if (size <= 256) {
            return BuiltinDigests.sha256.create();
        } else if (size <= 384) {
            return BuiltinDigests.sha384.create();
        } else if (size <= 521) {
            return BuiltinDigests.sha512.create();
        } else {
            throw new UnsupportedOperationException("Unsupported curve size for digest: " + size);
        }
    }

    /**
     * Decode an OctetString to EllipticCurvePoint according to SECG 2.3.4
     */
    public static ECPoint decodeECPoint(byte[] M, EllipticCurve curve) {
        if (M.length == 0) {
            return null;
        }

        // M has len 2 ceil(log_2(q)/8) + 1 ?
        int elementSize = (curve.getField().getFieldSize() + 7) / 8;
        if (M.length != 2 * elementSize + 1) {
            return null;
        }

        // step 3.2
        if (M[0] != 0x04) {
            return null;
        }

        // Step 3.3
        byte[] xp = new byte[elementSize];
        System.arraycopy(M, 1, xp, 0, elementSize);

        // Step 3.4
        byte[] yp = new byte[elementSize];
        System.arraycopy(M, 1 + elementSize, yp, 0, elementSize);

        ECPoint P = new ECPoint(new BigInteger(1, xp), new BigInteger(1, yp));

        // TODO check point 3.5

        // Step 3.6
        return P;
    }

    /**
     * Encode EllipticCurvePoint to an OctetString
     */
    public static byte[] encodeECPoint(ECPoint group, EllipticCurve curve) {
        // M has len 2 ceil(log_2(q)/8) + 1 ?
        int elementSize = (curve.getField().getFieldSize() + 7) / 8;
        byte[] M = new byte[2 * elementSize + 1];

        // Uncompressed format
        M[0] = 0x04;

        {
            byte[] affineX = removeLeadingZeroes(group.getAffineX().toByteArray());
            System.arraycopy(affineX, 0, M, 1 + elementSize - affineX.length, affineX.length);
        }

        {
            byte[] affineY = removeLeadingZeroes(group.getAffineY().toByteArray());
            System.arraycopy(affineY, 0, M, 1 + elementSize + elementSize - affineY.length, affineY.length);
        }

        return M;
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

    public static class EllipticCurves {
        public static ECParameterSpec nistp256 = new ECParameterSpec(
                new EllipticCurve(
                        new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                        new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)),
                new ECPoint(
                        new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
                        new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)),
                new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
                1);

        public static ECParameterSpec nistp384 = new ECParameterSpec(
                new EllipticCurve(
                        new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)),
                        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
                        new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)),
                new ECPoint(
                        new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
                        new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
                1);

        public static ECParameterSpec nistp521 = new ECParameterSpec(
                new EllipticCurve(
                        new ECFieldFp(new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)),
                        new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
                        new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)),
                new ECPoint(
                        new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
                        new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)),
                new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
                1);
    }
    
    private static final class LazySpecsMapHolder {
        private static final Map<String,ECParameterSpec> specsMap =
                Collections.unmodifiableMap(new TreeMap<String,ECParameterSpec>(String.CASE_INSENSITIVE_ORDER) {
                        private static final long serialVersionUID = 1L;    // we're not serializing it
                    
                        {
                            put(NISTP256, EllipticCurves.nistp256);
                            put(NISTP384, EllipticCurves.nistp384);
                            put(NISTP521, EllipticCurves.nistp521);
                        }
                });
    }

    @SuppressWarnings("synthetic-access")
    public static ECParameterSpec getECParameterSpec(String curveName) {
        if (GenericUtils.isEmpty(curveName)) {
            return null;
        } else {
            return LazySpecsMapHolder.specsMap.get(curveName);
        }
    }
}
