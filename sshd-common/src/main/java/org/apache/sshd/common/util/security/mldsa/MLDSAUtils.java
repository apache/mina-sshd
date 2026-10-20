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
package org.apache.sshd.common.util.security.mldsa;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.io.der.DERWriter;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Utilities to extract ML-DSA key bytes and construct keys using RFC 9881 encodings.
 *
 * @see    <a href="https://www.rfc-editor.org/rfc/rfc9881">RFC 9881</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MLDSAUtils {
    private static final byte[] OID_PREFIX = { 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };

    private MLDSAUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * Retrieves the parameter set of an ML-DSA key.
     *
     * @param  key                     the key
     * @return                         the parameter set
     * @throws InvalidKeySpecException if the key is not an ML-DSA key or its encoding is invalid
     */
    public static MLDSAParameterSets getParameters(Key key) throws InvalidKeySpecException {
        Objects.requireNonNull(key, "No key provided");
        String algorithm = key.getAlgorithm();
        MLDSAParameterSets named = MLDSAParameterSets.fromJceName(algorithm);
        if (named == null
                && !SecurityUtils.ML_DSA.equalsIgnoreCase(algorithm)
                && !"MLDSA".equalsIgnoreCase(algorithm)) {
            throw new InvalidKeySpecException("Not an ML-DSA key: " + algorithm);
        }
        if (named != null && key.getEncoded() == null) {
            return named;
        }
        try (KeyDERParser encoded = sequence(key.getEncoded())) {
            if (key instanceof PrivateKey) {
                encoded.readObject(0x02);
            }
            MLDSAParameterSets params = readAlgorithm(encoded);
            if (named != null && named != params) {
                throw new InvalidKeySpecException("ML-DSA algorithm and OID disagree");
            }
            return params;
        } catch (IOException e) {
            throw new InvalidKeySpecException("Invalid ML-DSA key encoding", e);
        }
    }

    /**
     * Retrieves the raw bytes from an ML-DSA public key.
     *
     * @param  key                     the public key
     * @return                         the raw public key bytes
     * @throws InvalidKeySpecException if the public key encoding is invalid
     */
    public static byte[] getRawBytes(PublicKey key) throws InvalidKeySpecException {
        Objects.requireNonNull(key, "No public key provided");
        try (KeyDERParser encoded = sequence(key.getEncoded())) {
            MLDSAParameterSets params = readAlgorithm(encoded);
            byte[] bits = encoded.readObject(0x03).getValue();
            encoded.requireEnd();
            if (bits.length != params.getPublicKeySize() + 1 || bits[0] != 0) {
                throw new InvalidKeySpecException("Invalid ML-DSA public key BIT STRING");
            }
            MLDSAParameterSets named = MLDSAParameterSets.fromJceName(key.getAlgorithm());
            if (named != null && named != params) {
                throw new InvalidKeySpecException("ML-DSA algorithm and OID disagree");
            }
            return Arrays.copyOfRange(bits, 1, bits.length);
        } catch (IOException e) {
            throw new InvalidKeySpecException("Invalid ML-DSA public key encoding", e);
        }
    }

    /**
     * Constructs an ML-DSA public key from raw bytes.
     *
     * @param  params                   the parameter set
     * @param  raw                      the raw public key bytes
     * @return                          the public key
     * @throws GeneralSecurityException if the bytes have the wrong length or the key cannot be constructed
     */
    public static PublicKey getPublicKey(MLDSAParameterSets params, byte[] raw) throws GeneralSecurityException {
        Objects.requireNonNull(params, "No ML-DSA parameters provided");
        requireLength(raw, params.getPublicKeySize(), "public key");
        byte[] bits = new byte[raw.length + 1];
        System.arraycopy(raw, 0, bits, 1, raw.length);
        try {
            byte[] encoded = encode(0x30, algorithm(params), encode(0x03, bits));
            return SecurityUtils.getKeyFactory(params.getJceName()).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (IOException e) {
            throw new InvalidKeySpecException("Cannot encode ML-DSA public key", e);
        }
    }

    private static void requireLength(byte[] value, int size, String what) throws InvalidKeySpecException {
        try {
            ValidateUtils.checkTrue(value != null && value.length == size,
                    "ML-DSA %s must contain %d bytes", what, size);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    private static MLDSAParameterSets readAlgorithm(KeyDERParser encoded) throws IOException, InvalidKeySpecException {
        try (KeyDERParser algorithm = new KeyDERParser(encoded.readObject(0x30).getValue())) {
            byte[] oid = algorithm.readObject(0x06).getValue();
            algorithm.requireEnd(); // RFC 9881 parameters MUST be absent.
            if (oid.length == OID_PREFIX.length + 1
                    && Arrays.equals(OID_PREFIX, Arrays.copyOf(oid, OID_PREFIX.length))) {
                for (MLDSAParameterSets params : MLDSAParameterSets.values()) {
                    if (oid[OID_PREFIX.length] == params.getOid()) {
                        return params;
                    }
                }
            }
        }
        throw new InvalidKeySpecException("Unknown ML-DSA algorithm OID");
    }

    private static byte[] algorithm(MLDSAParameterSets params) throws IOException {
        return encode(0x30, encode(0x06, OID_PREFIX, new byte[] { (byte) params.getOid() }));
    }

    private static KeyDERParser sequence(byte[] bytes) throws IOException, InvalidKeySpecException {
        if (bytes == null) {
            throw new InvalidKeySpecException("Key has no encoding");
        }
        try (KeyDERParser input = new KeyDERParser(bytes)) {
            ASN1Object sequence = input.readObject(0x30);
            input.requireEnd();
            return new KeyDERParser(sequence.getValue());
        }
    }

    private static byte[] encode(int tag, byte[]... values) throws IOException {
        try (DERWriter writer = new DERWriter()) {
            int length = 0;
            for (byte[] value : values) {
                length += value.length;
            }
            writer.write(tag);
            writer.writeLength(length);
            for (byte[] value : values) {
                writer.write(value);
            }
            return writer.toByteArray();
        }
    }

    private static final class KeyDERParser extends DERParser {
        KeyDERParser(byte[] bytes) {
            super(bytes);
        }

        ASN1Object readObject(int tag) throws IOException {
            mark(1);
            int actual = read();
            reset();
            if (actual != tag) {
                throw new IOException("Unexpected DER tag: " + actual);
            }
            return readObject();
        }

        void requireEnd() throws IOException {
            if (read() != -1) {
                throw new IOException("Trailing DER data");
            }
        }

        @Override
        public int readLength() throws IOException {
            int remaining = available();
            int length = super.readLength();
            // DERParser does not reject all non-minimal length encodings.
            int expected = length < 128 ? 1 : 1 + (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
            if (remaining - available() != expected) {
                throw new IOException("Non-minimal DER length");
            }
            return length;
        }
    }
}
