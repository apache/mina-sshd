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
package org.apache.sshd.common.util.security.eddsa.generic;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Utilities to extract the raw key bytes from ed25519 or ed448 keys or to construct such keys from the raw key bytes,
 * in a manner that is independent of the actual concrete key implementation classes.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EdDSAUtils {

    private static final int ED25519_LENGTH = 32; // bytes

    private static final int ED448_LENGTH = 57; // bytes

    // These are the constant prefixes of X.509 encodings of ed25519 and ed448 keys. Appending the actual 32
    // or 57 key bytes yields valid encodings.

    // Sequence, length 42, Sequence, length 5, OID, length 3, O, I, D, Bit String, length 33, zero unused bits
    private static final byte[] ED25519_X509_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    // Sequence, length 67, Sequence, length 5, OID, length 3, O, I, D, Bit String, length 58, zero unused bits
    private static final byte[] ED448_X509_PREFIX = {
            0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00 };

    // For reconstructing private keys from raw bytes we construct a minimal PKCS#8 encoding, using RFC 5208 (version 0)
    // without the public key and without attributes. This is allowed by RFC 5958 (Asymmetric key packages).

    // Sequence, length 46, (3 bytes: Version 0), Sequence, length 5, OID, length 3, O, I, D, Octet String, length 34,
    // Octet String, length 32
    private static final byte[] ED25519_PKCS8_PREFIX = {
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20 };
    // Sequence, length 71, (3 bytes: Version 0), Sequence, length 5, OID, length 3, O, I, D, Octet String, length 59,
    // Octet String, length 57
    private static final byte[] ED448_PKCS8_PREFIX = {
            0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71,
            0x04, 0x3b, 0x04, 0x39 };

    // The first two numbers of the dotted notation are combined into one byte: (1 * 40 + 3) = 43 = 0x2b
    private static final byte[] ED25519_OID = { 0x2b, 0x65, 0x70 }; // 1.3.101.112
    private static final byte[] ED448_OID = { 0x2b, 0x65, 0x71 }; // 1.3.101.113

    private EdDSAUtils() {
        throw new IllegalStateException("No instantiation");
    }

    private static boolean arrayEq(byte[] a, byte[] b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        int unequal = a.length ^ b.length;
        int length = Math.min(a.length, b.length);
        for (int i = 0; i < length; i++) {
            unequal |= a[i] ^ b[i];
        }
        return unequal == 0;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data == null || prefix == null || prefix.length == 0 || data.length < prefix.length) {
            return false;
        }
        int unequal = 0;
        int length = prefix.length;
        for (int i = 0; i < length; i++) {
            unequal |= data[i] ^ prefix[i];
        }
        return unequal == 0;
    }

    /**
     * Retrieves the raw key bytes from an ed25519 or ed448 {@link PublicKey}.
     *
     * @param  key                      {@link PublicKey} to get the bytes of
     * @return                          the raw key bytes
     * @throws IllegalArgumentException if the key is not an ed25519 or ed448 key, or if it doesn't use X.509 encoding
     */
    public static byte[] getBytes(PublicKey key) throws IllegalArgumentException {
        // Extract the public key bytes from the X.509 encoding (last n bytes, depending on the OID).
        if (!"X.509".equalsIgnoreCase(key.getFormat())) {
            throw new IllegalArgumentException("Cannot extract public key bytes from a non-X.509 encoding");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new IllegalArgumentException(
                    "Public key " + key.getClass().getCanonicalName() + " does not support encoding");
        }
        int n;
        if (encoded.length == ED25519_LENGTH + ED25519_X509_PREFIX.length && startsWith(encoded, ED25519_X509_PREFIX)) {
            n = ED25519_LENGTH;
        } else if (encoded.length == ED448_LENGTH + ED448_X509_PREFIX.length && startsWith(encoded, ED448_X509_PREFIX)) {
            n = ED448_LENGTH;
        } else {
            throw new IllegalArgumentException("Public key is neither ed25519 nor ed448");
        }
        return Arrays.copyOfRange(encoded, encoded.length - n, encoded.length);
    }

    /**
     * Retrieves the raw key bytes from an ed25519 or ed448 {@link PrivateKey}.
     *
     * @param  key                      {@link PrivateKey} to get the bytes of
     * @return                          the raw key bytes
     * @throws IllegalArgumentException if the key is not an ed25519 or ed448 key, or if it doesn't use PKCS#8 encoding
     */
    public static byte[] getBytes(PrivateKey key) throws IllegalArgumentException {
        // Extract the private key bytes from the PKCS#8 encoding.
        if (!"PKCS#8".equalsIgnoreCase(key.getFormat())) {
            throw new IllegalArgumentException("Cannot extract private key bytes from a non-PKCS#8 encoding");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new IllegalArgumentException(
                    "Private key " + key.getClass().getCanonicalName() + " does not support encoding");
        }
        try {
            return asn1Parse(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Extracts the private key bytes from an encoded EdDSA private key by parsing the bytes as ASN.1 according to RFC
     * 5958 (PKCS #8 encoding):
     *
     * <pre>
     * OneAsymmetricKey ::= SEQUENCE {
     *   version Version,
     *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     *   privateKey PrivateKey,
     *   ...
     * }
     *
     * Version ::= INTEGER
     * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     * PrivateKey ::= OCTET STRING
     *
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *   algorithm   OBJECT IDENTIFIER,
     *   parameters  ANY DEFINED BY algorithm OPTIONAL
     * }
     * </pre>
     * <p>
     * and RFC 8410: "... when encoding a OneAsymmetricKey object, the private key is wrapped in a CurvePrivateKey
     * object and wrapped by the OCTET STRING of the 'privateKey' field."
     * </p>
     *
     * <pre>
     * CurvePrivateKey ::= OCTET STRING
     * </pre>
     *
     * @param  encoded                  encoded private key to extract the private key bytes from
     * @return                          the extracted private key bytes
     * @throws IllegalArgumentException if the private key cannot be extracted
     * @see                             <a href="https://tools.ietf.org/html/rfc5958">RFC 5958</a>
     * @see                             <a href="https://tools.ietf.org/html/rfc8410">RFC 8410</a>
     */
    private static byte[] asn1Parse(byte[] encoded) throws IllegalArgumentException {
        byte[] privateKey = null;
        try (DERParser byteParser = new DERParser(encoded);
             DERParser oneAsymmetricKey = byteParser.readObject().createParser()) {
            oneAsymmetricKey.readObject(); // Skip version
            int n;
            try (DERParser algorithmIdentifier = oneAsymmetricKey.readObject().createParser()) {
                byte[] oid = algorithmIdentifier.readObject().getValue();
                if (arrayEq(ED25519_OID, oid)) {
                    n = ED25519_LENGTH;
                } else if (arrayEq(ED448_OID, oid)) {
                    n = ED448_LENGTH;
                } else {
                    throw new IllegalArgumentException("Private key is neither ed25519 nor ed448");
                }
            }
            privateKey = oneAsymmetricKey.readObject().getValue();
            // The last n bytes of this must be the private key bytes.
            return Arrays.copyOfRange(privateKey, privateKey.length - n, privateKey.length);
            // Depending on the version there may be optional stuff following, but we don't care about that.
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot parse EdDSA private key", e);
        } finally {
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
            }
        }
    }

    /**
     * Creates a {@link KeySpec} for re-creating the given ed25519 or ed448 public key.
     *
     * @param  key                 ed25519 or ed448 key to create a {@link KeySpec} for
     * @return                     the {@link KeySpec}
     * @throws InvalidKeyException if the key is neither an ed25519 nor an ed448 key
     */
    public static KeySpec createKeySpec(PublicKey key) throws InvalidKeyException {
        return createPublicKeySpec(getBytes(key));
    }

    /**
     * Creates a {@link KeySpec} for re-creating the given ed25519 or ed448 private key.
     *
     * @param  key                 ed25519 or ed448 key to create a {@link KeySpec} for
     * @return                     the {@link KeySpec}
     * @throws InvalidKeyException if the key is neither an ed25519 nor an ed448 key
     */
    public static KeySpec createKeySpec(PrivateKey key) throws InvalidKeyException {
        return createPrivateKeySpec(getBytes(key));
    }

    /**
     * Creates a {@link KeySpec} for re-creating an ed25519 or ed448 public key from the raw key bytes.
     *
     * @param  keyData             the raw key bytes
     * @return                     the {@link KeySpec}
     * @throws InvalidKeyException if the key bytes do not have the appropriate length for an ed25519 or ed448 key
     */
    public static KeySpec createPublicKeySpec(byte[] keyData) throws InvalidKeyException {
        // Create an X.509 encoding for ed25519 or ed448, depending on the length of keyData.
        if (keyData.length == ED25519_LENGTH) {
            byte[] x509 = Arrays.copyOf(ED25519_X509_PREFIX, ED25519_X509_PREFIX.length + ED25519_LENGTH);
            System.arraycopy(keyData, 0, x509, ED25519_X509_PREFIX.length, ED25519_LENGTH);
            return new X509EncodedKeySpec(x509);
        } else if (keyData.length == ED448_LENGTH) {
            byte[] x509 = Arrays.copyOf(ED448_X509_PREFIX, ED448_X509_PREFIX.length + ED448_LENGTH);
            System.arraycopy(keyData, 0, x509, ED448_X509_PREFIX.length, ED448_LENGTH);
            return new X509EncodedKeySpec(x509);
        }
        throw new InvalidKeyException("Public key data is neither ed25519 nor ed448");
    }

    /**
     * Creates a {@link KeySpec} for re-creating an ed25519 or ed448 public key from the raw key bytes.
     *
     * @param  keyData             the raw key bytes
     * @return                     the {@link KeySpec}
     * @throws InvalidKeyException if the key bytes do not have the appropriate length for an ed25519 or ed448 key
     */
    public static KeySpec createPrivateKeySpec(byte[] keyData) throws InvalidKeyException {
        // Create a PKCS#8 encoding for ed25519 or ed448, depending on the length of keyData.
        if (keyData.length == ED25519_LENGTH) {
            byte[] pkcs8 = Arrays.copyOf(ED25519_PKCS8_PREFIX, ED25519_PKCS8_PREFIX.length + ED25519_LENGTH);
            try {
                System.arraycopy(keyData, 0, pkcs8, ED25519_PKCS8_PREFIX.length, ED25519_LENGTH);
                return new PKCS8EncodedKeySpec(pkcs8);
            } finally {
                Arrays.fill(pkcs8, (byte) 0);
            }
        } else if (keyData.length == ED448_LENGTH) {
            byte[] pkcs8 = Arrays.copyOf(ED448_PKCS8_PREFIX, ED448_PKCS8_PREFIX.length + ED448_LENGTH);
            try {
                System.arraycopy(keyData, 0, pkcs8, ED448_PKCS8_PREFIX.length, ED448_LENGTH);
                return new PKCS8EncodedKeySpec(pkcs8);
            } finally {
                Arrays.fill(pkcs8, (byte) 0);
            }
        }
        throw new InvalidKeyException("Private key data is neither ed25519 nor ed448");
    }

    /**
     * Creates a {@link PublicKey} from the raw key bytes of an ed25519 or ed448 key.
     *
     * @param  keyData                  the raw key bytes
     * @return                          the {@link PublicKey}
     * @throws GeneralSecurityException if the key cannot be created
     */
    public static PublicKey getPublicKey(byte[] keyData) throws GeneralSecurityException {
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.ED25519);
        return factory.generatePublic(createPublicKeySpec(keyData));
    }

    /**
     * Creates a {@link PrivateKey} from the raw key bytes of an ed25519 or ed448 key.
     *
     * @param  keyData                  the raw key bytes
     * @return                          the {@link PrivateKey}
     * @throws GeneralSecurityException if the key cannot be created
     */
    public static PrivateKey getPrivateKey(byte[] keyData) throws GeneralSecurityException {
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.ED25519);
        return factory.generatePrivate(createPrivateKeySpec(keyData));
    }

    /**
     * Compares two ed25519 or two ed448 {@link PublicKey}s.
     *
     * @param  k1                       first {@link PublicKey}
     * @param  k2                       second {@link PublicKey}
     * @return                          if the two keys are equal
     * @throws IllegalArgumentException if one of the keys is neither an ed25519 nor an ed448 key
     */
    public static boolean equals(PublicKey k1, PublicKey k2) throws IllegalArgumentException {
        return arrayEq(getBytes(k1), getBytes(k2));
    }

    /**
     * Compares two ed25519 or two ed448 {@link PrivateKey}s.
     *
     * @param  k1                       first {@link PrivateKey}
     * @param  k2                       second {@link PrivateKey}
     * @return                          if the two keys are equal
     * @throws IllegalArgumentException if one of the keys is neither an ed25519 nor an ed448 key
     */
    public static boolean equals(PrivateKey k1, PrivateKey k2) throws IllegalArgumentException {
        byte[] k1Data = null;
        byte[] k2Data = null;
        try {
            k1Data = getBytes(k1);
            k2Data = getBytes(k2);
            return arrayEq(k1Data, k2Data);
        } finally {
            if (k1Data != null) {
                Arrays.fill(k1Data, (byte) 0);
            }
            if (k2Data != null) {
                Arrays.fill(k2Data, (byte) 0);
            }
        }
    }
}
