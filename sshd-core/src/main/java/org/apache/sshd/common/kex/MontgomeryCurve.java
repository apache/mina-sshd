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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Provides implementation details for Montgomery curves and their key exchange algorithms Curve25519/X25519 and
 * Curve448/X448 specified in RFC 7748 and RFC 8731. Montgomery curves provide improved security and flexibility over
 * Weierstrass curves used in ECDH.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7748">RFC 7748</a>
 * @see <a href="https://tools.ietf.org/html/rfc8731">RFC 8731</a>
 */
public enum MontgomeryCurve implements KeySizeIndicator, OptionalFeature {

    /**
     * The "magic" bytes below are the beginning of a DER encoding of the ASN.1 of the SubjectPublicKeyInfo as specified
     * in <a href="https://tools.ietf.org/html/rfc8410">RFC 8410</a>, sections 3 and 4.
     *
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *   algorithm   OBJECT IDENTIFIER,
     *   parameters  ANY DEFINED BY algorithm OPTIONAL -- absent for these keys
     * }
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *   algorithm AlgorithmIdentifier,
     *   subjectPublicKey BIT STRING
     * }
     * </pre>
     * <p>
     * If we take it apart the first one for x25519:
     * </p>
     *
     * <pre>
     *   0x30  - SEQUENCE (start of SubjectPublicKeyInfo)
     *   0x2a  -  of 42 bytes
     *     0x30  - SEQUENCE (start of AlgorithmIdentifier)
     *     0x05  -  of 5 bytes
     *       0x06  - OID
     *       0x03  -  of 3 bytes
     *         0x2b  -  1 3 (encoded as 1*40 + 3 = 43 = 0x2b)
     *         0x65  -  101
     *         0x6e  -  110
     *     0x03  - BIT STRING
     *     0x21  -  of 33 bytes
     *         0x00  -  NUL byte
     * </pre>
     * <p>
     * If one appends now the 32 public key bytes, the DER encoding for the x25519 public key is complete. The NUL byte
     * at the end ensures that the raw key bytes appended are always interpreted as unsigned, even if the most
     * significant bit is set.
     * </p>
     * <p>
     * The OID for x25519 is { 1 3 101 110 }, for x448 { 1 3 101 111 }.
     * </p>
     */

    /**
     * X25519 uses Curve25519 and SHA-256 with a 32-byte key size.
     */
    x25519("X25519", 32, BuiltinDigests.sha256,
           new byte[] { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00 }),

    /**
     * X448 uses Curve448 and SHA-512 with a 56-byte key size.
     */
    x448("X448", 56, BuiltinDigests.sha512,
         new byte[] { 0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00 });

    private final String algorithm;
    private final int keySize;
    private final boolean supported;
    private final DigestFactory digestFactory;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyFactory keyFactory;
    private final byte[] encodedPublicKeyPrefix;

    MontgomeryCurve(String algorithm, int keySize, DigestFactory digestFactory, byte[] encodedPublicKeyPrefix) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.digestFactory = digestFactory;
        this.encodedPublicKeyPrefix = encodedPublicKeyPrefix;
        boolean supported;
        KeyPairGenerator generator = null;
        KeyFactory factory = null;
        try {
            SecurityUtils.getKeyAgreement(algorithm);
            generator = SecurityUtils.getKeyPairGenerator(algorithm);
            factory = SecurityUtils.getKeyFactory(algorithm);
            supported = true;
        } catch (GeneralSecurityException ignored) {
            supported = false;
        }
        this.supported = supported && digestFactory.isSupported();
        keyPairGenerator = generator;
        keyFactory = factory;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    public boolean isSupported() {
        return supported;
    }

    public KeyAgreement createKeyAgreement() throws GeneralSecurityException {
        return SecurityUtils.getKeyAgreement(algorithm);
    }

    public Digest createDigest() {
        return digestFactory.create();
    }

    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] encode(PublicKey key) throws InvalidKeyException {
        // Per the ASN.1 of SubjectPublicKeyInfo, the key must be the last keySize bytes of the X.509 encoding
        byte[] subjectPublicKeyInfo = key.getEncoded();
        byte[] result = Arrays.copyOfRange(subjectPublicKeyInfo, subjectPublicKeyInfo.length - getKeySize(),
                subjectPublicKeyInfo.length);
        return result;
    }

    public PublicKey decode(byte[] key) throws InvalidKeySpecException {
        int size = getKeySize();
        int offset = key.length - size;
        // We're lenient here and accept a key prefixed by a zero byte.
        if (offset < 0 || offset > 1) {
            throw new InvalidKeySpecException("Provided key has wrong length (" + key.length + " bytes) for " + getAlgorithm());
        } else if (offset == 1) {
            if (key[0] != 0) {
                throw new InvalidKeySpecException("Provided key for " + getAlgorithm()
                                                  + " has extra byte, but it's non-zero: 0x"
                                                  + Integer.toHexString(key[0] & 0xFF));
            }
        }
        // Ideally, we'd just parse the key as a BigInteger and then create a XECPublicKeySpec in Java 11
        // BouncyCastle supports a separate API, but we can use the generic X.509 encoding scheme supported by both
        byte[] encoded = Arrays.copyOf(encodedPublicKeyPrefix, encodedPublicKeyPrefix.length + size);
        System.arraycopy(key, offset, encoded, encodedPublicKeyPrefix.length, size);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }
}
