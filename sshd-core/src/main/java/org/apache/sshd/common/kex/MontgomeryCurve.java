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

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Provides implementation details for Montgomery curves and their key exchange algorithms Curve25519/X25519 and
 * Curve448/X448 specified in RFC 7748 and RFC 8731. Montgomery curves provide improved security and flexibility over
 * Weierstrass curves used in ECDH.
 *
 * @see <a href="https://www.rfc-editor.org/info/rfc7748">RFC 7748</a>
 * @see <a href="https://www.rfc-editor.org/info/rfc8731">RFC 8731</a>
 */
public enum MontgomeryCurve implements KeySizeIndicator, OptionalFeature {

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
    private final int encodedKeySize;

    MontgomeryCurve(String algorithm, int keySize, DigestFactory digestFactory, byte[] encodedPublicKeyPrefix) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.digestFactory = digestFactory;
        this.encodedPublicKeyPrefix = encodedPublicKeyPrefix;
        encodedKeySize = keySize + encodedPublicKeyPrefix.length;
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
        return extractSubjectPublicKey(key.getEncoded());
    }

    public PublicKey decode(byte[] key) throws InvalidKeySpecException {
        if (key.length < getKeySize()) {
            throw new InvalidKeySpecException("Provided key is too small for " + getAlgorithm());
        }
        // ideally, we'd just parse the key as a BigInteger and then create a XECPublicKeySpec in Java 11
        // BouncyCastle supports a separate API, so we can use the generic X.509 encoding scheme supported by both
        byte[] encoded = new byte[encodedKeySize];
        System.arraycopy(encodedPublicKeyPrefix, 0, encoded, 0, encodedPublicKeyPrefix.length);
        // note that key can be either the raw key data or it may be prefixed by a padding byte and the key length.
        // these two bytes are already present as the last two bytes in encodedPublicKeyPrefix, thus there is no harm
        // in potentially overwriting it
        System.arraycopy(key, 0, encoded, encodedKeySize - key.length, key.length);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static byte[] extractSubjectPublicKey(byte[] subjectPublicKeyInfo) throws InvalidKeyException {
        try {
            //  SubjectPublicKeyInfo ::= SEQUENCE {
            //   algorithm AlgorithmIdentifier,
            //   subjectPublicKey BIT STRING }
            ASN1Object spki = new DERParser(subjectPublicKeyInfo).readObject();
            DERParser parser = spki.createParser();
            parser.readObject();
            return parser.readObject().getValue();
        } catch (StreamCorruptedException e) {
            throw new InvalidKeyException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
