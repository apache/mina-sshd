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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.util.io.IoUtils;

/**
 * @param <PUB> Type of {@link PublicKey}
 * @param <PRV> Type of {@link PrivateKey}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyEntryResolver<PUB extends PublicKey, PRV extends PrivateKey>
        extends IdentityResourceLoader<PUB, PRV> {
    /**
     * @param keySize Key size in bits
     * @return A {@link KeyPair} with the specified key size
     * @throws GeneralSecurityException if unable to generate the pair
     */
    default KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        KeyPairGenerator gen = getKeyPairGenerator();
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }

    /**
     * @param kp The {@link KeyPair} to be cloned - ignored if {@code null}
     * @return A cloned pair (or {@code null} if no original pair)
     * @throws GeneralSecurityException If failed to clone - e.g., provided key
     *                                  pair does not contain keys of the expected type
     * @see #getPublicKeyType()
     * @see #getPrivateKeyType()
     */
    default KeyPair cloneKeyPair(KeyPair kp) throws GeneralSecurityException {
        if (kp == null) {
            return null;
        }

        PUB pubCloned = null;
        PublicKey pubOriginal = kp.getPublic();
        Class<PUB> pubExpected = getPublicKeyType();
        if (pubOriginal != null) {
            Class<?> orgType = pubOriginal.getClass();
            if (!pubExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException(
                    "Mismatched public key types: expected=" + pubExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            PUB castPub = pubExpected.cast(pubOriginal);
            pubCloned = clonePublicKey(castPub);
        }

        PRV prvCloned = null;
        PrivateKey prvOriginal = kp.getPrivate();
        Class<PRV> prvExpected = getPrivateKeyType();
        if (prvOriginal != null) {
            Class<?> orgType = prvOriginal.getClass();
            if (!prvExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException(
                    "Mismatched private key types: expected=" + prvExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            PRV castPrv = prvExpected.cast(prvOriginal);
            prvCloned = clonePrivateKey(castPrv);
        }

        return new KeyPair(pubCloned, prvCloned);
    }

    /**
     * @param key The {@link PublicKey} to clone - ignored if {@code null}
     * @return The cloned key (or {@code null} if no original key)
     * @throws GeneralSecurityException If failed to clone the key
     */
    PUB clonePublicKey(PUB key) throws GeneralSecurityException;

    /**
     * @param key The {@link PrivateKey} to clone - ignored if {@code null}
     * @return The cloned key (or {@code null} if no original key)
     * @throws GeneralSecurityException If failed to clone the key
     */
    PRV clonePrivateKey(PRV key) throws GeneralSecurityException;

    /**
     * @return A {@link KeyPairGenerator} suitable for this decoder
     * @throws GeneralSecurityException If failed to create the generator
     */
    KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException;

    /**
     * @return A {@link KeyFactory} suitable for the specific decoder type
     * @throws GeneralSecurityException If failed to create one
     */
    KeyFactory getKeyFactoryInstance() throws GeneralSecurityException;

    static int encodeString(OutputStream s, String v) throws IOException {
        return encodeString(s, v, StandardCharsets.UTF_8);
    }

    static int encodeString(OutputStream s, String v, String charset) throws IOException {
        return encodeString(s, v, Charset.forName(charset));
    }

    static int encodeString(OutputStream s, String v, Charset cs) throws IOException {
        return writeRLEBytes(s, v.getBytes(cs));
    }

    static int encodeBigInt(OutputStream s, BigInteger v) throws IOException {
        return writeRLEBytes(s, v.toByteArray());
    }

    static int writeRLEBytes(OutputStream s, byte... bytes) throws IOException {
        return writeRLEBytes(s, bytes, 0, bytes.length);
    }

    static int writeRLEBytes(OutputStream s, byte[] bytes, int off, int len) throws IOException {
        byte[] lenBytes = encodeInt(s, len);
        s.write(bytes, off, len);
        return lenBytes.length + len;
    }

    static byte[] encodeInt(OutputStream s, int v) throws IOException {
        byte[] bytes = {
            (byte) ((v >> 24) & 0xFF),
            (byte) ((v >> 16) & 0xFF),
            (byte) ((v >> 8) & 0xFF),
            (byte) (v & 0xFF)
        };
        s.write(bytes);
        return bytes;
    }

    static String decodeString(InputStream s, int maxChars) throws IOException {
        return decodeString(s, StandardCharsets.UTF_8, maxChars);
    }

    static String decodeString(InputStream s, String charset, int maxChars) throws IOException {
        return decodeString(s, Charset.forName(charset), maxChars);
    }

    static String decodeString(InputStream s, Charset cs, int maxChars) throws IOException {
        byte[] bytes = readRLEBytes(s, maxChars * 4 /* in case UTF-8 with weird characters */);
        return new String(bytes, cs);
    }

    static BigInteger decodeBigInt(InputStream s) throws IOException {
        return new BigInteger(readRLEBytes(s, IdentityResourceLoader.MAX_BIGINT_OCTETS_COUNT));
    }

    static byte[] readRLEBytes(InputStream s, int maxAllowed) throws IOException {
        int len = decodeInt(s);
        if (len > maxAllowed) {
            throw new StreamCorruptedException("Requested block length (" + len + ") exceeds max. allowed (" + maxAllowed + ")");
        }
        if (len < 0) {
            throw new StreamCorruptedException("Negative block length requested: " + len);
        }

        byte[] bytes = new byte[len];
        IoUtils.readFully(s, bytes);
        return bytes;
    }

    static int decodeInt(InputStream s) throws IOException {
        byte[] bytes = {0, 0, 0, 0};
        IoUtils.readFully(s, bytes);
        return ((bytes[0] & 0xFF) << 24)
                | ((bytes[1] & 0xFF) << 16)
                | ((bytes[2] & 0xFF) << 8)
                | (bytes[3] & 0xFF);
    }
}
