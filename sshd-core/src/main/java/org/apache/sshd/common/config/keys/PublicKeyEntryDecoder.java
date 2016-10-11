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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Represents a decoder of an {@code OpenSSH} encoded key data
 *
 * @param <PUB> Type of {@link PublicKey}
 * @param <PRV> Type of {@link PrivateKey}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyEntryDecoder<PUB extends PublicKey, PRV extends PrivateKey> extends PublicKeyEntryResolver {
    /**
     * @return The {@link Class} of the {@link PublicKey} that is the result
     * of decoding
     */
    Class<PUB> getPublicKeyType();

    /**
     * @return The {@link Class} of the {@link PrivateKey} that matches the
     * public one
     */
    Class<PRV> getPrivateKeyType();

    /**
     * @return The {@link Collection} of {@code OpenSSH} key type names that
     * are supported by this decoder - e.g., ECDSA keys have several curve names.
     * <B>Caveat:</B> this collection may be un-modifiable...
     */
    Collection<String> getSupportedTypeNames();

    /**
     * @param keySize Key size in bits
     * @return A {@link KeyPair} with the specified key size
     * @throws GeneralSecurityException if unable to generate the pair
     */
    KeyPair generateKeyPair(int keySize) throws GeneralSecurityException;

    /**
     * @param kp The {@link KeyPair} to be cloned - ignored if {@code null}
     * @return A cloned pair (or {@code null} if no original pair)
     * @throws GeneralSecurityException If failed to clone - e.g., provided key
     *                                  pair does not contain keys of the expected type
     * @see #getPublicKeyType()
     * @see #getPrivateKeyType()
     */
    KeyPair cloneKeyPair(KeyPair kp) throws GeneralSecurityException;

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

    @Override
    default PublicKey resolve(String keyType, byte[] keyData) throws IOException, GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");
        Collection<String> supported = getSupportedTypeNames();
        if ((GenericUtils.size(supported) > 0) && supported.contains(keyType)) {
            return decodePublicKey(keyData);
        }

        throw new InvalidKeySpecException("resolve(" + keyType + ") not in listed supported types: " + supported);
    }

    /**
     * @param keyData The key data bytes in {@code OpenSSH} format (after
     *                BASE64 decoding) - ignored if {@code null}/empty
     * @return The decoded {@link PublicKey} - or {@code null} if no data
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    default PUB decodePublicKey(byte... keyData) throws IOException, GeneralSecurityException {
        return decodePublicKey(keyData, 0, NumberUtils.length(keyData));
    }

    default PUB decodePublicKey(byte[] keyData, int offset, int length) throws IOException, GeneralSecurityException {
        if (length <= 0) {
            return null;
        }

        try (InputStream stream = new ByteArrayInputStream(keyData, offset, length)) {
            return decodePublicKey(stream);
        }
    }

    default PUB decodePublicKey(InputStream keyData) throws IOException, GeneralSecurityException {
        // the actual data is preceded by a string that repeats the key type
        String type = decodeString(keyData);
        if (GenericUtils.isEmpty(type)) {
            throw new StreamCorruptedException("Missing key type string");
        }

        Collection<String> supported = getSupportedTypeNames();
        if (GenericUtils.isEmpty(supported) || (!supported.contains(type))) {
            throw new InvalidKeySpecException("Reported key type (" + type + ") not in supported list: " + supported);
        }

        return decodePublicKey(type, keyData);
    }

    /**
     * @param keyType The reported / encode key type
     * @param keyData The key data bytes stream positioned after the key type decoding
     *                and making sure it is one of the supported types
     * @return The decoded {@link PublicKey}
     * @throws IOException              If failed to read from the data stream
     * @throws GeneralSecurityException If failed to generate the key
     */
    PUB decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException;

    /**
     * Encodes the {@link PublicKey} using the {@code OpenSSH} format - same
     * one used by the {@code decodePublicKey} method(s)
     *
     * @param s   The {@link OutputStream} to write the data to
     * @param key The {@link PublicKey} - may not be {@code null}
     * @return The key type value - one of the {@link #getSupportedTypeNames()}
     * @throws IOException If failed to generate the encoding
     */
    String encodePublicKey(OutputStream s, PUB key) throws IOException;

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

    static String decodeString(InputStream s) throws IOException {
        return decodeString(s, StandardCharsets.UTF_8);
    }

    static String decodeString(InputStream s, String charset) throws IOException {
        return decodeString(s, Charset.forName(charset));
    }

    static String decodeString(InputStream s, Charset cs) throws IOException {
        byte[] bytes = readRLEBytes(s);
        return new String(bytes, cs);
    }

    static BigInteger decodeBigInt(InputStream s) throws IOException {
        return new BigInteger(readRLEBytes(s));
    }

    static byte[] readRLEBytes(InputStream s) throws IOException {
        int len = decodeInt(s);
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
