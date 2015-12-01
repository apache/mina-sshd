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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Useful base class implementation for a decoder of an {@code OpenSSH} encoded key data
 *
 * @param <PUB> Type of {@link PublicKey}
 * @param <PRV> Type of {@link PrivateKey}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPublicKeyEntryDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        implements PublicKeyEntryDecoder<PUB, PRV> {

    private final Class<PUB> pubType;
    private final Class<PRV> prvType;
    private final Collection<String> names;

    protected AbstractPublicKeyEntryDecoder(Class<PUB> pubType, Class<PRV> prvType, Collection<String> names) {
        this.pubType = ValidateUtils.checkNotNull(pubType, "No public key type specified");
        this.prvType = ValidateUtils.checkNotNull(prvType, "No private key type specified");
        this.names = ValidateUtils.checkNotNullAndNotEmpty(names, "No type names provided");
    }

    @Override
    public final Class<PUB> getPublicKeyType() {
        return pubType;
    }

    @Override
    public final Class<PRV> getPrivateKeyType() {
        return prvType;
    }

    @Override
    public KeyPair cloneKeyPair(KeyPair kp) throws GeneralSecurityException {
        if (kp == null) {
            return null;
        }

        PUB pubCloned = null;
        PublicKey pubOriginal = kp.getPublic();
        Class<PUB> pubExpected = getPublicKeyType();
        if (pubOriginal != null) {
            Class<?> orgType = pubOriginal.getClass();
            if (!pubExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException("Mismatched public key types: expected=" + pubExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            pubCloned = clonePublicKey(pubExpected.cast(pubOriginal));
        }

        PRV prvCloned = null;
        PrivateKey prvOriginal = kp.getPrivate();
        Class<PRV> prvExpected = getPrivateKeyType();
        if (prvOriginal != null) {
            Class<?> orgType = prvOriginal.getClass();
            if (!prvExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException("Mismatched private key types: expected=" + prvExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            prvCloned = clonePrivateKey(prvExpected.cast(prvOriginal));
        }

        return new KeyPair(pubCloned, prvCloned);
    }

    @Override   // TODO make this a default method in Java-8
    public PublicKey resolve(String keyType, byte[] keyData) throws IOException, GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");
        Collection<String> supported = getSupportedTypeNames();
        if ((GenericUtils.size(supported) > 0) && supported.contains(keyType)) {
            return decodePublicKey(keyData);
        }

        throw new InvalidKeySpecException("resolve(" + keyType + ") not in listed supported types: " + supported);
    }

    @Override
    public Collection<String> getSupportedTypeNames() {
        return names;
    }

    @Override
    public PUB decodePublicKey(byte... keyData) throws IOException, GeneralSecurityException {
        return decodePublicKey(keyData, 0, NumberUtils.length(keyData));
    }

    @Override
    public PUB decodePublicKey(byte[] keyData, int offset, int length) throws IOException, GeneralSecurityException {
        if (length <= 0) {
            return null;
        }

        try (InputStream stream = new ByteArrayInputStream(keyData, offset, length)) {
            return decodePublicKey(stream);
        }
    }

    @Override
    public PUB decodePublicKey(InputStream keyData) throws IOException, GeneralSecurityException {
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

    public PUB generatePublicKey(KeySpec keySpec) throws GeneralSecurityException {
        KeyFactory factory = getKeyFactoryInstance();
        Class<PUB> keyType = getPublicKeyType();
        return keyType.cast(factory.generatePublic(keySpec));
    }

    public PRV generatePrivateKey(KeySpec keySpec) throws GeneralSecurityException {
        KeyFactory factory = getKeyFactoryInstance();
        Class<PRV> keyType = getPrivateKeyType();
        return keyType.cast(factory.generatePrivate(keySpec));
    }

    /**
     * @param keyType The reported / encode key type
     * @param keyData The key data bytes stream positioned after the key type decoding
     *                and making sure it is one of the supported types
     * @return The decoded {@link PublicKey}
     * @throws IOException              If failed to read from the data stream
     * @throws GeneralSecurityException If failed to generate the key
     */
    public abstract PUB decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException;

    @Override
    public KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        KeyPairGenerator gen = getKeyPairGenerator();
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }

    @Override
    public String toString() {
        return getPublicKeyType().getSimpleName() + ": " + getSupportedTypeNames();
    }

    public static int encodeString(OutputStream s, String v) throws IOException {
        return encodeString(s, v, StandardCharsets.UTF_8);
    }

    public static int encodeString(OutputStream s, String v, String charset) throws IOException {
        return encodeString(s, v, Charset.forName(charset));
    }

    public static int encodeString(OutputStream s, String v, Charset cs) throws IOException {
        return writeRLEBytes(s, v.getBytes(cs));
    }

    public static int encodeBigInt(OutputStream s, BigInteger v) throws IOException {
        return writeRLEBytes(s, v.toByteArray());
    }

    public static int writeRLEBytes(OutputStream s, byte... bytes) throws IOException {
        return writeRLEBytes(s, bytes, 0, bytes.length);
    }

    public static int writeRLEBytes(OutputStream s, byte[] bytes, int off, int len) throws IOException {
        byte[] lenBytes = encodeInt(s, len);
        s.write(bytes, off, len);
        return lenBytes.length + len;
    }

    public static byte[] encodeInt(OutputStream s, int v) throws IOException {
        byte[] bytes = {
            (byte) ((v >> 24) & 0xFF),
            (byte) ((v >> 16) & 0xFF),
            (byte) ((v >> 8) & 0xFF),
            (byte) (v & 0xFF)
        };
        s.write(bytes);
        return bytes;
    }

    public static String decodeString(InputStream s) throws IOException {
        return decodeString(s, StandardCharsets.UTF_8);
    }

    public static String decodeString(InputStream s, String charset) throws IOException {
        return decodeString(s, Charset.forName(charset));
    }

    public static String decodeString(InputStream s, Charset cs) throws IOException {
        byte[] bytes = readRLEBytes(s);
        return new String(bytes, cs);
    }

    public static BigInteger decodeBigInt(InputStream s) throws IOException {
        return new BigInteger(readRLEBytes(s));
    }

    public static byte[] readRLEBytes(InputStream s) throws IOException {
        int len = decodeInt(s);
        byte[] bytes = new byte[len];
        IoUtils.readFully(s, bytes);
        return bytes;
    }

    public static int decodeInt(InputStream s) throws IOException {
        byte[] bytes = {0, 0, 0, 0};
        IoUtils.readFully(s, bytes);
        return ((bytes[0] & 0xFF) << 24)
                | ((bytes[1] & 0xFF) << 16)
                | ((bytes[2] & 0xFF) << 8)
                | (bytes[3] & 0xFF);
    }
}
