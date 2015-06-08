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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPublicKeyEntryDecoder<K extends PublicKey> implements PublicKeyEntryDecoder<K> {
    private final Class<K> keyType;
    private final Collection<String>    names;
    
    protected AbstractPublicKeyEntryDecoder(Class<K> keyType, Collection<String> names) {
        this.keyType = ValidateUtils.checkNotNull(keyType, "No key type specified", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.names = ValidateUtils.checkNotNullAndNotEmpty(names, "No type names provided", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    @Override
    public final Class<K> getKeyType() {
        return keyType;
    }

    @Override
    public Collection<String> getSupportedTypeNames() {
        return names;
    }

    @Override
    public K decodePublicKey(byte... keyData) throws IOException, GeneralSecurityException {
        return decodePublicKey(keyData, 0, GenericUtils.length(keyData));
    }

    @Override
    public K decodePublicKey(byte[] keyData, int offset, int length) throws IOException, GeneralSecurityException {
        if (length <= 0) {
            return null;
        }

        try(InputStream stream=new ByteArrayInputStream(keyData, offset, length)) {
            return decodePublicKey(stream);
        }
    }

    @Override
    public K decodePublicKey(InputStream keyData) throws IOException, GeneralSecurityException {
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

    public K generatePublicKey(KeySpec keySpec) throws GeneralSecurityException {
        KeyFactory  factory = getKeyFactoryInstance();
        Class<K>    keyType = getKeyType();
        return keyType.cast(factory.generatePublic(keySpec));
    }

    public abstract KeyFactory getKeyFactoryInstance() throws GeneralSecurityException;

    /**
     * @param keyType The reported / encode key type
     * @param keyData The key data bytes stream positioned after the key type decoding
     * and making sure it is one of the supported types
     * @return The decoded {@link PublicKey}
     * @throws IOException If failed to read from the data stream
     * @throws GeneralSecurityException If failed to generate the key
     */
    public abstract K decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException;

    @Override
    public String toString() {
        return getKeyType().getSimpleName() + ": " + getSupportedTypeNames();
    }

    public static final int encodeString(OutputStream s, String v) throws IOException {
        return encodeString(s, v, StandardCharsets.UTF_8);
    }

    public static final int encodeString(OutputStream s, String v, String charset) throws IOException {
        return encodeString(s, v, Charset.forName(charset));
    }

    public static final int encodeString(OutputStream s, String v, Charset cs) throws IOException {
        return writeRLEBytes(s, v.getBytes(cs));
    }

    public static final int encodeBigInt(OutputStream s, BigInteger v) throws IOException {
        return writeRLEBytes(s, v.toByteArray());
    }

    public static final int writeRLEBytes(OutputStream s, byte ... bytes) throws IOException {
        return writeRLEBytes(s, bytes, 0, bytes.length);
    }

    public static final int writeRLEBytes(OutputStream s, byte[] bytes, int off, int len) throws IOException {
        byte[]  lenBytes=encodeInt(s, len);
        s.write(bytes, off, len);
        return lenBytes.length + len;
    }

    public static final byte[] encodeInt(OutputStream s, int v) throws IOException {
        byte[]  bytes={
                (byte) ((v >> 24) & 0xFF),
                (byte) ((v >> 16) & 0xFF),
                (byte) ((v >>  8) & 0xFF),
                (byte) (    v     & 0xFF)
              };
        s.write(bytes);
        return bytes;
    }

    public static final String decodeString(InputStream s) throws IOException {
        return decodeString(s, StandardCharsets.UTF_8);
    }

    public static final String decodeString(InputStream s, String charset) throws IOException {
        return decodeString(s, Charset.forName(charset));
    }

    public static final String decodeString(InputStream s, Charset cs) throws IOException {
        byte[]  bytes=readRLEBytes(s);
        return new String(bytes, cs);
    }

    public static final BigInteger decodeBigInt(InputStream s) throws IOException {
        return new BigInteger(readRLEBytes(s));
    }

    public static final byte[] readRLEBytes(InputStream s) throws IOException {
        int     len=decodeInt(s);
        byte[]  bytes=new byte[len];
        IoUtils.readFully(s, bytes);
        return bytes;
    }

    public static final int decodeInt(InputStream s) throws IOException {
        byte[]  bytes={ 0, 0, 0, 0 };
        IoUtils.readFully(s, bytes);
        return ((bytes[0] & 0xFF) << 24)
             | ((bytes[1] & 0xFF) << 16)
             | ((bytes[2] & 0xFF) << 8)
             | (bytes[3] & 0xFF);
    }
}
