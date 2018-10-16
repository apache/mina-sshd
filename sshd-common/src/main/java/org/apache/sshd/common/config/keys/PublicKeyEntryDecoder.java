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
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Represents a decoder of an {@code OpenSSH} encoded key data
 *
 * @param <PUB> Type of {@link PublicKey}
 * @param <PRV> Type of {@link PrivateKey}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyEntryDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        extends KeyEntryResolver<PUB, PRV>, PublicKeyEntryResolver {

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
        String type = KeyEntryResolver.decodeString(keyData);
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
}
