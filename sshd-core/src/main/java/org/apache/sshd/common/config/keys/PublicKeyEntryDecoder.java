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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Collection;

/**
 * Represents a decoder of an {@code OpenSSH} encoded key data
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PublicKeyEntryDecoder<K extends PublicKey> {
    /**
     * @return The {@link Class} of the {@link PublicKey} that is the result
     * of decoding
     */
    Class<K> getKeyType();

    /**
     * @return The {@link Collection} of {@code OpenSSH} key type names that
     * are supported by this decoder - e.g., ECDSA keys have several curve names.
     * <B>Caveat:</B> this collection may be un-modifiable...
     */
    Collection<String> getSupportedTypeNames();
    
    /**
     * @param keyData The key data bytes in {@code OpenSSH} format (after
     * BASE64 decoding) - ignored if {@code null}/empty
     * @return The decoded {@link PublicKey} - or {@code null} if no data
     * @throws IOException If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    K decodePublicKey(byte ... keyData) throws IOException, GeneralSecurityException;
    K decodePublicKey(byte[] keyData, int offset, int length) throws IOException, GeneralSecurityException;
    K decodePublicKey(InputStream keyData) throws IOException, GeneralSecurityException;
    
    /**
     * Encodes the {@link PublicKey} using the {@code OpenSSH} format - same
     * one used by the {@code decodePublicKey} method(s)
     * @param s The {@link OutputStream} to write the data to
     * @param key The {@link PublicKey} - may not be {@code null}
     * @return The key type value - one of the {@link #getSupportedTypeNames()}
     * @throws IOException If failed to generate the encoding
     */
    String encodePublicKey(OutputStream s, K key) throws IOException;
}
