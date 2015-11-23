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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

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

    /**
     * @param keyData The key data bytes in {@code OpenSSH} format (after
     *                BASE64 decoding) - ignored if {@code null}/empty
     * @return The decoded {@link PublicKey} - or {@code null} if no data
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     */
    PUB decodePublicKey(byte... keyData) throws IOException, GeneralSecurityException;

    PUB decodePublicKey(byte[] keyData, int offset, int length) throws IOException, GeneralSecurityException;

    PUB decodePublicKey(InputStream keyData) throws IOException, GeneralSecurityException;

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
}
