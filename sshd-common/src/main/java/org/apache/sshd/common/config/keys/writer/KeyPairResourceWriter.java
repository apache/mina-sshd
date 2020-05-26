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

package org.apache.sshd.common.config.keys.writer;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.apache.sshd.common.config.keys.loader.PrivateKeyEncryptionContext;

/**
 * A {@code KeyPairResourceWriter} can serialize keys to an external representation.
 *
 * @param <OPTIONS> The type of {@link PrivateKeyEncryptionContext} to use with this {@code KeyPairResourceWriter}.
 */
public interface KeyPairResourceWriter<OPTIONS extends PrivateKeyEncryptionContext> {
    /**
     * Writes a serialization of a private key from a given {@link KeyPair} to a given {@link OutputStream}.
     *
     * @param  key                      to write the private key of
     * @param  comment                  to write with the private key
     * @param  options                  for writing the key; may be {@code null} if no encryption is wanted. The caller
     *                                  is responsible for clearing the options when no longer needed. If the passphrase
     *                                  obtained from the context is {@code null} or an empty/blank string (length zero
     *                                  or containing only whitespace), the key is written unencrypted.
     * @param  out                      The {@link OutputStream} to write to - recommend using a
     *                                  {@code SecureByteArrayOutputStream} in order to reduce sensitive data exposure
     *                                  in memory
     * @throws GeneralSecurityException if the key is inconsistent or unknown, or the encryption specified cannot be
     *                                  applied
     * @throws IOException              if the key cannot be written
     */
    void writePrivateKey(KeyPair key, String comment, OPTIONS options, OutputStream out)
            throws IOException, GeneralSecurityException;

    /**
     * Writes a serialization of a public key from a given {@link KeyPair} to a given {@link OutputStream}.
     *
     * @param  key                      to write the public key of
     * @param  comment                  to write with the public key
     * @param  out                      The {@link OutputStream} to write to - recommend using a
     *                                  {@code SecureByteArrayOutputStream} in order to reduce sensitive data exposure
     *                                  in memory
     * @throws GeneralSecurityException if the key is unknown
     * @throws IOException              if the key cannot be written
     */
    default void writePublicKey(KeyPair key, String comment, OutputStream out)
            throws IOException, GeneralSecurityException {
        writePublicKey(key.getPublic(), comment, out);
    }

    /**
     * Writes a serialization of a {@link PublicKey} to a given {@link OutputStream}.
     *
     * @param  key                      to write
     * @param  comment                  to write with the key
     * @param  out                      The {@link OutputStream} to write to - recommend using a
     *                                  {@code SecureByteArrayOutputStream} in order to reduce sensitive data exposure
     *                                  in memory
     * @throws GeneralSecurityException if the key is unknown
     * @throws IOException              if the key cannot be written
     */
    void writePublicKey(PublicKey key, String comment, OutputStream out)
            throws IOException, GeneralSecurityException;
}
