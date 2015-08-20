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
package org.apache.sshd.common.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Signature interface for SSH used to sign or verify packets
 * Usually wraps a javax.crypto.Signature object
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Signature {
    /**
     * @return The signature algorithm name
     */
    String getAlgorithm();

    /**
     * @param key The {@link PublicKey} to be used for verifying signatures
     * @throws Exception If failed to initialize
     */
    void initVerifier(PublicKey key) throws Exception;

    /**
     * @param key The {@link PrivateKey} to be used for signing
     * @throws Exception If failed to initialize
     */
    void initSigner(PrivateKey key) throws Exception;

    /**
     * Update the computed signature with the given data
     *
     * @param hash The hash data buffer
     * @throws Exception If failed to update
     * @see #update(byte[], int, int)
     */
    void update(byte[] hash) throws Exception;

    /**
     * Update the computed signature with the given data
     *
     * @param hash The hash data buffer
     * @param off  Offset of hash data in buffer
     * @param len  Length of hash data
     * @throws Exception If failed to update
     */
    void update(byte[] hash, int off, int len) throws Exception;

    /**
     * Verify against the given signature
     *
     * @param sig The signed data
     * @return {@code true} if signature is valid
     * @throws Exception If failed to extract signed data for validation
     */
    boolean verify(byte[] sig) throws Exception;

    /**
     * Compute the signature
     *
     * @return The signature value
     * @throws Exception If failed to calculate the signature
     */
    byte[] sign() throws Exception;

}
