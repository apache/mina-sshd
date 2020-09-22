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

import org.apache.sshd.common.AlgorithmNameProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.NumberUtils;

/**
 * Signature interface for SSH used to sign or verify packets. Usually wraps a {@code javax.crypto.Signature} object.
 * The reported algorithm name refers to the signature type being applied.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Signature extends AlgorithmNameProvider {
    /**
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  key       The {@link PublicKey} to be used for verifying signatures
     * @throws Exception If failed to initialize
     */
    void initVerifier(SessionContext session, PublicKey key) throws Exception;

    /**
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  key       The {@link PrivateKey} to be used for signing
     * @throws Exception If failed to initialize
     */
    void initSigner(SessionContext session, PrivateKey key) throws Exception;

    /**
     * Update the computed signature with the given data
     *
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  hash      The hash data buffer
     * @throws Exception If failed to update
     * @see              #update(SessionContext, byte[], int, int)
     */
    default void update(SessionContext session, byte[] hash) throws Exception {
        update(session, hash, 0, NumberUtils.length(hash));
    }

    /**
     * Update the computed signature with the given data
     *
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  hash      The hash data buffer
     * @param  off       Offset of hash data in buffer
     * @param  len       Length of hash data
     * @throws Exception If failed to update
     */
    void update(SessionContext session, byte[] hash, int off, int len) throws Exception;

    /**
     * Verify against the given signature
     *
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @param  sig       The signed data
     * @return           {@code true} if signature is valid
     * @throws Exception If failed to extract signed data for validation
     */
    boolean verify(SessionContext session, byte[] sig) throws Exception;

    /**
     * Compute the signature
     *
     * @param  session   The {@link SessionContext} for calling this method - may be {@code null} if not called within a
     *                   session context
     * @return           The signature value
     * @throws Exception If failed to calculate the signature
     */
    byte[] sign(SessionContext session) throws Exception;

    /**
     * @param  algo - the negotiated value
     * @return      The original ssh name of the signature algorithm
     */
    default String getSshAlgorithmName(String algo) {
        return algo;
    }
}
