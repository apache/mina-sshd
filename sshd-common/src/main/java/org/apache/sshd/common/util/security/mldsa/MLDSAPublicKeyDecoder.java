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
package org.apache.sshd.common.util.security.mldsa;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPublicKeyEntryDecoder;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * An {@link AbstractPublicKeyEntryDecoder} for an ML-DSA parameter set.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MLDSAPublicKeyDecoder extends AbstractPublicKeyEntryDecoder {
    private final MLDSAParameterSets params;

    /**
     * Creates a decoder for a parameter set.
     *
     * @param params the parameter set
     */
    public MLDSAPublicKeyDecoder(MLDSAParameterSets params) {
        super(Collections.singletonList(Objects.requireNonNull(params, "No ML-DSA parameters provided").getSshName()));
        this.params = params;
    }

    /**
     * @return                          a key pair generator for this parameter set
     * @throws GeneralSecurityException if no key pair generator is available
     */
    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(params.getJceName());
    }

    /**
     * @param  keySize                  the raw public key size in bits
     * @return                          a key pair for this parameter set
     * @throws GeneralSecurityException if the size does not match or key generation fails
     */
    @Override
    public KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        if (keySize != params.getPublicKeySize() * Byte.SIZE) {
            throw new InvalidKeySpecException("Mismatched ML-DSA public key size: " + keySize);
        }
        return getKeyPairGenerator().generateKeyPair();
    }

    /**
     * @return                          a key factory for this parameter set
     * @throws GeneralSecurityException if no key factory is available
     */
    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(params.getJceName());
    }

    /**
     * @param  out         the output stream
     * @param  key         the public key
     * @return             the SSH key type name
     * @throws IOException if the key is invalid or cannot be written
     */
    @Override
    public String encodePublicKey(OutputStream out, PublicKey key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");
        try {
            MLDSAParameterSets variant = MLDSAUtils.getParameters(key);
            if (params != variant) {
                throw new InvalidKeySpecException("Mismatched ML-DSA variant");
            }
            byte[] raw = MLDSAUtils.getRawBytes(key);
            KeyEntryResolver.encodeString(out, variant.getSshName());
            KeyEntryResolver.writeRLEBytes(out, raw);
            return variant.getSshName();
        } catch (InvalidKeySpecException e) {
            throw new IOException("Invalid ML-DSA public key", e);
        }
    }

    /**
     * @param  session                  the session context
     * @param  keyType                  the SSH key type name
     * @param  keyData                  the encoded public key
     * @param  headers                  the key entry headers
     * @return                          the decoded public key
     * @throws IOException              if the key data cannot be read
     * @throws GeneralSecurityException if the key type or key bytes are invalid
     */
    @Override
    public PublicKey decodePublicKey(SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        MLDSAParameterSets variant = MLDSAParameterSets.fromSshName(keyType);
        if (params != variant) {
            throw new InvalidKeySpecException("Unsupported ML-DSA key type: " + keyType);
        }
        byte[] raw = KeyEntryResolver.readRLEBytes(keyData, MLDSAParameterSets.MAX_PUBLIC_KEY_SIZE);
        return MLDSAUtils.getPublicKey(variant, raw);
    }
}
