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
package org.apache.sshd.common.util.buffer.keys;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.MLDSAParameterSets;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.mldsa.MLDSAUtils;

/**
 * Parses the SSH public-key encoding for ML-DSA parameter sets.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class MLDSABufferPublicKeyParser extends AbstractBufferPublicKeyParser<PublicKey> {
    /** Shared parser for all ML-DSA parameter sets. */
    public static final MLDSABufferPublicKeyParser INSTANCE = new MLDSABufferPublicKeyParser();

    private MLDSABufferPublicKeyParser() {
        super(PublicKey.class, MLDSAParameterSets.SSH_NAMES);
    }

    /**
     * @param  keyType the SSH key type name
     * @return         whether the key type has provider support
     */
    @Override
    public boolean isKeyTypeSupported(String keyType) {
        MLDSAParameterSets params = MLDSAParameterSets.fromSshName(keyType);
        return params != null && SecurityUtils.isMLDSASupported(params.getJceName());
    }

    /**
     * @param  keyType                  the SSH key type name
     * @param  buffer                   the buffer containing the public key string
     * @return                          the public key
     * @throws GeneralSecurityException if the key type is unsupported or the key data is invalid
     */
    @Override
    public PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
        MLDSAParameterSets params = MLDSAParameterSets.fromSshName(keyType);
        if (params == null || !isKeyTypeSupported(keyType)) {
            throw new InvalidKeySpecException("Unsupported ML-DSA key type: " + keyType);
        }
        // Bound the allocation by the parameter set's public key size.
        if (buffer.available() < Integer.BYTES || buffer.getInt() != params.getPublicKeySize()
                || buffer.available() < params.getPublicKeySize()) {
            throw new InvalidKeySpecException("Invalid or truncated ML-DSA public key string");
        }
        byte[] raw = new byte[params.getPublicKeySize()];
        buffer.getRawBytes(raw);
        return MLDSAUtils.getPublicKey(params, raw);
    }
}
