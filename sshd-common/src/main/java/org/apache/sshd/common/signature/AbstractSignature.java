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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Objects;

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Useful base class for {@link Signature} implementation
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSignature implements Signature {
    private java.security.Signature signatureInstance;
    private final String algorithm;

    protected AbstractSignature(String algorithm) {
        this.algorithm = ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No signature algorithm specified");
    }

    @Override
    public final String getAlgorithm() {
        return algorithm;
    }

    /**
     * Initializes the internal signature instance
     *
     * @param algo The signature's algorithm
     * @param forSigning If {@code true} then it is being initialized for signing,
     * otherwise for verifying a signature
     * @return The {@link java.security.Signature} instance
     * @throws GeneralSecurityException if failed to initialize
     */
    protected java.security.Signature doInitSignature(String algo, boolean forSigning) throws GeneralSecurityException {
        return SecurityUtils.getSignature(algo);
    }

    /**
     * @return The current {@link java.security.Signature} instance
     * - {@code null} if not initialized
     * @see #doInitSignature(String, boolean)
     */
    protected java.security.Signature getSignature() {
        return signatureInstance;
    }

    @Override
    public byte[] sign() throws Exception {
        java.security.Signature signature = Objects.requireNonNull(getSignature(), "Signature not initialized");
        return signature.sign();
    }

    @Override
    public void initVerifier(PublicKey key) throws Exception {
        String algo = getAlgorithm();
        signatureInstance = Objects.requireNonNull(doInitSignature(algo, false), "No signature instance create");
        signatureInstance.initVerify(Objects.requireNonNull(key, "No public key provided"));
    }

    @Override
    public void initSigner(PrivateKey key) throws Exception {
        String algo = getAlgorithm();
        signatureInstance = Objects.requireNonNull(doInitSignature(algo, true), "No signature instance create");
        signatureInstance.initSign(Objects.requireNonNull(key, "No private key provided"));
    }

    @Override
    public void update(byte[] hash, int off, int len) throws Exception {
        java.security.Signature signature = Objects.requireNonNull(getSignature(), "Signature not initialized");
        signature.update(hash, off, len);
    }

    /**
     * Makes an attempt to detect if the signature is encoded or pure data
     *
     * @param sig The original signature
     * @return A {@link SimpleImmutableEntry} where first value is the key type and second
     * value is the data - {@code null} if not encoded
     */
    protected SimpleImmutableEntry<String, byte[]> extractEncodedSignature(byte[] sig) {
        final int dataLen = NumberUtils.length(sig);
        // if it is encoded then we must have at least 2 UINT32 values
        if (dataLen < (2 * Integer.BYTES)) {
            return null;
        }

        long keyTypeLen = BufferUtils.getUInt(sig, 0, dataLen);
        // after the key type we MUST have data bytes
        if (keyTypeLen >= (dataLen - Integer.BYTES)) {
            return null;
        }

        int keyTypeStartPos = Integer.BYTES;
        int keyTypeEndPos = keyTypeStartPos + (int) keyTypeLen;
        int remainLen = dataLen - keyTypeEndPos;
        // must have UINT32 with the data bytes length
        if (remainLen < Integer.BYTES) {
            return null;
        }

        long dataBytesLen = BufferUtils.getUInt(sig, keyTypeEndPos, remainLen);
        // make sure reported number of bytes does not exceed available
        if (dataBytesLen > (remainLen - Integer.BYTES)) {
            return null;
        }

        String keyType = new String(sig, keyTypeStartPos, (int) keyTypeLen, StandardCharsets.UTF_8);
        byte[] data = new byte[(int) dataBytesLen];
        System.arraycopy(sig, keyTypeEndPos + Integer.BYTES, data, 0, (int) dataBytesLen);
        return new SimpleImmutableEntry<>(keyType, data);
    }

    protected boolean doVerify(byte[] data) throws SignatureException {
        java.security.Signature signature = Objects.requireNonNull(getSignature(), "Signature not initialized");
        return signature.verify(data);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getAlgorithm() + "]";
    }
}
