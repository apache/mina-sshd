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

import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSignature implements Signature {

    protected java.security.Signature signature;
    private final String algorithm;

    protected AbstractSignature(String algorithm) {
        this.algorithm = ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No signature algorithm specified");
    }

    @Override
    public final String getAlgorithm() {
        return algorithm;
    }

    protected java.security.Signature doInitSignature() throws GeneralSecurityException {
        return SecurityUtils.getSignature(getAlgorithm());
    }

    @Override
    public void initVerifier(PublicKey key) throws Exception {
        signature = doInitSignature();
        signature.initVerify(ValidateUtils.checkNotNull(key, "No public key provided"));
    }

    @Override
    public void initSigner(PrivateKey key) throws Exception {
        signature = doInitSignature();
        signature.initSign(ValidateUtils.checkNotNull(key, "No private key provided"));
    }

    @Override
    public void update(byte[] hash) throws Exception {
        update(hash, 0, NumberUtils.length(hash));
    }

    @Override
    public void update(byte[] hash, int off, int len) throws Exception {
        signature.update(hash, off, len);
    }

    /**
     * Makes an attempt to detect if the signature is encoded or pure data
     *
     * @param sig The original signature
     * @return A {@link Pair} where first value is the key type and second
     * value is the data - {@code null} if not encoded
     */
    protected Pair<String, byte[]> extractEncodedSignature(byte[] sig) {
        final int dataLen = NumberUtils.length(sig);
        // if it is encoded then we must have at least 2 UINT32 values
        if (dataLen < (2 * (Integer.SIZE / Byte.SIZE))) {
            return null;
        }

        long keyTypeLen = BufferUtils.getUInt(sig, 0, dataLen);
        // after the key type we MUST have data bytes
        if (keyTypeLen >= (dataLen - (Integer.SIZE / Byte.SIZE))) {
            return null;
        }

        int keyTypeStartPos = Integer.SIZE / Byte.SIZE;
        int keyTypeEndPos = keyTypeStartPos + (int) keyTypeLen;
        int remainLen = dataLen - keyTypeEndPos;
        // must have UINT32 with the data bytes length
        if (remainLen < (Integer.SIZE / Byte.SIZE)) {
            return null;
        }

        long dataBytesLen = BufferUtils.getUInt(sig, keyTypeEndPos, remainLen);
        // make sure reported number of bytes does not exceed available
        if (dataBytesLen > (remainLen - (Integer.SIZE / Byte.SIZE))) {
            return null;
        }

        String keyType = new String(sig, keyTypeStartPos, (int) keyTypeLen, StandardCharsets.UTF_8);
        byte[] data = new byte[(int) dataBytesLen];
        System.arraycopy(sig, keyTypeEndPos + (Integer.SIZE / Byte.SIZE), data, 0, (int) dataBytesLen);
        return new Pair<>(keyType, data);
    }

    protected boolean doVerify(byte[] data) throws SignatureException {
        return signature.verify(data);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getAlgorithm() + "]";
    }
}
