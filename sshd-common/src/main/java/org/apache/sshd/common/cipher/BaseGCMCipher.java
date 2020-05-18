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
package org.apache.sshd.common.cipher;

import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.security.SecurityUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BaseGCMCipher extends BaseCipher {

    private Mode mode;
    private SecretKey secretKey;

    public BaseGCMCipher(
            final int ivsize, final int kdfSize, final String algorithm, final int keySize, final String transformation,
            final int blkSize, final int authSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    protected byte[] initializeKeyData(final Mode mode, final byte[] key, final int reqLen) {
        byte[] keyData = super.initializeKeyData(mode, key, reqLen);
        secretKey = new SecretKeySpec(keyData, getAlgorithm());
        return keyData;
    }

    @Override
    protected Cipher createCipherInstance(final Mode mode, final byte[] key, final byte[] iv) throws Exception {
        this.mode = mode;
        Cipher instance = SecurityUtils.getCipher(getTransformation());
        instance.init(
                Mode.Encrypt.equals(this.mode) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                secretKey,
                new GCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, iv));
        return instance;
    }

    public void incrementIV() throws Exception {
        Cipher cipher = getCipherInstance();
        Buffer iv = new ByteArrayBuffer(cipher.getIV());
        iv.rpos(Integer.BYTES);
        long ic = iv.getLong();
        ic = (ic + 1) & 0x0ffffffffL;
        iv.wpos(Integer.BYTES);
        iv.putLong(ic);
        cipher.init(
                mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                secretKey,
                new GCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, iv.array()));
    }

    public void updateAAD(final byte[] additionalAuthenticatedData, final int aadOffset, final int aadLength) {
        getCipherInstance().updateAAD(additionalAuthenticatedData, aadOffset, aadLength);
    }

    public void doFinal(final byte[] output, final int outputOffset) throws Exception {
        getCipherInstance().doFinal(output, outputOffset);
    }
}
