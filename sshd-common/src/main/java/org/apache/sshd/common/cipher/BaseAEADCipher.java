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

import org.apache.sshd.common.util.security.SecurityUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

public abstract class BaseAEADCipher extends BaseCipher {

    private Mode mode;
    private SecretKey secretKey;
    private AlgorithmParameterSpec params;
    private boolean aadWritten;

    public BaseAEADCipher(
            int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation, int blkSize) {
        super(ivsize, authSize, kdfSize, algorithm, keySize, transformation, blkSize);
    }

    @Override
    protected byte[] initializeIVData(final Mode mode, final byte[] iv, final int reqLen) {
        byte[] data = super.initializeIVData(mode, iv, reqLen);
        params = initializeAlgorithmParameters(data);
        return data;
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
        init(instance);
        return instance;
    }

    private void init(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, params);
    }

    protected abstract AlgorithmParameterSpec initializeAlgorithmParameters(byte[] iv);

    protected abstract AlgorithmParameterSpec getNextAlgorithmParameters();

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
        if (inputLen != getCipherInstance().update(input, inputOffset, inputLen, input, inputOffset) && mode == Mode.Encrypt) {
            throw new IllegalStateException();
        }
    }

    public void updateAAD(final byte[] additionalAuthenticatedData, final int aadOffset, final int aadLength) throws Exception {
        Cipher cipher = getCipherInstance();
        if (!aadWritten) {
            params = getNextAlgorithmParameters();
            init(cipher);
        }
        cipher.updateAAD(additionalAuthenticatedData, aadOffset, aadLength);
        aadWritten = true;
    }

    public void doFinal(final byte[] output, final int outputOffset) throws Exception {
        getCipherInstance().doFinal(output, outputOffset);
        aadWritten = false;
    }

}
