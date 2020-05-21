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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Base cipher for authenticated encryption with associated data implementations.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5116">RFC 5116</a>
 */
public abstract class BaseAEADCipher extends BaseCipher {

    private Mode mode;
    private SecretKey secretKey;
    private AlgorithmParameterSpec params;

    public BaseAEADCipher(
                          int ivsize, int authSize, int kdfSize, String algorithm, int keySize, String transformation,
                          int blkSize) {
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

    /**
     * Initializes this cipher using the given JDK cipher and the previously configured secret key and algorithm
     * parameters.
     *
     * @param  cipher                             the JDK cipher instance to initialize
     * @throws InvalidKeyException                if this cipher's secret key is incompatible with the given cipher
     * @throws InvalidAlgorithmParameterException if this cipher's algorithm parameters are incompatible with the given
     *                                            cipher
     */
    protected void init(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, params);
    }

    /**
     * Creates the specific algorithm parameters for the given input initialization vector.
     *
     * @param  iv initialization vector provided at construction
     * @return    this cipher's parameters
     */
    protected abstract AlgorithmParameterSpec initializeAlgorithmParameters(byte[] iv);

    /**
     * Returns the next algorithm parameters to use for encrypting or decrypting the next
     * {@link #updateWithAAD(byte[], int, int, int, int)}} operation.
     *
     * @return the parameters for the next updateWithAAD operation
     */
    protected abstract AlgorithmParameterSpec getNextAlgorithmParameters();

    @Override
    public void updateWithAAD(byte[] input, int aadOffset, int aadLen, int inputOffset, int inputLen) throws Exception {
        Cipher cipher = getCipherInstance();
        params = getNextAlgorithmParameters();
        init(cipher);
        cipher.updateAAD(input, aadOffset, aadLen);
        cipher.doFinal(input, inputOffset, inputLen, input, inputOffset);
    }

}
